import time
import httpx
import pytest

from modules.dependency_scanner.osv_client import (
    OSVClient,
    OSVError,
    cvss_score_from_vector,
    fixed_versions,
    score_to_severity,
    vuln_severity,
)


def test_get_vuln_individual_query_and_cache(tmp_path):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            200,
            json={"id": "GHSA-xyz1", "summary": "Test advisory"},
        )

    client = OSVClient(
        tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler))
    )

    data = client.get_vuln("GHSA-xyz1")
    assert data["id"] == "GHSA-xyz1"
    assert len(calls) == 1

    cached_data = client.get_vuln("GHSA-xyz1")
    assert cached_data["id"] == "GHSA-xyz1"
    assert len(calls) == 1


def test_get_vuln_offline_miss_raises(tmp_path):
    client = OSVClient(tmp_path, offline=True)
    with pytest.raises(OSVError, match="offline and not cached"):
        client.get_vuln("GHSA-missing")


def test_http_404_raises_immediately_without_retry(tmp_path, monkeypatch):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(404)

    sleep_calls = []
    monkeypatch.setattr(time, "sleep", lambda s: sleep_calls.append(s))

    client = OSVClient(
        tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler))
    )

    with pytest.raises(OSVError, match="HTTP 404"):
        client.get_vuln("GHSA-notfound")

    assert len(calls) == 1
    assert len(sleep_calls) == 0


def test_http_500_retries_and_succeeds(tmp_path, monkeypatch):
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(500)
        return httpx.Response(200, json={"id": "GHSA-recovered"})

    sleep_calls = []
    monkeypatch.setattr(time, "sleep", lambda s: sleep_calls.append(s))

    client = OSVClient(
        tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler))
    )

    data = client.get_vuln("GHSA-recovered")
    assert data["id"] == "GHSA-recovered"
    assert len(calls) == 2
    assert len(sleep_calls) == 1


def test_http_429_retries_and_exhausts(tmp_path, monkeypatch):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(429)

    sleep_calls = []
    monkeypatch.setattr(time, "sleep", lambda s: sleep_calls.append(s))

    client = OSVClient(
        tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler))
    )

    with pytest.raises(OSVError, match="HTTP 429"):
        client.get_vuln("GHSA-ratelimited")

    assert len(calls) == 3
    assert len(sleep_calls) == 2


def test_network_httpx_error_retries(tmp_path, monkeypatch):
    calls = []

    def handler(request):
        calls.append(request)
        raise httpx.ConnectError("Connection refused")

    sleep_calls = []
    monkeypatch.setattr(time, "sleep", lambda s: sleep_calls.append(s))

    client = OSVClient(
        tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler))
    )

    with pytest.raises(OSVError, match="Connection refused"):
        client.get_vuln("GHSA-connerr")

    assert len(calls) == 3


def test_paginate_multiple_pages(tmp_path):
    calls = []

    def handler(request):
        calls.append(request)
        payload = request.read().decode("utf-8")
        if "tok1" in payload:
            return httpx.Response(
                200,
                json={"vulns": [{"id": "V-2"}], "next_page_token": None},
            )
        else:
            return httpx.Response(
                200,
                json={"vulns": [{"id": "V-1"}], "next_page_token": "tok1"},
            )

    client = OSVClient(
        tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler))
    )

    ids = client._paginate(("npm", "multi-page-pkg", "1.0.0"))
    assert ids == ["V-1", "V-2"]
    assert len(calls) == 2


def test_vuln_severity_cvss_fallbacks():
    v_db = {"database_specific": {"severity": "HIGH"}, "severity": [{"type": "CVSS_V3", "score": "2.0"}]}
    assert vuln_severity(v_db) == "HIGH"

    v_num = {"severity": [{"type": "CVSS_V3", "score": "9.5"}]}
    assert vuln_severity(v_num) == "CRITICAL"

    v_num_med = {"severity": [{"type": "CVSS_V3", "score": 6.5}]}
    assert vuln_severity(v_num_med) == "MEDIUM"

    v_num_low = {"severity": [{"type": "CVSS_V3", "score": "3.5"}]}
    assert vuln_severity(v_num_low) == "LOW"

    v_vec = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    assert vuln_severity(v_vec) == "CRITICAL"

    assert vuln_severity({}) == "UNKNOWN"


def test_osv_single_query_official_endpoint(tmp_path):
    calls = []

    def handler(request):
        calls.append(request)
        assert request.url == "https://api.osv.dev/v1/query"
        return httpx.Response(200, json={"vulns": [{"id": "GHSA-single-vuln"}]})

    client = OSVClient(tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler)))
    ids = client.query(("npm", "lodash", "4.17.20"))
    assert ids == ["GHSA-single-vuln"]
    assert len(calls) == 1
    assert calls[0].method == "POST"


def test_osv_batch_query_official_endpoint(tmp_path):
    calls = []

    def handler(request):
        calls.append(request)
        assert request.url == "https://api.osv.dev/v1/querybatch"
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-batch-1"}]}]})

    client = OSVClient(tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler)))
    results, failed = client.query_ids([("npm", "lodash", "4.17.20")])
    assert failed == []
    assert results[("npm", "lodash", "4.17.20")] == ["GHSA-batch-1"]
    assert len(calls) == 1
    assert calls[0].method == "POST"


def test_osv_query_zero_advisories(tmp_path):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={})

    client = OSVClient(tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler)))
    ids = client.query(("vcpkg", "curl", "7.80.0"))
    assert ids == []
    assert len(calls) == 1
