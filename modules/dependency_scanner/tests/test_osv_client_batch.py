import httpx
import pytest

from modules.dependency_scanner.osv_client import (
    OSVClient,
    OSVError,
    fixed_versions,
    vuln_severity,
)


def test_batch_query_and_cache(tmp_path):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            200,
            json={"results": [{"vulns": [{"id": "GHSA-test"}]}]},
        )

    client = OSVClient(
        tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler))
    )
    package = ("npm", "lodash", "4.17.20")

    result, failed = client.query_ids([package])

    assert result == {package: ["GHSA-test"]}
    assert failed == []
    assert len(calls) == 1

    client.query_ids([package])
    assert len(calls) == 1


def test_offline_cache_miss(tmp_path):
    client = OSVClient(tmp_path, offline=True)
    package = ("npm", "unknown", "1.0.0")

    result, failed = client.query_ids([package])

    assert result == {}
    assert failed == [package]


def test_vulnerability_details_and_cache(tmp_path):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"id": "GHSA-test"})

    client = OSVClient(
        tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler))
    )

    assert client.get_vuln("GHSA-test") == {"id": "GHSA-test"}
    assert client.get_vuln("GHSA-test") == {"id": "GHSA-test"}
    assert len(calls) == 1


def test_offline_vulnerability_cache_miss(tmp_path):
    client = OSVClient(tmp_path, offline=True)

    with pytest.raises(OSVError):
        client.get_vuln("GHSA-missing")


def test_severity_and_fixed_versions():
    assert vuln_severity({"database_specific": {"severity": "CRITICAL"}}) == "CRITICAL"
    assert vuln_severity({"database_specific": {"severity": "MODERATE"}}) == "MEDIUM"

    vulnerability = {
        "affected": [{
            "ranges": [{
                "events": [
                    {"introduced": "0"},
                    {"fixed": "2.0.0"},
                    {"fixed": "3.0.0"},
                ]
            }]
        }]
    }

    assert fixed_versions(vulnerability) == ["2.0.0", "3.0.0"]
