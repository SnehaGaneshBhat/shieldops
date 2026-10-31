from modules.dependency_scanner.syft_runner import parse_purl


def test_npm():
    assert parse_purl("pkg:npm/lodash@4.17.20") == (
        "npm", "lodash", "4.17.20"
    )


def test_scoped():
    assert parse_purl("pkg:npm/%40babel/core@7.0.0") == (
        "npm", "@babel/core", "7.0.0"
    )
    assert parse_purl("pkg:npm/@babel/core@7.0.0") == (
        "npm", "@babel/core", "7.0.0"
    )


def test_scoped_unversioned():
    assert parse_purl("pkg:npm/@babel/core") == ("npm", "@babel/core", None)
    assert parse_purl("pkg:npm/%40babel/core") == ("npm", "@babel/core", None)
    assert parse_purl("pkg:npm/@types/node") == ("npm", "@types/node", None)


def test_no_version():
    assert parse_purl("pkg:pypi/requests") == ("pypi", "requests", None)


def test_maven():
    assert parse_purl(
        "pkg:maven/org.apache.commons/commons-lang3@3.12.0?type=jar"
    ) == ("maven", "org.apache.commons:commons-lang3", "3.12.0")


def test_garbage():
    assert parse_purl("nonsense") is None
