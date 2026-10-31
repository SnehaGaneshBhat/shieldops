from backend.mock_server import REPORT_ITEMS
from backend.schemas import Finding


def test_mock_items_match_the_finding_schema():
    for it in REPORT_ITEMS:
        Finding.model_validate({
            k: v for k, v in it.items() if k in Finding.model_fields
        })
