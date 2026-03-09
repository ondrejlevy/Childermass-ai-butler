"""
Tests for Childermass Tracking MCP server tools.

Covers:
- All 8 MCP tool functions
- Error handling and error sanitization
- SecurityError pass-through

Run with:
    pytest src/childermass/tracking_mcp/tests/test_server.py -v
"""

from unittest.mock import MagicMock, patch

from childermass.tracking_mcp.client import (
    EmailParseResult,
    Shipment,
    ShipmentDetail,
)
from childermass.tracking_mcp.security import SecurityError
from childermass.tracking_mcp.server import (
    tracking_archive,
    tracking_detect_carrier,
    tracking_get,
    tracking_list,
    tracking_parse_email,
    tracking_register,
)


# =========================================================================
# Fixtures & Helpers
# =========================================================================


def _mock_shipment(**kwargs) -> Shipment:
    defaults = {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "carrier": "zasilkovna",
        "tracking_number": "Z1234567890",
        "tracking_url": "https://tracking.zasilkovna.cz/Z1234567890",
        "status": "registered",
        "status_detail": "Shipment registered for tracking",
        "expected_delivery": None,
        "delivery_location": None,
        "order_source": "alza.cz",
        "order_number": "OBJ-123456",
        "email_id": None,
        "email_subject": None,
        "last_checked": None,
        "last_status_change": "2025-01-15T10:00:00+00:00",
        "is_active": True,
        "created_at": "2025-01-15T10:00:00+00:00",
        "metadata": "{}",
    }
    defaults.update(kwargs)
    return Shipment(**defaults)


# =========================================================================
# tracking_register
# =========================================================================


class TestTrackingRegister:
    @patch("childermass.tracking_mcp.server.get_client")
    def test_successful_registration(self, mock_get_client):
        client = MagicMock()
        client.register_shipment.return_value = _mock_shipment()
        mock_get_client.return_value = client

        result = tracking_register(
            carrier="zasilkovna",
            tracking_url="https://tracking.zasilkovna.cz/Z1234567890",
            tracking_number="Z1234567890",
        )

        assert "error" not in result
        assert result["carrier"] == "zasilkovna"
        assert result["id"] == "550e8400-e29b-41d4-a716-446655440000"

    @patch("childermass.tracking_mcp.server.get_client")
    def test_security_error_returned(self, mock_get_client):
        client = MagicMock()
        client.register_shipment.side_effect = SecurityError("Invalid carrier")
        mock_get_client.return_value = client

        result = tracking_register(
            carrier="fedex",
            tracking_url="https://fedex.com/track/123",
        )

        assert "error" in result
        assert "Invalid carrier" in result["error"]

    @patch("childermass.tracking_mcp.server.get_client")
    def test_generic_error_sanitized(self, mock_get_client):
        client = MagicMock()
        client.register_shipment.side_effect = Exception(
            "DB error at /Users/user/.childermass/tracking.sqlite"
        )
        mock_get_client.return_value = client

        result = tracking_register(
            carrier="zasilkovna",
            tracking_url="https://tracking.zasilkovna.cz/Z1234567890",
        )

        assert "error" in result
        # File path should be sanitized
        assert "/Users/" not in result["error"]


# =========================================================================
# tracking_get
# =========================================================================


class TestTrackingGet:
    @patch("childermass.tracking_mcp.server.get_client")
    def test_successful_get(self, mock_get_client):
        client = MagicMock()
        client.get_shipment.return_value = ShipmentDetail(
            shipment=_mock_shipment(),
            history=[],
        )
        mock_get_client.return_value = client

        result = tracking_get("550e8400-e29b-41d4-a716-446655440000")

        assert "shipment" in result
        assert "history" in result
        assert result["shipment"]["carrier"] == "zasilkovna"

    @patch("childermass.tracking_mcp.server.get_client")
    def test_not_found(self, mock_get_client):
        client = MagicMock()
        client.get_shipment.side_effect = SecurityError("Shipment not found")
        mock_get_client.return_value = client

        result = tracking_get("550e8400-e29b-41d4-a716-446655440000")

        assert "error" in result
        assert "not found" in result["error"]


# =========================================================================
# tracking_list
# =========================================================================


class TestTrackingList:
    @patch("childermass.tracking_mcp.server.get_client")
    def test_list_active(self, mock_get_client):
        client = MagicMock()
        client.list_shipments.return_value = [
            _mock_shipment(id="id-1"),
            _mock_shipment(id="id-2"),
        ]
        mock_get_client.return_value = client

        result = tracking_list(active_only=True)

        assert isinstance(result, list)
        assert len(result) == 2

    @patch("childermass.tracking_mcp.server.get_client")
    def test_list_empty(self, mock_get_client):
        client = MagicMock()
        client.list_shipments.return_value = []
        mock_get_client.return_value = client

        result = tracking_list()

        assert isinstance(result, list)
        assert len(result) == 0


# =========================================================================
# tracking_archive
# =========================================================================


class TestTrackingArchive:
    @patch("childermass.tracking_mcp.server.get_client")
    def test_successful_archive(self, mock_get_client):
        client = MagicMock()
        client.archive_shipment.return_value = True
        mock_get_client.return_value = client

        result = tracking_archive("550e8400-e29b-41d4-a716-446655440000")

        assert result["success"] is True

    @patch("childermass.tracking_mcp.server.get_client")
    def test_archive_not_found(self, mock_get_client):
        client = MagicMock()
        client.archive_shipment.return_value = False
        mock_get_client.return_value = client

        result = tracking_archive("550e8400-e29b-41d4-a716-446655440000")

        assert "error" in result
        assert "not found" in result["error"]


# =========================================================================
# tracking_parse_email
# =========================================================================


class TestTrackingParseEmail:
    @patch("childermass.tracking_mcp.server.get_client")
    def test_successful_parse(self, mock_get_client):
        client = MagicMock()
        client.parse_email.return_value = EmailParseResult(
            carrier="zasilkovna",
            tracking_url="https://tracking.zasilkovna.cz/Z1234567890",
            tracking_number="Z1234567890",
            order_source="alza.cz",
            order_number="OBJ-123456",
            expected_delivery=None,
            delivery_location=None,
            confidence=0.8,
        )
        mock_get_client.return_value = client

        result = tracking_parse_email(
            email_body="Zásilka odeslána",
            email_subject="Sledování zásilky",
            email_from="info@zasilkovna.cz",
        )

        assert result["carrier"] == "zasilkovna"
        assert result["confidence"] == 0.8


# =========================================================================
# tracking_detect_carrier
# =========================================================================


class TestTrackingDetectCarrier:
    @patch("childermass.tracking_mcp.server.get_client")
    def test_detect_by_url(self, mock_get_client):
        client = MagicMock()
        client.detect_carrier.return_value = {
            "carrier": "zasilkovna",
            "method": "url_pattern",
        }
        mock_get_client.return_value = client

        result = tracking_detect_carrier(url="https://tracking.zasilkovna.cz/Z1234567890")

        assert result["carrier"] == "zasilkovna"

    @patch("childermass.tracking_mcp.server.get_client")
    def test_detect_error_handling(self, mock_get_client):
        client = MagicMock()
        client.detect_carrier.side_effect = SecurityError("Invalid URL")
        mock_get_client.return_value = client

        result = tracking_detect_carrier(url="bad-url")

        assert "error" in result
