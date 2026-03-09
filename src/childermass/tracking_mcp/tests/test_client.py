"""
Tests for Childermass Tracking MCP client.

Covers:
- TrackingDatabase (SQLite CRUD operations)
- TrackingClient (business logic, email parsing, carrier detection)

Run with:
    pytest src/childermass/tracking_mcp/tests/test_client.py -v
"""

import json

import pytest

from childermass.tracking_mcp.client import (
    EmailParseResult,
    Shipment,
    ShipmentDetail,
    TrackingClient,
    TrackingDatabase,
)
from childermass.tracking_mcp.security import SecurityError


# =========================================================================
# Fixtures
# =========================================================================


@pytest.fixture
def db(tmp_path):
    """Create a temporary database."""
    db_path = tmp_path / "test_tracking.sqlite"
    return TrackingDatabase(db_path=db_path)


@pytest.fixture
def client(tmp_path):
    """Create a TrackingClient with a temporary database."""
    db_path = tmp_path / "test_tracking.sqlite"
    return TrackingClient(db_path=db_path)


def _make_shipment(**kwargs) -> Shipment:
    """Create a test shipment with defaults."""
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
# TrackingDatabase
# =========================================================================


class TestTrackingDatabase:
    def test_insert_and_get(self, db):
        shipment = _make_shipment()
        db.insert_shipment(shipment)

        result = db.get_shipment(shipment.id)
        assert result is not None
        assert result.id == shipment.id
        assert result.carrier == "zasilkovna"
        assert result.tracking_number == "Z1234567890"
        assert result.is_active is True

    def test_get_nonexistent(self, db):
        result = db.get_shipment("nonexistent-id")
        assert result is None

    def test_find_by_tracking_url(self, db):
        shipment = _make_shipment()
        db.insert_shipment(shipment)

        result = db.find_by_tracking_url(shipment.tracking_url)
        assert result is not None
        assert result.id == shipment.id

    def test_find_by_tracking_url_nonexistent(self, db):
        result = db.find_by_tracking_url("https://nonexistent.com/track")
        assert result is None

    def test_list_shipments_active_only(self, db):
        active = _make_shipment(id="id-1", tracking_url="https://a.com/1")
        inactive = _make_shipment(id="id-2", tracking_url="https://a.com/2", is_active=False)
        db.insert_shipment(active)
        db.insert_shipment(inactive)

        result = db.list_shipments(active_only=True)
        assert len(result) == 1
        assert result[0].id == "id-1"

    def test_list_shipments_all(self, db):
        s1 = _make_shipment(id="id-1", tracking_url="https://a.com/1")
        s2 = _make_shipment(id="id-2", tracking_url="https://a.com/2", is_active=False)
        db.insert_shipment(s1)
        db.insert_shipment(s2)

        result = db.list_shipments(active_only=False)
        assert len(result) == 2

    def test_list_shipments_filter_carrier(self, db):
        s1 = _make_shipment(id="id-1", carrier="zasilkovna", tracking_url="https://a.com/1")
        s2 = _make_shipment(id="id-2", carrier="ppl", tracking_url="https://a.com/2")
        db.insert_shipment(s1)
        db.insert_shipment(s2)

        result = db.list_shipments(carrier="zasilkovna")
        assert len(result) == 1
        assert result[0].carrier == "zasilkovna"

    def test_list_shipments_filter_order_source(self, db):
        s1 = _make_shipment(id="id-1", order_source="alza.cz", tracking_url="https://a.com/1")
        s2 = _make_shipment(id="id-2", order_source="czc.cz", tracking_url="https://a.com/2")
        db.insert_shipment(s1)
        db.insert_shipment(s2)

        result = db.list_shipments(order_source="alza.cz")
        assert len(result) == 1
        assert result[0].order_source == "alza.cz"

    def test_update_status(self, db):
        shipment = _make_shipment()
        db.insert_shipment(shipment)

        changed = db.update_status(shipment.id, "in_transit", "Package in sorting facility")
        assert changed is True

        updated = db.get_shipment(shipment.id)
        assert updated.status == "in_transit"
        assert updated.status_detail == "Package in sorting facility"

    def test_update_status_no_change(self, db):
        shipment = _make_shipment()
        db.insert_shipment(shipment)

        changed = db.update_status(shipment.id, "registered", "Same status")
        assert changed is False

    def test_update_status_nonexistent(self, db):
        changed = db.update_status("nonexistent", "delivered", "Done")
        assert changed is False

    def test_update_status_auto_deactivates_delivered(self, db):
        shipment = _make_shipment()
        db.insert_shipment(shipment)

        db.update_status(shipment.id, "delivered", "Package delivered")
        updated = db.get_shipment(shipment.id)
        assert updated.is_active is False

    def test_update_status_auto_deactivates_returned(self, db):
        shipment = _make_shipment()
        db.insert_shipment(shipment)

        db.update_status(shipment.id, "returned", "Package returned")
        updated = db.get_shipment(shipment.id)
        assert updated.is_active is False

    def test_update_status_auto_deactivates_cancelled(self, db):
        shipment = _make_shipment()
        db.insert_shipment(shipment)

        db.update_status(shipment.id, "cancelled", "Cancelled")
        updated = db.get_shipment(shipment.id)
        assert updated.is_active is False

    def test_archive_shipment(self, db):
        shipment = _make_shipment()
        db.insert_shipment(shipment)

        success = db.archive_shipment(shipment.id)
        assert success is True

        updated = db.get_shipment(shipment.id)
        assert updated.is_active is False

    def test_archive_nonexistent(self, db):
        success = db.archive_shipment("nonexistent")
        assert success is False

    def test_status_history(self, db):
        shipment = _make_shipment()
        db.insert_shipment(shipment)

        db.update_status(shipment.id, "in_transit", "In transit", location="Prague")
        db.update_status(shipment.id, "delivered", "Delivered", location="Brno")

        history = db.get_history(shipment.id)
        assert len(history) == 2
        assert history[0].status == "delivered"  # DESC order
        assert history[1].status == "in_transit"

    def test_update_status_preserves_expected_delivery(self, db):
        shipment = _make_shipment()
        db.insert_shipment(shipment)

        db.update_status(
            shipment.id,
            "in_transit",
            "In transit",
            expected_delivery="2025-01-20",
            delivery_location="Zásilkovna - OC Chodov",
        )

        updated = db.get_shipment(shipment.id)
        assert updated.expected_delivery == "2025-01-20"
        assert updated.delivery_location == "Zásilkovna - OC Chodov"


# =========================================================================
# TrackingClient - Carrier Detection
# =========================================================================


class TestCarrierDetection:
    def test_detect_zasilkovna_from_url(self, client):
        assert (
            client.detect_carrier_from_url("https://tracking.zasilkovna.cz/Z1234") == "zasilkovna"
        )

    def test_detect_ppl_from_url(self, client):
        assert client.detect_carrier_from_url("https://www.ppl.cz/vyhledat-zasilku?id=123") == "ppl"

    def test_detect_dpd_from_url(self, client):
        assert client.detect_carrier_from_url("https://tracking.dpd.de/status/123") == "dpd"

    def test_detect_gls_from_url(self, client):
        assert client.detect_carrier_from_url("https://gls-group.com/CZ/track/123") == "gls"

    def test_detect_balikovna_from_url(self, client):
        assert (
            client.detect_carrier_from_url("https://b2c.cpost.cz/services/ParcelHistory?id=123")
            == "balikovna"
        )

    def test_detect_alza_from_url(self, client):
        assert client.detect_carrier_from_url("https://www.alza.cz/Order/Track/123") == "alza"

    def test_unknown_url(self, client):
        assert client.detect_carrier_from_url("https://unknown-carrier.com/track") == "unknown"

    def test_detect_zasilkovna_from_email(self, client):
        assert client.detect_carrier_from_email("info@zasilkovna.cz") == "zasilkovna"

    def test_detect_ppl_from_email(self, client):
        assert client.detect_carrier_from_email("tracking@ppl.cz") == "ppl"

    def test_detect_dpd_from_email(self, client):
        assert client.detect_carrier_from_email("noreply@dpd.cz") == "dpd"

    def test_unknown_email(self, client):
        assert client.detect_carrier_from_email("hello@example.com") == "unknown"


# =========================================================================
# TrackingClient - E-shop Detection
# =========================================================================


class TestEshopDetection:
    def test_detect_alza(self, client):
        assert client.detect_eshop("info@alza.cz") == "alza.cz"

    def test_detect_rohlik(self, client):
        assert client.detect_eshop("info@rohlik.cz") == "rohlik.cz"

    def test_detect_czc(self, client):
        assert client.detect_eshop("orders@czc.cz") == "czc.cz"

    def test_detect_amazon(self, client):
        assert client.detect_eshop("auto-confirm@amazon.de") == "amazon.de"

    def test_detect_temu(self, client):
        assert client.detect_eshop("noreply@temu.com") == "temu.com"

    def test_unknown_eshop(self, client):
        assert client.detect_eshop("hello@unknown.com") is None


# =========================================================================
# TrackingClient - Registration
# =========================================================================


class TestRegistration:
    def test_register_shipment(self, client):
        shipment = client.register_shipment(
            carrier="zasilkovna",
            tracking_url="https://tracking.zasilkovna.cz/Z1234567890",
            tracking_number="Z1234567890",
            order_source="alza.cz",
        )
        assert shipment.carrier == "zasilkovna"
        assert shipment.tracking_url == "https://tracking.zasilkovna.cz/Z1234567890"
        assert shipment.status == "registered"
        assert shipment.is_active is True
        assert shipment.id  # UUID assigned

    def test_register_rejects_duplicate_active(self, client):
        client.register_shipment(
            carrier="zasilkovna",
            tracking_url="https://tracking.zasilkovna.cz/Z1234567890",
        )
        with pytest.raises(SecurityError, match="already registered"):
            client.register_shipment(
                carrier="zasilkovna",
                tracking_url="https://tracking.zasilkovna.cz/Z1234567890",
            )

    def test_register_validates_carrier(self, client):
        with pytest.raises(SecurityError, match="Unknown carrier"):
            client.register_shipment(
                carrier="fedex",
                tracking_url="https://fedex.com/track/123",
            )

    def test_register_validates_url(self, client):
        with pytest.raises(SecurityError, match="http"):
            client.register_shipment(
                carrier="zasilkovna",
                tracking_url="not-a-url",
            )

    def test_register_with_metadata(self, client):
        shipment = client.register_shipment(
            carrier="ppl",
            tracking_url="https://www.ppl.cz/vyhledat-zasilku?id=12345678901",
            metadata='{"items": ["phone case"]}',
        )
        assert json.loads(shipment.metadata) == {"items": ["phone case"]}

    def test_register_with_invalid_metadata(self, client):
        with pytest.raises(SecurityError, match="Invalid JSON"):
            client.register_shipment(
                carrier="ppl",
                tracking_url="https://www.ppl.cz/vyhledat-zasilku?id=12345678901",
                metadata="not json {{{",
            )


# =========================================================================
# TrackingClient - Read Operations
# =========================================================================


class TestReadOperations:
    def test_get_shipment(self, client):
        registered = client.register_shipment(
            carrier="zasilkovna",
            tracking_url="https://tracking.zasilkovna.cz/Z1234567890",
        )
        detail = client.get_shipment(registered.id)
        assert isinstance(detail, ShipmentDetail)
        assert detail.shipment.id == registered.id

    def test_get_nonexistent(self, client):
        with pytest.raises(SecurityError, match="not found"):
            client.get_shipment("550e8400-e29b-41d4-a716-446655440000")

    def test_get_validates_id(self, client):
        with pytest.raises(SecurityError, match="Invalid shipment ID"):
            client.get_shipment("not-a-uuid")

    def test_list_shipments(self, client):
        client.register_shipment(
            carrier="zasilkovna",
            tracking_url="https://tracking.zasilkovna.cz/Z1234567890",
        )
        client.register_shipment(
            carrier="ppl",
            tracking_url="https://www.ppl.cz/vyhledat-zasilku?id=12345678901",
        )
        result = client.list_shipments()
        assert len(result) == 2

    def test_list_filter_carrier(self, client):
        client.register_shipment(
            carrier="zasilkovna",
            tracking_url="https://tracking.zasilkovna.cz/Z1234567890",
        )
        client.register_shipment(
            carrier="ppl",
            tracking_url="https://www.ppl.cz/vyhledat-zasilku?id=12345678901",
        )
        result = client.list_shipments(carrier="zasilkovna")
        assert len(result) == 1
        assert result[0].carrier == "zasilkovna"


# =========================================================================
# TrackingClient - Archive
# =========================================================================


class TestArchive:
    def test_archive_shipment(self, client):
        registered = client.register_shipment(
            carrier="zasilkovna",
            tracking_url="https://tracking.zasilkovna.cz/Z1234567890",
        )
        success = client.archive_shipment(registered.id)
        assert success is True

        # Should not appear in active list
        active = client.list_shipments(active_only=True)
        assert len(active) == 0

    def test_archive_validates_id(self, client):
        with pytest.raises(SecurityError, match="Invalid shipment ID"):
            client.archive_shipment("not-a-uuid")


# =========================================================================
# TrackingClient - Email Parsing
# =========================================================================


class TestEmailParsing:
    def test_parse_zasilkovna_email(self, client):
        result = client.parse_email(
            email_body="Vaše zásilka Z1234567890 byla odeslána.",
            email_subject="Zásilka odeslána",
            email_from="info@zasilkovna.cz",
            email_body_html='<a href="https://tracking.zasilkovna.cz/Z1234567890">Sledovat</a>',
        )
        assert isinstance(result, EmailParseResult)
        assert result.carrier == "zasilkovna"
        assert result.tracking_url == "https://tracking.zasilkovna.cz/Z1234567890"
        assert result.tracking_number == "Z1234567890"
        assert result.confidence > 0.5

    def test_parse_alza_email(self, client):
        result = client.parse_email(
            email_body="Objednávka č. OBJ-123456 byla odeslána.",
            email_subject="Objednávka odeslána",
            email_from="info@alza.cz",
            email_body_html='<a href="https://www.alza.cz/Order/Track/123456">Sledovat zásilku</a>',
        )
        assert result.order_source == "alza.cz"
        assert result.tracking_url == "https://www.alza.cz/Order/Track/123456"
        assert result.carrier == "alza"

    def test_parse_extracts_order_number(self, client):
        result = client.parse_email(
            email_body="Objednávka č. OBJ-123456 byla odeslána přepravcem PPL.",
            email_subject="Objednávka odeslána",
            email_from="info@czc.cz",
        )
        assert result.order_number == "OBJ-123456"
        assert result.order_source == "czc.cz"

    def test_parse_email_with_ppl_tracking_url(self, client):
        result = client.parse_email(
            email_body="Zásilka odeslána.",
            email_subject="PPL zásilka",
            email_from="noreply@shop.cz",
            email_body_html='<a href="https://www.ppl.cz/vyhledat-zasilku?shipmentId=12345678901">Sledovat</a>',
        )
        assert result.tracking_url == "https://www.ppl.cz/vyhledat-zasilku?shipmentId=12345678901"
        assert result.carrier == "ppl"

    def test_parse_detects_carrier_from_subject(self, client):
        result = client.parse_email(
            email_body="Vaše zásilka je na cestě.",
            email_subject="DPD: Zásilka odeslána",
            email_from="noreply@genericshop.cz",
        )
        assert result.carrier == "dpd"

    def test_parse_extracts_delivery_location(self, client):
        result = client.parse_email(
            email_body="Zásilka bude doručena\nvýdejní místo: Zásilkovna - Albert OC Chodov\n\nDěkujeme",
            email_subject="Zásilka přijata",
            email_from="info@zasilkovna.cz",
        )
        assert result.delivery_location is not None
        assert "Chodov" in result.delivery_location

    def test_parse_extracts_expected_delivery(self, client):
        result = client.parse_email(
            email_body="Vaše zásilka bude doručení dne 20. 1. 2025.\nDěkujeme.",
            email_subject="Zásilka odeslána",
            email_from="info@ppl.cz",
        )
        assert result.expected_delivery is not None
        assert "2025" in result.expected_delivery

    def test_parse_low_confidence_generic_email(self, client):
        result = client.parse_email(
            email_body="Hello world, nothing about tracking here.",
            email_subject="Random email",
            email_from="hello@random.com",
        )
        assert result.carrier == "unknown"
        assert result.tracking_url is None
        assert result.confidence < 0.3

    def test_parse_validates_body_length(self, client):
        with pytest.raises(SecurityError, match="too long"):
            client.parse_email(
                email_body="x" * 600_000,
                email_subject="Test",
                email_from="test@test.com",
            )

    def test_parse_validates_from_required(self, client):
        with pytest.raises(SecurityError, match="required"):
            client.parse_email(
                email_body="Test",
                email_subject="Test",
                email_from="",
            )


# =========================================================================
# TrackingClient - Carrier Detection Standalone
# =========================================================================


class TestDetectCarrier:
    def test_detect_by_url(self, client):
        result = client.detect_carrier(url="https://tracking.zasilkovna.cz/Z1234567890")
        assert result["carrier"] == "zasilkovna"
        assert result["method"] == "url_pattern"

    def test_detect_by_email(self, client):
        result = client.detect_carrier(email_from="info@ppl.cz")
        assert result["carrier"] == "ppl"
        assert result["method"] == "email_pattern"

    def test_detect_eshop_only(self, client):
        result = client.detect_carrier(email_from="info@alza.cz")
        # Alza email pattern may or may not match carrier
        assert "method" in result

    def test_detect_unknown(self, client):
        result = client.detect_carrier(
            url="https://unknown.com/track",
            email_from="unknown@unknown.com",
        )
        assert result["carrier"] == "unknown"


# =========================================================================
# TrackingClient - Tracking URL Extraction
# =========================================================================


class TestTrackingUrlExtraction:
    def test_extracts_zasilkovna_url(self, client):
        html = '<a href="https://tracking.zasilkovna.cz/Z1234567890">Track</a>'
        urls = client._extract_tracking_urls(html)
        assert len(urls) >= 1
        assert "tracking.zasilkovna.cz" in urls[0]

    def test_extracts_ppl_url(self, client):
        html = '<a href="https://www.ppl.cz/vyhledat-zasilku?shipmentId=12345678901">Track</a>'
        urls = client._extract_tracking_urls(html)
        assert len(urls) >= 1
        assert "ppl.cz" in urls[0]

    def test_extracts_cpost_url(self, client):
        html = "Sledovat: https://b2c.cpost.cz/services/ParcelHistory?parcelNumbers=DR1234567890"
        urls = client._extract_tracking_urls(html)
        assert len(urls) >= 1
        assert "cpost.cz" in urls[0]

    def test_extracts_dpd_url(self, client):
        html = '<a href="https://tracking.dpd.de/status/en_EN/parcel/01234567890123">Track</a>'
        urls = client._extract_tracking_urls(html)
        assert len(urls) >= 1

    def test_deduplicates_urls(self, client):
        html = """
        <a href="https://tracking.zasilkovna.cz/Z1234">Link 1</a>
        <a href="https://tracking.zasilkovna.cz/Z1234">Link 2</a>
        """
        urls = client._extract_tracking_urls(html)
        # Should be deduplicated
        zasilkovna_urls = [u for u in urls if "zasilkovna" in u]
        assert len(zasilkovna_urls) == 1

    def test_extracts_generic_href_with_tracking_keyword(self, client):
        html = '<a href="https://shop.cz/tracking?id=123">Track your order</a>'
        urls = client._extract_tracking_urls(html)
        assert len(urls) >= 1

    def test_no_urls_in_plain_text(self, client):
        text = "No tracking URLs here, just a regular message."
        urls = client._extract_tracking_urls(text)
        assert len(urls) == 0


# =========================================================================
# TrackingClient - Tracking Number Extraction
# =========================================================================


class TestTrackingNumberExtraction:
    def test_extracts_zasilkovna_number(self, client):
        result = client._extract_tracking_number(
            "Zásilka Z1234567890 odeslána", "Sledování zásilky", "zasilkovna"
        )
        assert result == "Z1234567890"

    def test_extracts_balikovna_number(self, client):
        result = client._extract_tracking_number(
            "Zásilka DR1234567890 připravena", "Zásilka", "balikovna"
        )
        assert result == "DR1234567890"

    def test_extracts_generic_tracking_number(self, client):
        result = client._extract_tracking_number("číslo zásilky: ABC123DEF", "Sledování", "unknown")
        assert result == "ABC123DEF"

    def test_returns_none_when_no_match(self, client):
        result = client._extract_tracking_number(
            "Hello world, nothing about parcels here", "Random subject", "unknown"
        )
        assert result is None
