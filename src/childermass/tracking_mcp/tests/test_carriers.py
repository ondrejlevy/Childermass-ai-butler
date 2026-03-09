"""
Tests for carrier parser modules.

Covers:
- CarrierParser base class (URL/email detection, status normalization)
- Individual carrier parser detection patterns
- Generic parser behavior

Run with:
    pytest src/childermass/tracking_mcp/tests/test_carriers.py -v
"""

import pytest

from childermass.tracking_mcp.carriers.alza import AlzaParser
from childermass.tracking_mcp.carriers.balikovna import BalikovnaParser
from childermass.tracking_mcp.carriers.base import ShipmentStatus, StatusEvent
from childermass.tracking_mcp.carriers.dpd import DPDParser
from childermass.tracking_mcp.carriers.generic import GenericParser
from childermass.tracking_mcp.carriers.gls import GLSParser
from childermass.tracking_mcp.carriers.ppl import PPLParser
from childermass.tracking_mcp.carriers.zasilkovna import ZasilkovnaParser


# =========================================================================
# Base CarrierParser - Status Normalization
# =========================================================================


class TestStatusNormalization:
    """Test the _normalize_status method from the base class."""

    @pytest.fixture
    def parser(self):
        # Use any concrete parser for testing base functionality
        return ZasilkovnaParser()

    # Delivered variants
    @pytest.mark.parametrize(
        "raw",
        [
            "Doručeno",
            "Zásilka byla doručená",
            "Delivered successfully",
            "Zásilka vyzvednutá",
            "Předána příjemci",
            "Zásilka převzata",
        ],
    )
    def test_delivered(self, parser, raw):
        assert parser._normalize_status(raw) == "delivered"

    # Pickup ready variants
    @pytest.mark.parametrize(
        "raw",
        [
            "Připraveno k vyzvednutí",
            "Zásilka k vyzvednutí na pobočce",
            "Ready for pickup",
            "Uložena na výdejním místě",
            "Na výdejním místě",
            "Zásilka na pobočce",
        ],
    )
    def test_pickup_ready(self, parser, raw):
        assert parser._normalize_status(raw) == "pickup_ready"

    # Out for delivery
    @pytest.mark.parametrize(
        "raw",
        [
            "Na cestě k vám",
            "Doručuje se příjemci",
            "V doručování",
            "Out for delivery",
            "Kurýr doručuje",
        ],
    )
    def test_out_for_delivery(self, parser, raw):
        assert parser._normalize_status(raw) == "out_for_delivery"

    # In transit
    @pytest.mark.parametrize(
        "raw",
        [
            "V přepravě",
            "Na cestě do depa",
            "In transit",
            "Zásilka odeslána",
            "Přijato do sběrného depa",
            "Překládka na sklad",
        ],
    )
    def test_in_transit(self, parser, raw):
        assert parser._normalize_status(raw) == "in_transit"

    # Registered
    @pytest.mark.parametrize(
        "raw",
        [
            "Zásilka zaregistrována",
            "Nová zásilka",
            "Registered",
            "Data received",
            "Zásilka podána",
        ],
    )
    def test_registered(self, parser, raw):
        assert parser._normalize_status(raw) == "registered"

    # Returned
    @pytest.mark.parametrize(
        "raw",
        [
            "Vráceno odesílateli",
            "Returned to sender",
        ],
    )
    def test_returned(self, parser, raw):
        assert parser._normalize_status(raw) == "returned"

    # Unknown fallback
    def test_unknown_status(self, parser):
        assert parser._normalize_status("Something completely unrecognized") == "unknown"


# =========================================================================
# Zásilkovna Parser
# =========================================================================


class TestZasilkovnaParser:
    @pytest.fixture
    def parser(self):
        return ZasilkovnaParser()

    def test_name(self, parser):
        assert parser.name == "zasilkovna"

    def test_detect_url_tracking(self, parser):
        assert parser.detect_url("https://tracking.zasilkovna.cz/Z1234567890")

    def test_detect_url_sledovani(self, parser):
        assert parser.detect_url("https://www.zasilkovna.cz/sledovani/Z1234")

    def test_detect_url_packeta(self, parser):
        assert parser.detect_url("https://app.packeta.com/tracking/Z1234")

    def test_reject_unrelated_url(self, parser):
        assert not parser.detect_url("https://www.ppl.cz/track/123")

    def test_detect_email_zasilkovna(self, parser):
        assert parser.detect_email("info@zasilkovna.cz")

    def test_detect_email_packeta(self, parser):
        assert parser.detect_email("noreply@packeta.com")

    def test_reject_unrelated_email(self, parser):
        assert not parser.detect_email("info@ppl.cz")


# =========================================================================
# Balíkovna Parser
# =========================================================================


class TestBalikovnaParser:
    @pytest.fixture
    def parser(self):
        return BalikovnaParser()

    def test_name(self, parser):
        assert parser.name == "balikovna"

    def test_detect_url_cpost(self, parser):
        assert parser.detect_url("https://b2c.cpost.cz/services/ParcelHistory?parcelNumbers=123")

    def test_detect_url_postaonline(self, parser):
        assert parser.detect_url("https://www.postaonline.cz/trackandtrace/123")

    def test_detect_url_balikovna(self, parser):
        assert parser.detect_url("https://www.balikovna.cz/sledovani/123")

    def test_reject_unrelated_url(self, parser):
        assert not parser.detect_url("https://www.zasilkovna.cz/track")

    def test_detect_email_cpost(self, parser):
        assert parser.detect_email("noreply@cpost.cz")

    def test_detect_email_balikovna(self, parser):
        assert parser.detect_email("info@balikovna.cz")

    def test_detect_email_ceskaposta(self, parser):
        assert parser.detect_email("tracking@ceskaposta.cz")


# =========================================================================
# PPL Parser
# =========================================================================


class TestPPLParser:
    @pytest.fixture
    def parser(self):
        return PPLParser()

    def test_name(self, parser):
        assert parser.name == "ppl"

    def test_detect_url(self, parser):
        assert parser.detect_url("https://www.ppl.cz/vyhledat-zasilku?shipmentId=12345678901")

    def test_reject_unrelated_url(self, parser):
        assert not parser.detect_url("https://www.dpd.cz/track")

    def test_detect_email(self, parser):
        assert parser.detect_email("tracking@ppl.cz")


# =========================================================================
# DPD Parser
# =========================================================================


class TestDPDParser:
    @pytest.fixture
    def parser(self):
        return DPDParser()

    def test_name(self, parser):
        assert parser.name == "dpd"

    def test_detect_url_tracking(self, parser):
        assert parser.detect_url("https://tracking.dpd.de/status/en_EN/parcel/01234567890123")

    def test_detect_url_cz(self, parser):
        assert parser.detect_url("https://www.dpd.cz/sledovani-zasilky/123")

    def test_reject_unrelated_url(self, parser):
        assert not parser.detect_url("https://www.ppl.cz/track")

    def test_detect_email_cz(self, parser):
        assert parser.detect_email("noreply@dpd.cz")

    def test_detect_email_de(self, parser):
        assert parser.detect_email("info@dpd.de")


# =========================================================================
# GLS Parser
# =========================================================================


class TestGLSParser:
    @pytest.fixture
    def parser(self):
        return GLSParser()

    def test_name(self, parser):
        assert parser.name == "gls"

    def test_detect_url_group(self, parser):
        assert parser.detect_url("https://gls-group.com/CZ/cs/sledovani-zasilky?match=12345678")

    def test_detect_url_online(self, parser):
        assert parser.detect_url("https://online.gls-czech.com/tracking/12345678")

    def test_reject_unrelated_url(self, parser):
        assert not parser.detect_url("https://www.zasilkovna.cz/track")

    def test_detect_email(self, parser):
        assert parser.detect_email("info@gls-czech.com")


# =========================================================================
# Alza Parser
# =========================================================================


class TestAlzaParser:
    @pytest.fixture
    def parser(self):
        return AlzaParser()

    def test_name(self, parser):
        assert parser.name == "alza"

    def test_detect_url(self, parser):
        assert parser.detect_url("https://www.alza.cz/Order/Track/123456")

    def test_reject_unrelated_url(self, parser):
        assert not parser.detect_url("https://www.czc.cz/track")

    def test_detect_email(self, parser):
        assert parser.detect_email("info@alza.cz")

    def test_reject_unrelated_email(self, parser):
        assert not parser.detect_email("info@czc.cz")


# =========================================================================
# Generic Parser
# =========================================================================


class TestGenericParser:
    @pytest.fixture
    def parser(self):
        return GenericParser()

    def test_name(self, parser):
        assert parser.name == "unknown"

    def test_always_detects_url(self, parser):
        # Generic parser should not match specific URLs (it's a fallback)
        assert not parser.detect_url("https://example.com/track")

    def test_never_detects_email(self, parser):
        assert not parser.detect_email("info@example.com")


# =========================================================================
# ShipmentStatus and StatusEvent dataclasses
# =========================================================================


class TestDataClasses:
    def test_status_event_creation(self):
        event = StatusEvent(
            status="in_transit",
            status_detail="Na cestě do depa Praha",
            location="Praha",
            timestamp="2025-01-15T10:00:00",
        )
        assert event.status == "in_transit"
        assert event.location == "Praha"

    def test_status_event_defaults(self):
        event = StatusEvent(status="unknown", status_detail="Test")
        assert event.location is None
        assert event.timestamp is None

    def test_shipment_status_creation(self):
        status = ShipmentStatus(
            status="delivered",
            status_detail="Zásilka doručena příjemci",
            location="Brno",
            expected_delivery="2025-01-20",
            delivery_location="Zásilkovna - OC Chodov",
            history=[
                StatusEvent(status="registered", status_detail="Registrováno"),
                StatusEvent(status="delivered", status_detail="Doručeno"),
            ],
        )
        assert status.status == "delivered"
        assert len(status.history) == 2
        assert status.raw_text is None

    def test_shipment_status_defaults(self):
        status = ShipmentStatus(status="unknown", status_detail="")
        assert status.location is None
        assert status.expected_delivery is None
        assert status.history == []
        assert status.raw_text is None
