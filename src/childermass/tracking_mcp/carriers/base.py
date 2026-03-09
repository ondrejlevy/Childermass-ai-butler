"""
Base carrier parser interface and shared data models.

All carrier-specific parsers inherit from CarrierParser and implement
the detect/scrape methods.
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class StatusEvent:
    """A single tracking event in a shipment's history."""

    status: str  # normalised status
    status_detail: str  # original text from tracking page
    location: str | None = None
    timestamp: str | None = None  # ISO 8601 or original text


@dataclass
class ShipmentStatus:
    """Result of scraping a tracking page."""

    status: str  # normalised: registered, in_transit, out_for_delivery, etc.
    status_detail: str  # last status text from page
    location: str | None = None  # current location if available
    expected_delivery: str | None = None  # ETA if available
    delivery_location: str | None = None  # destination branch/address
    history: list[StatusEvent] = field(default_factory=list)
    raw_text: str | None = None  # raw page text for fallback analysis


class CarrierParser(ABC):
    """Abstract base class for carrier tracking page parsers."""

    name: str = "unknown"
    url_patterns: list[re.Pattern] = []
    email_patterns: list[re.Pattern] = []

    @classmethod
    def detect_url(cls, url: str) -> bool:
        """Check if this parser handles the given tracking URL."""
        return any(pattern.search(url) for pattern in cls.url_patterns)

    @classmethod
    def detect_email(cls, from_addr: str) -> bool:
        """Check if this parser handles emails from this sender."""
        return any(pattern.search(from_addr.lower()) for pattern in cls.email_patterns)

    @abstractmethod
    async def scrape(
        self,
        url: str,
        tracking_number: str | None = None,
    ) -> ShipmentStatus:
        """
        Scrape the tracking page and return current shipment status.

        Args:
            url: Tracking page URL
            tracking_number: Optional tracking number for API-based lookups

        Returns:
            ShipmentStatus with current status and history
        """
        ...

    def _normalize_status(self, raw_status: str) -> str:
        """Map carrier-specific status text to normalised status."""
        raw_lower = raw_status.lower()

        # Pickup ready (must be checked BEFORE delivered, because
        # 'vyzvednutí' contains 'vyzvednut' which would match delivered)
        pickup_kw = [
            "připraven k vyzvednutí",
            "k vyzvednutí",
            "ready for pickup",
            "uložen",
            "uložena",
            "na výdejním místě",
            "na pobočce",
        ]
        if any(kw in raw_lower for kw in pickup_kw):
            return "pickup_ready"

        # Delivered
        delivered_kw = [
            "doručen",
            "doručená",
            "delivered",
            "vyzvednut",
            "předán",
            "předána",
            "převzat",
        ]
        if any(kw in raw_lower for kw in delivered_kw):
            return "delivered"

        # Out for delivery
        ofd_kw = [
            "na cestě k vám",
            "doručuje se",
            "v doručování",
            "out for delivery",
            "on the way",
            "kurýr",
        ]
        if any(kw in raw_lower for kw in ofd_kw):
            return "out_for_delivery"

        # In transit
        transit_kw = [
            "přeprav",  # matches přeprava, přepravě, přepravou, etc.
            "na cestě",
            "in transit",
            "odesláno",
            "odeslána",
            "expedováno",
            "přijato",
            "zpracován",
            "depo",
            "sklad",
            "překládka",
            "nakládka",
        ]
        if any(kw in raw_lower for kw in transit_kw):
            return "in_transit"

        # Registered
        registered_kw = [
            "zaregistrován",
            "objednán",
            "nová zásilka",
            "registered",
            "created",
            "podán",
            "podána",
            "data received",
        ]
        if any(kw in raw_lower for kw in registered_kw):
            return "registered"

        # Returned
        returned_kw = [
            "vrácen",
            "returned",
            "nedoručen",
            "neúspěšn",
            "zpět",
        ]
        if any(kw in raw_lower for kw in returned_kw):
            return "returned"

        # Cancelled
        cancelled_kw = ["zrušen", "storno", "cancelled", "canceled"]
        if any(kw in raw_lower for kw in cancelled_kw):
            return "cancelled"

        return "unknown"
