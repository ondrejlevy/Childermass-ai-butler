"""
Zásilkovna (Packeta) tracking parser.

Tracking URL: https://tracking.zasilkovna.cz/Z1234567890
Alternative: https://www.zasilkovna.cz/sledovani-zasilky/Z1234567890
"""

import logging
import re

import httpx
from bs4 import BeautifulSoup

from .base import CarrierParser, ShipmentStatus, StatusEvent


logger = logging.getLogger(__name__)


class ZasilkovnaParser(CarrierParser):
    """Parser for Zásilkovna (Packeta) tracking pages."""

    name = "zasilkovna"
    url_patterns = [
        re.compile(r"tracking\.zasilkovna\.cz", re.IGNORECASE),
        re.compile(r"zasilkovna\.cz/sledovani", re.IGNORECASE),
        re.compile(r"app\.packeta\.com/tracking", re.IGNORECASE),
    ]
    email_patterns = [
        re.compile(r"@zasilkovna\.cz", re.IGNORECASE),
        re.compile(r"@packeta\.com", re.IGNORECASE),
    ]

    async def scrape(
        self,
        url: str,
        tracking_number: str | None = None,
    ) -> ShipmentStatus:
        """Scrape Zásilkovna tracking page."""
        async with httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "Accept-Language": "cs-CZ,cs;q=0.9,en;q=0.8",
            },
        ) as client:
            response = await client.get(url)
            response.raise_for_status()
            html = response.text

        soup = BeautifulSoup(html, "lxml")
        raw_text = soup.get_text(separator="\n", strip=True)

        history: list[StatusEvent] = []
        status_detail = ""
        location = None
        expected_delivery = None
        delivery_location = None

        # Parse tracking events from the page
        # Zásilkovna typically has a timeline of events
        events = soup.select(".tracking-event, .timeline-item, .status-row, tr")
        for event in events:
            event_text = event.get_text(separator=" ", strip=True)
            if not event_text or len(event_text) < 5:
                continue

            # Try to extract timestamp and description
            time_el = event.select_one(".tracking-event-date, .date, .time, td:first-child")
            desc_el = event.select_one(
                ".tracking-event-text, .description, .status, td:nth-child(2)"
            )
            loc_el = event.select_one(".tracking-event-location, .location, td:nth-child(3)")

            timestamp = time_el.get_text(strip=True) if time_el else None
            description = desc_el.get_text(strip=True) if desc_el else event_text
            event_location = loc_el.get_text(strip=True) if loc_el else None

            if description:
                history.append(
                    StatusEvent(
                        status=self._normalize_status(description),
                        status_detail=description,
                        location=event_location,
                        timestamp=timestamp,
                    )
                )

        # Current status is the latest event
        if history:
            latest = history[0]
            status_detail = latest.status_detail
            location = latest.location
            current_status = latest.status
        else:
            # Fallback: try to find status in the page text
            status_detail = self._extract_status_from_text(raw_text)
            current_status = self._normalize_status(status_detail)

        # Try to extract delivery location
        pickup_el = soup.select_one(".delivery-point, .pickup-point, .branch-name")
        if pickup_el:
            delivery_location = pickup_el.get_text(strip=True)

        # Try to extract ETA
        eta_el = soup.select_one(".delivery-date, .eta, .expected-delivery")
        if eta_el:
            expected_delivery = eta_el.get_text(strip=True)

        return ShipmentStatus(
            status=current_status,
            status_detail=status_detail,
            location=location,
            expected_delivery=expected_delivery,
            delivery_location=delivery_location,
            history=history,
            raw_text=raw_text[:5000],  # Limit raw text size
        )

    def _extract_status_from_text(self, text: str) -> str:
        """Extract status from raw page text as fallback."""
        lines = [ln.strip() for ln in text.split("\n") if ln.strip()]
        # Look for status-like lines
        for line in lines:
            if len(line) > 10 and any(
                kw in line.lower()
                for kw in [
                    "doruč",
                    "přeprav",
                    "vyzvednut",
                    "uložen",
                    "odesla",
                    "připraven",
                ]
            ):
                return line[:200]
        return "Status not parsed"
