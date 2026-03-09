"""
DPD CZ tracking parser.

Tracking URL: https://tracking.dpd.de/status/cs_CZ/parcel/01234567890123
Alternative: https://www.dpd.cz/sledovani-zasilky?parcelNumber=01234567890123
"""

import logging
import re

import httpx
from bs4 import BeautifulSoup

from .base import CarrierParser, ShipmentStatus, StatusEvent


logger = logging.getLogger(__name__)


class DPDParser(CarrierParser):
    """Parser for DPD CZ tracking pages."""

    name = "dpd"
    url_patterns = [
        re.compile(r"tracking\.dpd\.de", re.IGNORECASE),
        re.compile(r"dpd\.cz", re.IGNORECASE),
        re.compile(r"dpd\.com", re.IGNORECASE),
    ]
    email_patterns = [
        re.compile(r"@dpd\.cz", re.IGNORECASE),
        re.compile(r"@dpd\.de", re.IGNORECASE),
        re.compile(r"@dpd\.com", re.IGNORECASE),
    ]

    async def scrape(
        self,
        url: str,
        tracking_number: str | None = None,
    ) -> ShipmentStatus:
        """Scrape DPD tracking page."""
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

        # DPD uses a tracking events list/table
        events = soup.select(
            ".parcelLifeCycleEvent, .tracking-event, "
            ".status-event, table.tracking tr, .timeline-entry"
        )
        for event in events:
            event_text = event.get_text(separator=" ", strip=True)
            if not event_text or len(event_text) < 5:
                continue

            date_el = event.select_one(".date, .eventDate, td:first-child")
            desc_el = event.select_one(".eventDescription, .status, .description, td:nth-child(2)")
            loc_el = event.select_one(".eventLocation, .location, .depot, td:nth-child(3)")

            timestamp = date_el.get_text(strip=True) if date_el else None
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

        if history:
            latest = history[0]
            status_detail = latest.status_detail
            location = latest.location
            current_status = latest.status
        else:
            status_detail = self._extract_fallback_status(raw_text)
            current_status = self._normalize_status(status_detail)

        # ETA
        eta_el = soup.select_one(".delivery-date, .expected-delivery, .eta, .deliveryDate")
        if eta_el:
            expected_delivery = eta_el.get_text(strip=True)

        return ShipmentStatus(
            status=current_status,
            status_detail=status_detail,
            location=location,
            expected_delivery=expected_delivery,
            delivery_location=delivery_location,
            history=history,
            raw_text=raw_text[:5000],
        )

    def _extract_fallback_status(self, text: str) -> str:
        """Extract status from raw text."""
        lines = [ln.strip() for ln in text.split("\n") if ln.strip()]
        for line in lines:
            if any(kw in line.lower() for kw in ["doruč", "přeprav", "depo", "scan", "parcel"]):
                return line[:200]
        return "Status not parsed"
