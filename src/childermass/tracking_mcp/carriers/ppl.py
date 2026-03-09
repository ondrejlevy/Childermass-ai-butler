"""
PPL CZ tracking parser.

Tracking URL: https://www.ppl.cz/vyhledat-zasilku?shipmentId=12345678901
"""

import logging
import re

import httpx
from bs4 import BeautifulSoup

from .base import CarrierParser, ShipmentStatus, StatusEvent


logger = logging.getLogger(__name__)


class PPLParser(CarrierParser):
    """Parser for PPL CZ tracking pages."""

    name = "ppl"
    url_patterns = [
        re.compile(r"ppl\.cz", re.IGNORECASE),
    ]
    email_patterns = [
        re.compile(r"@ppl\.cz", re.IGNORECASE),
    ]

    async def scrape(
        self,
        url: str,
        tracking_number: str | None = None,
    ) -> ShipmentStatus:
        """Scrape PPL tracking page."""
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

        # PPL typically has a timeline/table of events
        events = soup.select(
            ".shipment-detail-tracking-item, .tracking-row, .timeline-item, table.tracking tr"
        )
        for event in events:
            event_text = event.get_text(separator=" ", strip=True)
            if not event_text or len(event_text) < 5:
                continue

            # Try to extract structured data
            date_el = event.select_one(".date, .tracking-date, td:first-child")
            desc_el = event.select_one(".status, .tracking-status, .description, td:nth-child(2)")
            loc_el = event.select_one(".location, .tracking-location, .depot, td:nth-child(3)")

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

        # Current status from latest event
        if history:
            latest = history[0]
            status_detail = latest.status_detail
            location = latest.location
            current_status = latest.status
        else:
            status_detail = self._extract_fallback_status(raw_text)
            current_status = self._normalize_status(status_detail)

        # ETA — PPL sometimes shows expected delivery date
        eta_el = soup.select_one(".delivery-date, .expected-delivery, .eta")
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
        """Extract status from raw text as fallback."""
        lines = [ln.strip() for ln in text.split("\n") if ln.strip()]
        for line in lines:
            if any(kw in line.lower() for kw in ["doruč", "přeprav", "depo", "sklad", "kurýr"]):
                return line[:200]
        return "Status not parsed"
