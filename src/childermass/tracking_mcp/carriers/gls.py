"""
GLS Czech Republic tracking parser.

Tracking URL: https://gls-group.com/CZ/cs/sledovani-zasilek?match=12345678
Alternative: https://online.gls-czech.com/tt_page.php?tt_value=12345678
"""

import logging
import re

import httpx
from bs4 import BeautifulSoup

from .base import CarrierParser, ShipmentStatus, StatusEvent


logger = logging.getLogger(__name__)


class GLSParser(CarrierParser):
    """Parser for GLS CZ tracking pages."""

    name = "gls"
    url_patterns = [
        re.compile(r"gls-group\.com/CZ", re.IGNORECASE),
        re.compile(r"gls-czech\.com", re.IGNORECASE),
        re.compile(r"gls\.cz", re.IGNORECASE),
        re.compile(r"online\.gls", re.IGNORECASE),
    ]
    email_patterns = [
        re.compile(r"@gls", re.IGNORECASE),
    ]

    async def scrape(
        self,
        url: str,
        tracking_number: str | None = None,
    ) -> ShipmentStatus:
        """Scrape GLS tracking page."""
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

        # GLS tracking events
        events = soup.select(".parcel-detail-table tr, .tracking-event, .timeline-item, table tr")
        for event in events:
            cells = event.select("td")
            if len(cells) < 2:
                continue

            if len(cells) >= 3:
                timestamp = cells[0].get_text(strip=True)
                event_location = cells[1].get_text(strip=True)
                description = cells[2].get_text(strip=True)
            else:
                timestamp = cells[0].get_text(strip=True)
                description = cells[1].get_text(strip=True)
                event_location = None

            if description:
                history.append(
                    StatusEvent(
                        status=self._normalize_status(description),
                        status_detail=description,
                        location=event_location if event_location else None,
                        timestamp=timestamp if timestamp else None,
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
