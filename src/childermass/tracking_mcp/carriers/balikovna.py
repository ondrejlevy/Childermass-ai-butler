"""
Balíkovna / Česká pošta tracking parser.

Tracking URL: https://b2c.cpost.cz/services/ParcelHistory?parcelNumbers=DR1234567890
Alternative: https://www.postaonline.cz/trackandtrace/-/zasilka/cislo?parcelNumbers=DR1234567890
"""

import logging
import re

import httpx
from bs4 import BeautifulSoup

from .base import CarrierParser, ShipmentStatus, StatusEvent


logger = logging.getLogger(__name__)


class BalikovnaParser(CarrierParser):
    """Parser for Balíkovna / Česká pošta tracking pages."""

    name = "balikovna"
    url_patterns = [
        re.compile(r"b2c\.cpost\.cz", re.IGNORECASE),
        re.compile(r"postaonline\.cz", re.IGNORECASE),
        re.compile(r"cpost\.cz.*parcel", re.IGNORECASE),
        re.compile(r"balikovna\.cz", re.IGNORECASE),
    ]
    email_patterns = [
        re.compile(r"@cpost\.cz", re.IGNORECASE),
        re.compile(r"@ceskaposta\.cz", re.IGNORECASE),
        re.compile(r"@balikovna\.cz", re.IGNORECASE),
        re.compile(r"@postaonline\.cz", re.IGNORECASE),
    ]

    async def scrape(
        self,
        url: str,
        tracking_number: str | None = None,
    ) -> ShipmentStatus:
        """Scrape Česká pošta / Balíkovna tracking page."""
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

        # Česká pošta uses a table for tracking history
        rows = soup.select(
            "table.parcel-history tr, .tracking-table tr, .history-table tr, table tr"
        )
        for row in rows:
            cells = row.select("td")
            if len(cells) < 2:
                continue

            # Typical format: Date | Time | Location | Status
            event_location: str | None = None
            if len(cells) >= 4:
                date_text = cells[0].get_text(strip=True)
                time_text = cells[1].get_text(strip=True)
                event_location = cells[2].get_text(strip=True)
                description = cells[3].get_text(strip=True)
                timestamp = f"{date_text} {time_text}".strip() or None
            elif len(cells) >= 2:
                timestamp = cells[0].get_text(strip=True)
                description = cells[1].get_text(strip=True)
                event_location = cells[2].get_text(strip=True) if len(cells) > 2 else None
            else:
                continue

            if description:
                history.append(
                    StatusEvent(
                        status=self._normalize_status(description),
                        status_detail=description,
                        location=event_location if event_location else None,
                        timestamp=timestamp,
                    )
                )

        # Current status is the first (most recent) event
        if history:
            latest = history[0]
            status_detail = latest.status_detail
            location = latest.location
            current_status = latest.status
        else:
            status_detail = self._extract_fallback_status(raw_text)
            current_status = self._normalize_status(status_detail)

        # Try to find delivery location
        for el in soup.select(".delivery-point, .branch, .pobocka"):
            text = el.get_text(strip=True)
            if text:
                delivery_location = text
                break

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
            if any(kw in line.lower() for kw in ["doruč", "podán", "přeprav", "uložen", "výdejn"]):
                return line[:200]
        return "Status not parsed"
