"""
Generic / fallback tracking parser.

Used when no carrier-specific parser matches the URL.
Fetches the page and extracts raw text for the agent to interpret.
"""

import logging

import httpx
from bs4 import BeautifulSoup

from .base import CarrierParser, ShipmentStatus, StatusEvent


logger = logging.getLogger(__name__)


class GenericParser(CarrierParser):
    """Generic fallback parser for unknown carrier tracking pages."""

    name = "unknown"
    url_patterns = []  # Never auto-detected; used as explicit fallback
    email_patterns = []

    async def scrape(
        self,
        url: str,
        tracking_number: str | None = None,
    ) -> ShipmentStatus:
        """Scrape any tracking page and return raw text for agent analysis."""
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

        # Try to extract any tracking-like information
        history: list[StatusEvent] = []
        status_keywords = [
            "doruč",
            "odesla",
            "přeprav",
            "přijat",
            "expedov",
            "delivered",
            "shipped",
            "transit",
            "tracking",
            "vyzvednut",
            "uložen",
        ]

        lines = [ln.strip() for ln in raw_text.split("\n") if ln.strip()]
        for line in lines:
            if len(line) > 10 and any(kw in line.lower() for kw in status_keywords):
                history.append(
                    StatusEvent(
                        status=self._normalize_status(line),
                        status_detail=line[:300],
                        location=None,
                        timestamp=None,
                    )
                )
                if len(history) >= 20:
                    break

        if history:
            status_detail = history[0].status_detail
            current_status = history[0].status
        else:
            status_detail = "Could not parse tracking page — raw text available"
            current_status = "unknown"

        return ShipmentStatus(
            status=current_status,
            status_detail=status_detail,
            location=None,
            expected_delivery=None,
            delivery_location=None,
            history=history,
            raw_text=raw_text[:8000],  # Larger limit for generic parser
        )
