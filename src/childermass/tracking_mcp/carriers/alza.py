"""
Alza.cz order tracking parser.

Tracking URL: https://www.alza.cz/Order/Track/12345678
"""

import logging
import re

import httpx
from bs4 import BeautifulSoup

from .base import CarrierParser, ShipmentStatus, StatusEvent


logger = logging.getLogger(__name__)


class AlzaParser(CarrierParser):
    """Parser for Alza.cz order/shipment tracking pages."""

    name = "alza"
    url_patterns = [
        re.compile(r"alza\.cz/Order", re.IGNORECASE),
        re.compile(r"alza\.cz.*track", re.IGNORECASE),
        re.compile(r"alza\.cz.*sledovani", re.IGNORECASE),
    ]
    email_patterns = [
        re.compile(r"@alza\.cz", re.IGNORECASE),
    ]

    async def scrape(
        self,
        url: str,
        tracking_number: str | None = None,
    ) -> ShipmentStatus:
        """Scrape Alza.cz tracking page."""
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

        # Alza tracking timeline / status steps
        events = soup.select(
            ".order-status-step, .shipment-status, .tracking-step, .status-item, .timeline-item"
        )
        for event in events:
            event_text = event.get_text(separator=" ", strip=True)
            if not event_text or len(event_text) < 3:
                continue

            # Check if step is active/completed
            classes = event.get("class")
            class_list = classes if isinstance(classes, list) else []
            _is_active = "active" in class_list or "completed" in class_list

            date_el = event.select_one(".date, .step-date")
            timestamp = date_el.get_text(strip=True) if date_el else None

            history.append(
                StatusEvent(
                    status=self._normalize_status(event_text),
                    status_detail=event_text,
                    location=None,
                    timestamp=timestamp,
                )
            )

        # Current status from active step or latest event
        if history:
            latest = history[0]
            status_detail = latest.status_detail
            current_status = latest.status
        else:
            status_detail = self._extract_fallback_status(raw_text)
            current_status = self._normalize_status(status_detail)

        # Delivery location from page
        loc_el = soup.select_one(
            ".delivery-address, .pickup-point, .branch-name, .alzabox-name, .delivery-place"
        )
        if loc_el:
            delivery_location = loc_el.get_text(strip=True)

        # Expected delivery
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
        """Extract status from raw text."""
        lines = [ln.strip() for ln in text.split("\n") if ln.strip()]
        for line in lines:
            if any(
                kw in line.lower()
                for kw in [
                    "objednávka",
                    "doruč",
                    "expedov",
                    "odesla",
                    "připraven",
                ]
            ):
                return line[:200]
        return "Status not parsed"
