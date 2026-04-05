"""
Tracking MCP Client

Business logic for package tracking: SQLite database, email parsing,
carrier detection, and web scraping orchestration.

Security features:
- Input validation on all public functions
- Rate limiting per operation type
- Audit logging for state-changing operations
- Error message sanitization to prevent credential leaks
"""

import logging
import re
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .auth import get_db_path
from .carriers.alza import AlzaParser
from .carriers.balikovna import BalikovnaParser
from .carriers.base import CarrierParser
from .carriers.dpd import DPDParser
from .carriers.generic import GenericParser
from .carriers.gls import GLSParser
from .carriers.ppl import PPLParser
from .carriers.zasilkovna import ZasilkovnaParser
from .security import (
    SecurityError,
    audit_log,
    rate_limiter,
    validate_carrier,
    validate_email_body,
    validate_email_from,
    validate_email_subject,
    validate_metadata,
    validate_order_number,
    validate_shipment_id,
    validate_tracking_number,
    validate_url,
)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Carrier Registry
# ---------------------------------------------------------------------------

# All available carrier parsers (order matters for detection priority)
_CARRIER_PARSERS: list[CarrierParser] = [
    ZasilkovnaParser(),
    BalikovnaParser(),
    PPLParser(),
    DPDParser(),
    GLSParser(),
    AlzaParser(),
]

_GENERIC_PARSER = GenericParser()

# E-shop sender patterns for email parsing
_ESHOP_PATTERNS: dict[str, list[re.Pattern]] = {
    "alza.cz": [re.compile(r"@alza\.cz", re.IGNORECASE)],
    "rohlik.cz": [re.compile(r"@rohlik\.cz", re.IGNORECASE)],
    "mall.cz": [re.compile(r"@mall\.cz", re.IGNORECASE)],
    "czc.cz": [re.compile(r"@czc\.cz", re.IGNORECASE)],
    "notino.cz": [re.compile(r"@notino\.cz", re.IGNORECASE)],
    "datart.cz": [re.compile(r"@datart\.cz", re.IGNORECASE)],
    "amazon.de": [re.compile(r"@amazon\.(de|com|co\.uk)", re.IGNORECASE)],
    "temu.com": [re.compile(r"@temu\.com", re.IGNORECASE)],
    "aliexpress.com": [re.compile(r"@aliexpress\.com", re.IGNORECASE)],
}


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


@dataclass
class Shipment:
    """A tracked shipment."""

    id: str
    carrier: str
    tracking_number: str | None
    tracking_url: str
    status: str
    status_detail: str
    expected_delivery: str | None
    delivery_location: str | None
    order_source: str | None
    order_number: str | None
    email_id: str | None
    email_subject: str | None
    last_checked: str | None
    last_status_change: str | None
    is_active: bool
    created_at: str
    metadata: str  # JSON string


@dataclass
class StatusHistoryEntry:
    """A single status change event."""

    id: int
    shipment_id: str
    status: str
    status_detail: str
    location: str | None
    timestamp: str | None
    scraped_at: str


@dataclass
class ShipmentDetail:
    """Full shipment info with status history."""

    shipment: Shipment
    history: list[StatusHistoryEntry] = field(default_factory=list)


@dataclass
class StatusChange:
    """Change detected during batch check."""

    shipment_id: str
    carrier: str
    tracking_number: str | None
    order_source: str | None
    old_status: str
    new_status: str
    new_status_detail: str
    expected_delivery: str | None
    delivery_location: str | None


@dataclass
class EmailParseResult:
    """Result of parsing a shipment email."""

    carrier: str
    tracking_url: str | None
    tracking_number: str | None
    order_source: str | None
    order_number: str | None
    expected_delivery: str | None
    delivery_location: str | None
    confidence: float  # 0.0 - 1.0


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


class TrackingDatabase:
    """SQLite database for shipment tracking."""

    def __init__(self, db_path: Path | None = None):
        self._db_path = db_path or get_db_path()
        self._ensure_schema()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _ensure_schema(self) -> None:
        """Create tables if they don't exist."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        conn = self._get_connection()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS shipments (
                    id TEXT PRIMARY KEY,
                    carrier TEXT NOT NULL,
                    tracking_number TEXT,
                    tracking_url TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'unknown',
                    status_detail TEXT NOT NULL DEFAULT '',
                    expected_delivery TEXT,
                    delivery_location TEXT,
                    order_source TEXT,
                    order_number TEXT,
                    email_id TEXT,
                    email_subject TEXT,
                    last_checked TEXT,
                    last_status_change TEXT,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    metadata TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS status_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    shipment_id TEXT NOT NULL
                        REFERENCES shipments(id) ON DELETE CASCADE,
                    status TEXT NOT NULL,
                    status_detail TEXT NOT NULL DEFAULT '',
                    location TEXT,
                    timestamp TEXT,
                    scraped_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_shipments_active
                    ON shipments(is_active);
                CREATE INDEX IF NOT EXISTS idx_shipments_carrier
                    ON shipments(carrier);
                CREATE INDEX IF NOT EXISTS idx_shipments_tracking_url
                    ON shipments(tracking_url);
                CREATE INDEX IF NOT EXISTS idx_status_history_shipment
                    ON status_history(shipment_id);
            """)
            conn.commit()
        finally:
            conn.close()

    def insert_shipment(self, shipment: Shipment) -> None:
        """Insert a new shipment."""
        conn = self._get_connection()
        try:
            conn.execute(
                """
                INSERT INTO shipments (
                    id, carrier, tracking_number, tracking_url,
                    status, status_detail, expected_delivery, delivery_location,
                    order_source, order_number, email_id, email_subject,
                    last_checked, last_status_change, is_active, created_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    shipment.id,
                    shipment.carrier,
                    shipment.tracking_number,
                    shipment.tracking_url,
                    shipment.status,
                    shipment.status_detail,
                    shipment.expected_delivery,
                    shipment.delivery_location,
                    shipment.order_source,
                    shipment.order_number,
                    shipment.email_id,
                    shipment.email_subject,
                    shipment.last_checked,
                    shipment.last_status_change,
                    1 if shipment.is_active else 0,
                    shipment.created_at,
                    shipment.metadata,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def get_shipment(self, shipment_id: str) -> Shipment | None:
        """Get a shipment by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute("SELECT * FROM shipments WHERE id = ?", (shipment_id,)).fetchone()
            if row is None:
                return None
            return self._row_to_shipment(row)
        finally:
            conn.close()

    def find_by_tracking_url(self, tracking_url: str) -> Shipment | None:
        """Find a shipment by tracking URL."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM shipments WHERE tracking_url = ? ORDER BY created_at DESC LIMIT 1",
                (tracking_url,),
            ).fetchone()
            if row is None:
                return None
            return self._row_to_shipment(row)
        finally:
            conn.close()

    def list_shipments(
        self,
        active_only: bool = True,
        carrier: str | None = None,
        order_source: str | None = None,
    ) -> list[Shipment]:
        """List shipments with optional filters."""
        conn = self._get_connection()
        try:
            query = "SELECT * FROM shipments WHERE 1=1"
            params: list = []

            if active_only:
                query += " AND is_active = 1"
            if carrier:
                query += " AND carrier = ?"
                params.append(carrier)
            if order_source:
                query += " AND order_source = ?"
                params.append(order_source)

            query += " ORDER BY created_at DESC"

            rows = conn.execute(query, params).fetchall()
            return [self._row_to_shipment(row) for row in rows]
        finally:
            conn.close()

    def update_status(
        self,
        shipment_id: str,
        status: str,
        status_detail: str,
        expected_delivery: str | None = None,
        delivery_location: str | None = None,
        location: str | None = None,
    ) -> bool:
        """
        Update shipment status. Returns True if status actually changed.
        """
        conn = self._get_connection()
        try:
            now = datetime.now(UTC).isoformat()

            # Get current status
            row = conn.execute(
                "SELECT status FROM shipments WHERE id = ?", (shipment_id,)
            ).fetchone()
            if row is None:
                return False

            old_status = row["status"]
            status_changed = old_status != status

            # Update shipment
            update_fields = [
                "status = ?",
                "status_detail = ?",
                "last_checked = ?",
            ]
            update_params: list = [status, status_detail, now]

            if status_changed:
                update_fields.append("last_status_change = ?")
                update_params.append(now)

            if expected_delivery is not None:
                update_fields.append("expected_delivery = ?")
                update_params.append(expected_delivery)

            if delivery_location is not None:
                update_fields.append("delivery_location = ?")
                update_params.append(delivery_location)

            # Auto-deactivate delivered/returned/cancelled shipments
            if status in ("delivered", "returned", "cancelled"):
                update_fields.append("is_active = 0")

            update_params.append(shipment_id)

            conn.execute(
                f"UPDATE shipments SET {', '.join(update_fields)} WHERE id = ?",  # noqa: S608
                update_params,
            )

            # Add to status history
            conn.execute(
                """
                INSERT INTO status_history (
                    shipment_id, status, status_detail, location, timestamp, scraped_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (shipment_id, status, status_detail, location, now, now),
            )

            conn.commit()
            return status_changed
        finally:
            conn.close()

    def archive_shipment(self, shipment_id: str) -> bool:
        """Mark a shipment as inactive."""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "UPDATE shipments SET is_active = 0 WHERE id = ?",
                (shipment_id,),
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    def get_history(self, shipment_id: str) -> list[StatusHistoryEntry]:
        """Get status history for a shipment."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM status_history WHERE shipment_id = ? ORDER BY scraped_at DESC",
                (shipment_id,),
            ).fetchall()
            return [
                StatusHistoryEntry(
                    id=row["id"],
                    shipment_id=row["shipment_id"],
                    status=row["status"],
                    status_detail=row["status_detail"],
                    location=row["location"],
                    timestamp=row["timestamp"],
                    scraped_at=row["scraped_at"],
                )
                for row in rows
            ]
        finally:
            conn.close()

    def _row_to_shipment(self, row: sqlite3.Row) -> Shipment:
        """Convert a database row to a Shipment object."""
        return Shipment(
            id=row["id"],
            carrier=row["carrier"],
            tracking_number=row["tracking_number"],
            tracking_url=row["tracking_url"],
            status=row["status"],
            status_detail=row["status_detail"],
            expected_delivery=row["expected_delivery"],
            delivery_location=row["delivery_location"],
            order_source=row["order_source"],
            order_number=row["order_number"],
            email_id=row["email_id"],
            email_subject=row["email_subject"],
            last_checked=row["last_checked"],
            last_status_change=row["last_status_change"],
            is_active=bool(row["is_active"]),
            created_at=row["created_at"],
            metadata=row["metadata"],
        )


# ---------------------------------------------------------------------------
# Client (singleton)
# ---------------------------------------------------------------------------


_client_instance: "TrackingClient | None" = None


def get_client() -> "TrackingClient":
    """Get or create the singleton TrackingClient."""
    global _client_instance
    if _client_instance is None:
        _client_instance = TrackingClient()
    return _client_instance


class TrackingClient:
    """Main tracking client with all business logic."""

    def __init__(self, db_path: Path | None = None):
        self._db = TrackingDatabase(db_path)

    # -------------------------------------------------------------------
    # Carrier Detection
    # -------------------------------------------------------------------

    def detect_carrier_from_url(self, url: str) -> str:
        """Detect carrier from tracking URL pattern."""
        for parser in _CARRIER_PARSERS:
            if parser.detect_url(url):
                return parser.name
        return "unknown"

    def detect_carrier_from_email(self, from_addr: str) -> str:
        """Detect carrier from email sender address."""
        for parser in _CARRIER_PARSERS:
            if parser.detect_email(from_addr):
                return parser.name
        return "unknown"

    def detect_eshop(self, from_addr: str) -> str | None:
        """Detect e-shop from email sender address."""
        from_lower = from_addr.lower()
        for eshop, patterns in _ESHOP_PATTERNS.items():
            if any(p.search(from_lower) for p in patterns):
                return eshop
        return None

    def _get_parser(self, carrier: str) -> CarrierParser:
        """Get the parser for a specific carrier."""
        for parser in _CARRIER_PARSERS:
            if parser.name == carrier:
                return parser
        return _GENERIC_PARSER

    # -------------------------------------------------------------------
    # Registration
    # -------------------------------------------------------------------

    def register_shipment(
        self,
        carrier: str,
        tracking_url: str,
        tracking_number: str | None = None,
        order_source: str | None = None,
        order_number: str | None = None,
        email_id: str | None = None,
        email_subject: str | None = None,
        expected_delivery: str | None = None,
        delivery_location: str | None = None,
        metadata: str | None = None,
    ) -> Shipment:
        """Register a new shipment for tracking."""
        rate_limiter.check("register")

        # Validate inputs
        carrier = validate_carrier(carrier)
        tracking_url = validate_url(tracking_url, "Tracking URL")

        if tracking_number:
            tracking_number = validate_tracking_number(tracking_number)
        if order_number:
            order_number = validate_order_number(order_number)
        if metadata:
            metadata = validate_metadata(metadata)

        # Check for duplicates
        existing = self._db.find_by_tracking_url(tracking_url)
        if existing and existing.is_active:
            msg = (
                f"Shipment already registered with this tracking URL "
                f"(ID: {existing.id}, carrier: {existing.carrier})"
            )
            raise SecurityError(msg)

        now = datetime.now(UTC).isoformat()
        shipment = Shipment(
            id=str(uuid.uuid4()),
            carrier=carrier,
            tracking_number=tracking_number,
            tracking_url=tracking_url,
            status="registered",
            status_detail="Shipment registered for tracking",
            expected_delivery=expected_delivery,
            delivery_location=delivery_location,
            order_source=order_source,
            order_number=order_number,
            email_id=email_id,
            email_subject=email_subject,
            last_checked=None,
            last_status_change=now,
            is_active=True,
            created_at=now,
            metadata=metadata or "{}",
        )

        self._db.insert_shipment(shipment)

        audit_log(
            "register_shipment",
            details={
                "shipment_id": shipment.id,
                "carrier": carrier,
                "tracking_number": tracking_number,
                "order_source": order_source,
            },
        )

        return shipment

    # -------------------------------------------------------------------
    # Status Check (Scraping)
    # -------------------------------------------------------------------

    async def check_status(self, shipment_id: str) -> ShipmentDetail:
        """
        Check live status of a shipment by scraping its tracking page.

        Returns updated ShipmentDetail with full history.
        """
        rate_limiter.check("scrape")
        shipment_id = validate_shipment_id(shipment_id)

        shipment = self._db.get_shipment(shipment_id)
        if shipment is None:
            msg = f"Shipment not found: {shipment_id}"
            raise SecurityError(msg)

        # Get the right parser
        parser = self._get_parser(shipment.carrier)

        # Scrape tracking page
        try:
            result = await parser.scrape(
                shipment.tracking_url,
                shipment.tracking_number,
            )
        except Exception as e:
            logger.warning(
                "Scrape failed for %s (%s): %s",
                shipment_id,
                shipment.tracking_url,
                e,
            )
            # Update last_checked even on failure
            self._db.update_status(
                shipment_id,
                shipment.status,
                f"Scrape failed: {type(e).__name__}",
            )
            raise

        # Update database with scraped status
        self._db.update_status(
            shipment_id,
            result.status,
            result.status_detail,
            expected_delivery=result.expected_delivery,
            delivery_location=result.delivery_location,
            location=result.location,
        )

        audit_log(
            "check_status",
            details={
                "shipment_id": shipment_id,
                "carrier": shipment.carrier,
                "status": result.status,
            },
        )

        # Return updated shipment with history
        updated_shipment = self._db.get_shipment(shipment_id)
        history = self._db.get_history(shipment_id)

        if updated_shipment is None:
            msg = f"Shipment disappeared after status update: {shipment_id}"
            raise RuntimeError(msg)

        return ShipmentDetail(
            shipment=updated_shipment,
            history=history,
        )

    async def check_all_active(self) -> list[StatusChange]:
        """
        Check status of all active shipments.

        Returns list of shipments whose status changed.
        """
        rate_limiter.check("batch")

        active_shipments = self._db.list_shipments(active_only=True)
        changes: list[StatusChange] = []

        for shipment in active_shipments:
            old_status = shipment.status
            parser = self._get_parser(shipment.carrier)

            try:
                result = await parser.scrape(
                    shipment.tracking_url,
                    shipment.tracking_number,
                )
            except Exception as e:
                logger.warning("Batch scrape failed for %s: %s", shipment.id, e)
                continue

            # Update status in DB
            changed = self._db.update_status(
                shipment.id,
                result.status,
                result.status_detail,
                expected_delivery=result.expected_delivery,
                delivery_location=result.delivery_location,
                location=result.location,
            )

            if changed:
                changes.append(
                    StatusChange(
                        shipment_id=shipment.id,
                        carrier=shipment.carrier,
                        tracking_number=shipment.tracking_number,
                        order_source=shipment.order_source,
                        old_status=old_status,
                        new_status=result.status,
                        new_status_detail=result.status_detail,
                        expected_delivery=result.expected_delivery,
                        delivery_location=result.delivery_location,
                    )
                )

        audit_log(
            "check_all_active",
            details={
                "total_checked": len(active_shipments),
                "changes_detected": len(changes),
            },
        )

        return changes

    # -------------------------------------------------------------------
    # Read Operations
    # -------------------------------------------------------------------

    def get_shipment(self, shipment_id: str) -> ShipmentDetail:
        """Get shipment details from DB (no live scrape)."""
        rate_limiter.check("read")
        shipment_id = validate_shipment_id(shipment_id)

        shipment = self._db.get_shipment(shipment_id)
        if shipment is None:
            msg = f"Shipment not found: {shipment_id}"
            raise SecurityError(msg)

        history = self._db.get_history(shipment_id)
        return ShipmentDetail(shipment=shipment, history=history)

    def list_shipments(
        self,
        active_only: bool = True,
        carrier: str | None = None,
        order_source: str | None = None,
    ) -> list[Shipment]:
        """List shipments with optional filters."""
        rate_limiter.check("read")

        if carrier:
            carrier = validate_carrier(carrier)

        return self._db.list_shipments(
            active_only=active_only,
            carrier=carrier,
            order_source=order_source,
        )

    def archive_shipment(self, shipment_id: str) -> bool:
        """Mark a shipment as inactive."""
        rate_limiter.check("archive")
        shipment_id = validate_shipment_id(shipment_id)

        success = self._db.archive_shipment(shipment_id)

        if success:
            audit_log(
                "archive_shipment",
                details={"shipment_id": shipment_id},
            )

        return success

    # -------------------------------------------------------------------
    # Email Parsing
    # -------------------------------------------------------------------

    def parse_email(
        self,
        email_body: str,
        email_subject: str,
        email_from: str,
        email_body_html: str | None = None,
    ) -> EmailParseResult:
        """
        Parse a shipment notification email and extract tracking info.

        Analyses email body/HTML for tracking URLs, numbers, carrier info,
        and order details.

        Args:
            email_body: Plain text email body
            email_subject: Email subject line
            email_from: Sender email address
            email_body_html: HTML email body (for URL extraction)

        Returns:
            EmailParseResult with extracted tracking data
        """
        rate_limiter.check("parse")

        email_body = validate_email_body(email_body)
        email_subject = validate_email_subject(email_subject)
        email_from = validate_email_from(email_from)
        if email_body_html:
            email_body_html = validate_email_body(email_body_html)

        # Start with low confidence
        confidence = 0.0

        # Detect e-shop from sender
        order_source = self.detect_eshop(email_from)
        if order_source:
            confidence += 0.2

        # Detect carrier from sender
        carrier = self.detect_carrier_from_email(email_from)
        if carrier != "unknown":
            confidence += 0.3

        # Extract tracking URLs from HTML body (preferred)
        tracking_url = None
        search_text = email_body_html or email_body

        tracking_urls = self._extract_tracking_urls(search_text)
        if tracking_urls:
            tracking_url = tracking_urls[0]
            confidence += 0.3

            # If we found a URL, detect carrier from it
            url_carrier = self.detect_carrier_from_url(tracking_url)
            if url_carrier != "unknown":
                carrier = url_carrier
                confidence += 0.1

        # Extract tracking number
        tracking_number = self._extract_tracking_number(email_body, email_subject, carrier)
        if tracking_number:
            confidence += 0.1

        # Extract order number
        order_number = self._extract_order_number(email_body, email_subject)

        # If still no carrier, try subject line
        if carrier == "unknown":
            carrier = self._detect_carrier_from_subject(email_subject)
            if carrier != "unknown":
                confidence += 0.2

        # Extract delivery location
        delivery_location = self._extract_delivery_location(email_body)

        # Extract expected delivery date
        expected_delivery = self._extract_expected_delivery(email_body, email_subject)

        return EmailParseResult(
            carrier=carrier,
            tracking_url=tracking_url,
            tracking_number=tracking_number,
            order_source=order_source,
            order_number=order_number,
            expected_delivery=expected_delivery,
            delivery_location=delivery_location,
            confidence=min(confidence, 1.0),
        )

    def _extract_tracking_urls(self, text: str) -> list[str]:
        """Extract tracking URLs from text/HTML."""
        urls: list[str] = []

        # Known tracking URL patterns
        tracking_patterns = [
            # Zásilkovna
            r'https?://tracking\.zasilkovna\.cz/[^\s"\'<>]+',
            r'https?://(?:www\.)?zasilkovna\.cz/sledovani[^\s"\'<>]*',
            # Balíkovna / Česká pošta
            r'https?://b2c\.cpost\.cz/services/ParcelHistory[^\s"\'<>]*',
            r'https?://(?:www\.)?postaonline\.cz/trackandtrace[^\s"\'<>]*',
            r'https?://(?:www\.)?balikovna\.cz[^\s"\'<>]*track[^\s"\'<>]*',
            # PPL
            r'https?://(?:www\.)?ppl\.cz/vyhledat-zasilku[^\s"\'<>]*',
            # DPD
            r'https?://tracking\.dpd\.de[^\s"\'<>]*',
            r'https?://(?:www\.)?dpd\.cz[^\s"\'<>]*sledov[^\s"\'<>]*',
            # GLS
            r'https?://gls-group\.com/CZ[^\s"\'<>]*',
            r'https?://online\.gls[^\s"\'<>]*',
            # Alza
            r'https?://(?:www\.)?alza\.cz/Order/Track[^\s"\'<>]*',
        ]

        for pattern in tracking_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            urls.extend(matches)

        # Also look for generic href tracking links
        href_pattern = r'href=["\']([^"\']*(?:track|sledov|zasilk|parcel)[^"\']*)["\']'
        href_matches = re.findall(href_pattern, text, re.IGNORECASE)
        for href in href_matches:
            if href.startswith("http") and href not in urls:
                urls.append(href)

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique_urls: list[str] = []
        for url in urls:
            # Clean up URL (remove trailing punctuation)
            url = url.rstrip(".,;:!?)")
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)

        return unique_urls

    def _extract_tracking_number(self, body: str, subject: str, carrier: str) -> str | None:
        """Extract tracking number based on carrier-specific patterns."""
        combined = f"{subject}\n{body}"

        # Carrier-specific patterns
        patterns: dict[str, list[str]] = {
            "zasilkovna": [r"\bZ\d{10,14}\b"],
            "balikovna": [r"\bDR\d{10,14}\b", r"\bRR\d{10,14}CZ\b"],
            "ceska_posta": [r"\bDR\d{10,14}\b", r"\bRR\d{10,14}CZ\b"],
            "ppl": [r"\b\d{11,14}\b"],
            "dpd": [r"\b\d{14}\b", r"\b01\d{12}\b"],
            "gls": [r"\b\d{8,12}\b"],
        }

        # Try carrier-specific patterns first
        if carrier in patterns:
            for pattern in patterns[carrier]:
                match = re.search(pattern, combined)
                if match:
                    return match.group(0)

        # Generic tracking number patterns
        generic_patterns = [
            r"(?:číslo zásilky|tracking\s*(?:number|id|#)?|zásilka\s*č\.?)\s*:?\s*([A-Z0-9\-]{6,30})",
        ]
        for pattern in generic_patterns:
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def _extract_order_number(self, body: str, subject: str) -> str | None:
        """Extract order number from email."""
        combined = f"{subject}\n{body}"

        patterns = [
            # Requires č./číslo/# separator to avoid false positives
            r"(?:objednávka|obj\.)\s*(?:č(?:íslo)?\.?|#)\s*:?\s*([A-Z0-9\-]{4,30})",
            r"(?:order)\s*(?:number|#|no\.?)\s*:?\s*([A-Z0-9\-]{4,30})",
            r"(?:č(?:íslo)?\.?\s*objednávky)\s*:?\s*([A-Z0-9\-]{4,30})",
        ]

        for pattern in patterns:
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                return match.group(1).strip()

        return None

    def _detect_carrier_from_subject(self, subject: str) -> str:
        """Detect carrier from email subject line."""
        subject_lower = subject.lower()

        carrier_keywords = {
            "zasilkovna": ["zásilkovna", "zasilkovna", "packeta"],
            "balikovna": ["balíkovna", "balikovna", "česká pošta", "ceska posta"],
            "ppl": ["ppl"],
            "dpd": ["dpd"],
            "gls": ["gls"],
            "alza": ["alza"],
            "rohlik": ["rohlík", "rohlik"],
        }

        for carrier, keywords in carrier_keywords.items():
            if any(kw in subject_lower for kw in keywords):
                return carrier

        return "unknown"

    def _extract_delivery_location(self, body: str) -> str | None:
        """Extract delivery location/address from email body."""
        patterns = [
            r"(?:výdejní místo|pobočka|na adresu|doručovací adresa|doručení na)\s*:?\s*(.+?)(?:\n|$)",
            r"(?:pickup point|delivery address|branch)\s*:?\s*(.+?)(?:\n|$)",
        ]

        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                location = match.group(1).strip()
                if 5 < len(location) < 200:
                    return location

        return None

    def _extract_expected_delivery(self, body: str, subject: str) -> str | None:
        """Extract expected delivery date from email."""
        combined = f"{subject}\n{body}"

        patterns = [
            r"(?:doručení|doručena|delivery|dorazí|doručíme)\s*(?:dne|do|v)?\s*:?\s*(\d{1,2}\.\s*\d{1,2}\.\s*\d{4})",
            r"(?:předpokládané doručení|expected delivery)\s*:?\s*(\d{1,2}\.\s*\d{1,2}\.\s*\d{4})",
            r"(?:doručení|delivery)\s*:?\s*(\d{4}-\d{2}-\d{2})",
        ]

        for pattern in patterns:
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                return match.group(1).strip()

        return None

    # -------------------------------------------------------------------
    # Carrier Detection (standalone)
    # -------------------------------------------------------------------

    def detect_carrier(
        self,
        url: str | None = None,
        email_from: str | None = None,
    ) -> dict:
        """
        Detect carrier from URL pattern or email sender.

        Returns dict with carrier info and detection method.
        """
        rate_limiter.check("read")

        result: dict = {"carrier": "unknown", "method": "none"}

        if url:
            url = validate_url(url, "URL")
            carrier = self.detect_carrier_from_url(url)
            if carrier != "unknown":
                return {"carrier": carrier, "method": "url_pattern"}

        if email_from:
            email_from = validate_email_from(email_from)
            carrier = self.detect_carrier_from_email(email_from)
            if carrier != "unknown":
                return {"carrier": carrier, "method": "email_pattern"}

            # Also check e-shop patterns
            eshop = self.detect_eshop(email_from)
            if eshop:
                result["order_source"] = eshop
                result["method"] = "eshop_pattern"

        return result
