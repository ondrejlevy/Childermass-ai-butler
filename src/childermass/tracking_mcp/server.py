"""
Childermass Tracking MCP Server

Package tracking for Czech e-shops and carriers.
Scrapes public tracking pages to provide shipment status updates.

Security: All tool responses go through error sanitization so that
internal paths, database details, or credentials are never leaked to the LLM.

Run with: python -m childermass.tracking_mcp.server
"""

from dataclasses import asdict

from mcp.server.fastmcp import FastMCP

from .client import get_client
from .security import SecurityError, sanitize_error_message


# Create FastMCP server
mcp = FastMCP("childermass-tracking")


# ---------------------------------------------------------------------------
# Registration tools
# ---------------------------------------------------------------------------


@mcp.tool()
def tracking_register(
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
) -> dict:
    """
    Register a new shipment for tracking.

    Creates a tracking record in the local database. The shipment's status
    can then be checked periodically via tracking_status or tracking_check_all.

    Args:
        carrier: Carrier identifier. One of: zasilkovna, balikovna, ceska_posta,
                 ppl, dpd, gls, alza, rohlik, amazon, dhl, unknown
        tracking_url: URL of the tracking page (e.g., https://tracking.zasilkovna.cz/Z1234567890)
        tracking_number: Carrier tracking number (e.g., Z1234567890)
        order_source: E-shop that sent the shipment (e.g., "alza.cz", "rohlik.cz")
        order_number: Order number from the e-shop
        email_id: Gmail message ID of the notification email
        email_subject: Subject of the notification email
        expected_delivery: Expected delivery date/time
        delivery_location: Delivery address or pickup point name
        metadata: Additional JSON metadata (e.g., '{"items": ["phone case"]}')

    Returns:
        dict: Registered shipment details with assigned UUID

    Examples:
        tracking_register("zasilkovna", "https://tracking.zasilkovna.cz/Z1234567890",
                          tracking_number="Z1234567890", order_source="alza.cz")
        tracking_register("ppl", "https://www.ppl.cz/vyhledat-zasilku?shipmentId=12345678901",
                          order_source="czc.cz", order_number="OBJ-123456")
    """
    try:
        client = get_client()
        shipment = client.register_shipment(
            carrier=carrier,
            tracking_url=tracking_url,
            tracking_number=tracking_number,
            order_source=order_source,
            order_number=order_number,
            email_id=email_id,
            email_subject=email_subject,
            expected_delivery=expected_delivery,
            delivery_location=delivery_location,
            metadata=metadata,
        )
        return asdict(shipment)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Status check tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def tracking_status(shipment_id: str) -> dict:
    """
    Check live status of a shipment by scraping its tracking page.

    Fetches the tracking page, parses the current status, updates the
    database, and returns full shipment details with status history.

    Args:
        shipment_id: UUID of the registered shipment

    Returns:
        dict: Updated shipment details including:
              - shipment: current shipment data
              - history: chronological list of status changes

    Examples:
        tracking_status("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    """
    try:
        client = get_client()
        detail = await client.check_status(shipment_id)
        return {
            "shipment": asdict(detail.shipment),
            "history": [asdict(h) for h in detail.history],
        }
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
async def tracking_check_all() -> dict:
    """
    Check status of ALL active shipments (batch operation).

    Scrapes tracking pages for every active shipment and reports changes.
    Use this during morning briefing or periodic status checks.

    Returns:
        dict: Summary with:
              - changes: list of shipments whose status changed
              - total_checked: number of shipments checked
              - total_changes: number of status changes detected

    Examples:
        tracking_check_all()  # Check all active shipments
    """
    try:
        client = get_client()
        changes = await client.check_all_active()
        return {
            "changes": [asdict(c) for c in changes],
            "total_checked": len(client.list_shipments(active_only=True)),
            "total_changes": len(changes),
        }
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Read tools
# ---------------------------------------------------------------------------


@mcp.tool()
def tracking_get(shipment_id: str) -> dict:
    """
    Get shipment details from database (no live scrape).

    Returns stored shipment data and status history without making any
    network requests. Use tracking_status for a live update.

    Args:
        shipment_id: UUID of the shipment

    Returns:
        dict: Shipment details and status history

    Examples:
        tracking_get("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    """
    try:
        client = get_client()
        detail = client.get_shipment(shipment_id)
        return {
            "shipment": asdict(detail.shipment),
            "history": [asdict(h) for h in detail.history],
        }
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def tracking_list(
    active_only: bool = True,
    carrier: str | None = None,
    order_source: str | None = None,
) -> list[dict] | dict:
    """
    List tracked shipments with optional filters.

    Args:
        active_only: If True (default), only show active (not delivered/archived) shipments
        carrier: Filter by carrier (e.g., "zasilkovna", "ppl")
        order_source: Filter by e-shop (e.g., "alza.cz", "rohlik.cz")

    Returns:
        list: List of shipment summaries

    Examples:
        tracking_list()                          # All active shipments
        tracking_list(active_only=False)         # All shipments including delivered
        tracking_list(carrier="zasilkovna")      # Only Zásilkovna shipments
        tracking_list(order_source="alza.cz")    # Only Alza orders
    """
    try:
        client = get_client()
        shipments = client.list_shipments(
            active_only=active_only,
            carrier=carrier,
            order_source=order_source,
        )
        return [asdict(s) for s in shipments]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def tracking_archive(shipment_id: str) -> dict:
    """
    Archive a shipment (mark as inactive).

    Stops tracking the shipment. It won't appear in active lists
    or be checked during batch status updates.

    Args:
        shipment_id: UUID of the shipment to archive

    Returns:
        dict: Success status

    Examples:
        tracking_archive("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    """
    try:
        client = get_client()
        success = client.archive_shipment(shipment_id)
        if success:
            return {"success": True, "message": f"Shipment {shipment_id} archived"}
        return {"error": f"Shipment not found: {shipment_id}"}
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Email parsing tools
# ---------------------------------------------------------------------------


@mcp.tool()
def tracking_parse_email(
    email_body: str,
    email_subject: str,
    email_from: str,
    email_body_html: str | None = None,
) -> dict:
    """
    Parse a shipment notification email and extract tracking information.

    Analyses the email's sender, subject, and body to detect:
    - Which carrier is handling the shipment
    - The tracking URL and tracking number
    - The originating e-shop
    - Order number, expected delivery, delivery location

    Use the returned data to register the shipment via tracking_register.

    Args:
        email_body: Plain text email body (from gmail_read_email)
        email_subject: Email subject line
        email_from: Sender email address
        email_body_html: HTML email body (preferred for URL extraction)

    Returns:
        dict: Parsed tracking information including:
              - carrier: detected carrier name
              - tracking_url: tracking page URL (if found)
              - tracking_number: tracking number (if found)
              - order_source: e-shop name (if detected)
              - order_number: order number (if found)
              - confidence: detection confidence (0.0 - 1.0)

    Examples:
        tracking_parse_email(
            email_body="Vaše zásilka Z1234567890 byla odeslána...",
            email_subject="Zásilka odeslána",
            email_from="info@zasilkovna.cz",
            email_body_html="<a href='https://tracking.zasilkovna.cz/Z1234567890'>Sledovat</a>"
        )
    """
    try:
        client = get_client()
        result = client.parse_email(
            email_body=email_body,
            email_subject=email_subject,
            email_from=email_from,
            email_body_html=email_body_html,
        )
        return asdict(result)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def tracking_detect_carrier(
    url: str | None = None,
    email_from: str | None = None,
) -> dict:
    """
    Detect carrier from a tracking URL or email sender address.

    Useful for quick carrier identification without full email parsing.

    Args:
        url: Tracking page URL (e.g., "https://tracking.zasilkovna.cz/Z123")
        email_from: Email sender address (e.g., "info@ppl.cz")

    Returns:
        dict: Detection result with carrier name and method used

    Examples:
        tracking_detect_carrier(url="https://tracking.zasilkovna.cz/Z1234567890")
        tracking_detect_carrier(email_from="noreply@dpd.cz")
    """
    try:
        client = get_client()
        return client.detect_carrier(url=url, email_from=email_from)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
