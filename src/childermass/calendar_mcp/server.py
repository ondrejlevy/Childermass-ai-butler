"""
Childermass Google Calendar MCP Server

Custom Google Calendar MCP server for Claude Code / OpenCode.
All data stays local - we only call official Google APIs.

Security: All tool responses go through error sanitization so that
OAuth tokens, credentials, or internal paths are never leaked to the LLM.

Run with: python -m childermass.calendar_mcp.server
"""

from dataclasses import asdict

from mcp.server.fastmcp import FastMCP

from . import client
from .security import SecurityError, sanitize_error_message


# Create FastMCP server
mcp = FastMCP("childermass-calendar")


# ---------------------------------------------------------------------------
# Helper: safe tool wrapper
# ---------------------------------------------------------------------------


def _safe_call(func, *args, **kwargs):
    """Execute a client call with error sanitization."""
    try:
        return func(*args, **kwargs)
    except SecurityError as e:
        # Security errors are user-facing (validation failures) – pass as-is
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Calendar listing tools
# ---------------------------------------------------------------------------


@mcp.tool()
def calendar_list_calendars() -> list[dict] | dict:
    """
    List all calendars available in the user's Google account.

    Returns:
        List of calendars with id, name, description, timezone, color, and access role.
        The primary calendar is marked with primary=True.
    """
    try:
        calendars = client.list_calendars()
        return [asdict(cal) for cal in calendars]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Event read tools
# ---------------------------------------------------------------------------


@mcp.tool()
def calendar_list_events(
    calendar_id: str = "primary",
    time_min: str = "",
    time_max: str = "",
    query: str = "",
    max_results: int = 50,
) -> list[dict] | dict:
    """
    List events from a specific calendar.

    Args:
        calendar_id: Calendar ID (use "primary" for the main calendar,
            or get IDs from calendar_list_calendars)
        time_min: Start of time range in RFC3339 format
            (e.g., "2024-01-15T00:00:00Z"). Defaults to now.
        time_max: End of time range in RFC3339 format
            (e.g., "2024-01-31T23:59:59Z"). Optional.
        query: Free-text search across event summary, description,
            location, and attendees. Optional.
        max_results: Maximum number of events to return (default: 50, max: 2500)

    Returns:
        List of events sorted by start time, with full details including
        title, time, location, attendees, Meet link, and recurrence info.
    """
    try:
        events = client.list_events(
            calendar_id=calendar_id,
            time_min=time_min or "",
            time_max=time_max or "",
            query=query or "",
            max_results=max_results,
        )
        return [asdict(event) for event in events]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def calendar_list_all_events(
    time_min: str = "",
    time_max: str = "",
    query: str = "",
    max_results_per_calendar: int = 100,
    owned_only: bool = True,
) -> list[dict] | dict:
    """
    List events from all calendars, aggregated and sorted.

    Args:
        time_min: Start of time range in RFC3339 format
            (e.g., "2024-01-15T00:00:00Z"). Defaults to now.
        time_max: End of time range in RFC3339 format.
        query: Free-text search across event summary, description, location, attendees.
        max_results_per_calendar: Maximum events per calendar (default: 100)
        owned_only: If True (default), only include events from owned calendars
            (excludes shared calendars from other users). Set to False to include
            all visible calendars.

    Returns:
        Sorted list of events from all (or owned-only) calendars.
    """
    try:
        events = client.list_events_all_calendars(
            time_min=time_min or "",
            time_max=time_max or "",
            query=query or "",
            max_results_per_calendar=max_results_per_calendar,
            owned_only=owned_only,
        )
        return [asdict(event) for event in events]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def calendar_get_event(
    calendar_id: str,
    event_id: str,
) -> dict:
    """
    Get full details of a specific event.

    Args:
        calendar_id: Calendar ID (e.g., "primary")
        event_id: Event ID (from calendar_list_events)

    Returns:
        Full event details including ETag, attendees, recurrence, reminders,
        attachments, and conference data.
    """
    try:
        event = client.get_event(
            calendar_id=calendar_id,
            event_id=event_id,
        )
        return asdict(event)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def calendar_search_events(
    query: str,
    time_min: str = "",
    time_max: str = "",
    max_results: int = 50,
) -> list[dict] | dict:
    """
    Search events across all calendars using free-text query.

    Searches event summary, description, location, and attendee emails/names.

    Args:
        query: Search text (e.g., "team meeting", "dentist", "john@example.com")
        time_min: Start of time range (RFC3339). Optional.
        time_max: End of time range (RFC3339). Optional.
        max_results: Maximum results to return (default: 50)

    Returns:
        List of matching events from all calendars.
    """
    try:
        events = client.list_events_all_calendars(
            query=query,
            time_min=time_min or "",
            time_max=time_max or "",
            max_results_per_calendar=max_results,
        )
        return [asdict(event) for event in events]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Event write tools
# ---------------------------------------------------------------------------


@mcp.tool()
def calendar_create_event(
    calendar_id: str = "primary",
    summary: str = "",
    start: str = "",
    end: str = "",
    description: str = "",
    location: str = "",
    attendees: str = "",
    timezone: str = "",
    recurrence: str = "",
    add_meet: bool = False,
    send_updates: str = "none",
) -> dict:
    """
    Create a new calendar event.

    Args:
        calendar_id: Calendar to create event in (default: "primary")
        summary: Event title (required)
        start: Start time in RFC3339 format (e.g., "2024-01-15T14:00:00Z")
            or date for all-day events ("2024-01-15")
        end: End time in RFC3339 format or date
        description: Event description / notes
        location: Event location (physical or virtual)
        attendees: Comma-separated email addresses (e.g., "user@example.com, other@example.com")
        timezone: Timezone for the event (e.g., "America/New_York").
            If not specified, uses calendar's default timezone.
        recurrence: Recurrence rule in RRULE format (e.g., "RRULE:FREQ=WEEKLY;BYDAY=MO,WE,FR")
        add_meet: If True, add a Google Meet conference link (default: False)
        send_updates: Send email updates to attendees. Options: "all", "externalOnly", "none" (default)

    Returns:
        Created event with id, link, and all details.
    """
    try:
        event = client.create_event(
            calendar_id=calendar_id,
            summary=summary,
            start=start,
            end=end,
            description=description or "",
            location=location or "",
            attendees=attendees or "",
            timezone=timezone or "",
            recurrence=[recurrence] if recurrence else None,
            add_meet=add_meet,
            send_updates=send_updates,
        )
        return asdict(event)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def calendar_update_event(
    calendar_id: str,
    event_id: str,
    summary: str = "",
    start: str = "",
    end: str = "",
    description: str = "",
    location: str = "",
    attendees: str = "",
    timezone: str = "",
    send_updates: str = "none",
) -> dict:
    """
    Update an existing event.

    Uses atomic get+update with ETag to prevent conflicts. Only specify
    the fields you want to change – unspecified fields remain unchanged.

    Args:
        calendar_id: Calendar ID
        event_id: Event ID to update
        summary: New title. Empty = keep existing.
        start: New start time (RFC3339). Empty = keep existing.
        end: New end time (RFC3339). Empty = keep existing.
        description: New description. Empty = keep existing.
        location: New location. Empty = keep existing.
        attendees: New attendee list (comma-separated). Empty = keep existing.
        timezone: New timezone. Empty = keep existing.
        send_updates: Send email updates. Options: "all", "externalOnly", "none" (default)

    Returns:
        Updated event with all details.
    """
    try:
        event = client.update_event(
            calendar_id=calendar_id,
            event_id=event_id,
            summary=summary or None,
            start=start or None,
            end=end or None,
            description=description or None,
            location=location or None,
            attendees=attendees or None,
            timezone=timezone or None,
            send_updates=send_updates,
        )
        return asdict(event)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def calendar_delete_event(
    calendar_id: str,
    event_id: str,
    send_updates: str = "none",
) -> dict:
    """
    Delete an event permanently.

    WARNING: This cannot be undone. The event is permanently removed.

    Args:
        calendar_id: Calendar ID
        event_id: Event ID to delete
        send_updates: Send cancellation emails to attendees.
            Options: "all", "externalOnly", "none" (default)

    Returns:
        Success confirmation.
    """
    try:
        return client.delete_event(
            calendar_id=calendar_id,
            event_id=event_id,
            send_updates=send_updates,
        )
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def calendar_quick_add(
    text: str,
    calendar_id: str = "primary",
) -> dict:
    """
    Create an event using natural language quick-add.

    Google Calendar interprets the text and creates an event.
    Very convenient for fast event creation.

    Args:
        text: Natural language event description.
            Examples:
            - "Team meeting tomorrow at 2pm"
            - "Lunch with John on Friday at noon"
            - "Dentist appointment next Monday 9am-10am at Main Street Dental"
        calendar_id: Calendar to create event in (default: "primary")

    Returns:
        Created event with parsed details.
    """
    try:
        event = client.quick_add_event(
            text=text,
            calendar_id=calendar_id,
        )
        return asdict(event)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def calendar_move_event(
    source_calendar_id: str,
    event_id: str,
    destination_calendar_id: str,
    send_updates: str = "none",
) -> dict:
    """
    Move an event from one calendar to another.

    Args:
        source_calendar_id: Current calendar ID
        event_id: Event ID to move
        destination_calendar_id: Target calendar ID
        send_updates: Send email updates. Options: "all", "externalOnly", "none" (default)

    Returns:
        Moved event with updated calendar_id.
    """
    try:
        event = client.move_event(
            calendar_id=source_calendar_id,
            event_id=event_id,
            destination_calendar_id=destination_calendar_id,
            send_updates=send_updates,
        )
        return asdict(event)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Advanced / utility tools
# ---------------------------------------------------------------------------


@mcp.tool()
def calendar_check_availability(
    emails: str,
    time_min: str,
    time_max: str,
    timezone: str = "UTC",
) -> dict:
    """
    Check free/busy status for one or more calendars.

    Useful for finding meeting availability or checking if someone is free.

    Args:
        emails: Comma-separated email addresses or calendar IDs to check
            (e.g., "user@example.com, other@example.com")
        time_min: Start of time range (RFC3339, e.g., "2024-01-15T09:00:00Z")
        time_max: End of time range (RFC3339, e.g., "2024-01-15T17:00:00Z")
        timezone: Timezone for interpretation (default: "UTC")

    Returns:
        Dict with busy periods for each calendar.
    """
    try:
        calendar_ids = [e.strip() for e in emails.split(",") if e.strip()]
        return client.query_free_busy(
            calendar_ids=calendar_ids,
            time_min=time_min,
            time_max=time_max,
        )
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def calendar_list_recurring(
    calendar_id: str,
    event_id: str,
    time_min: str = "",
    time_max: str = "",
    max_results: int = 50,
) -> list[dict] | dict:
    """
    List individual instances of a recurring event.

    Args:
        calendar_id: Calendar ID
        event_id: Recurring event ID (the master event)
        time_min: Start of time range (RFC3339). Optional.
        time_max: End of time range (RFC3339). Optional.
        max_results: Maximum instances to return (default: 50)

    Returns:
        List of event instances with specific dates/times.
    """
    try:
        instances = client.list_recurring_instances(
            calendar_id=calendar_id,
            event_id=event_id,
            time_min=time_min or "",
            time_max=time_max or "",
            max_results=max_results,
        )
        return [asdict(inst) for inst in instances]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Convenience / agenda tools (most used by AI assistant)
# ---------------------------------------------------------------------------


@mcp.tool()
def calendar_get_today_agenda(owned_only: bool = True) -> list[dict] | dict:
    """
    Get today's complete agenda.

    This is the most common calendar query. Returns all events for today
    sorted chronologically.

    Args:
        owned_only: If True (default), only return events from calendars
            you own (excludes shared calendars from other users).
            Set to False to include all visible calendars.

    Returns:
        Sorted list of today's events with titles, times, locations,
        attendees, and calendar info. Empty list if no events today.
    """
    try:
        events = client.get_today_agenda(owned_only=owned_only)
        return [asdict(event) for event in events]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def calendar_get_week_agenda(
    weeks: int = 1,
    owned_only: bool = True,
) -> list[dict] | dict:
    """
    Get this week's (or upcoming weeks') agenda.

    Perfect for weekly planning and overview of upcoming commitments.

    Args:
        weeks: Number of weeks to include (default: 1 = current week,
            2 = current + next week, etc.)
        owned_only: If True (default), only return events from calendars
            you own (excludes shared calendars from other users).
            Set to False to include all visible calendars.

    Returns:
        Sorted list of events for the specified period.
        Events include day-of-week info for easy grouping.
    """
    try:
        events = client.get_week_agenda(weeks=weeks, owned_only=owned_only)
        return [asdict(event) for event in events]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Server entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
