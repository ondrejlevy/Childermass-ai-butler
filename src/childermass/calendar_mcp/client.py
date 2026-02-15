"""
Google Calendar API Client Wrapper

Provides a clean interface for Calendar API operations with integrated security.
All data stays local - we only call official Google APIs.

Uses get+update with etag atomicity (Google API recommendation over patch,
which consumes 3x quota).

Security features:
- Input validation on all public functions
- Rate limiting per account / operation
- Audit logging for write operations (create, update, delete)
- Error message sanitization to prevent credential leaks
"""

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from googleapiclient.discovery import Resource, build

from .auth import get_authenticated_credentials, list_authenticated_accounts
from .security import (
    audit_log,
    rate_limiter,
    sanitize_error_message,
    validate_attendees,
    validate_calendar_id,
    validate_color_id,
    validate_datetime,
    validate_event_description,
    validate_event_id,
    validate_event_summary,
    validate_location,
    validate_max_results,
    validate_quick_add_text,
    validate_recurrence,
    validate_search_query,
    validate_send_updates,
    validate_timezone,
)


logger = logging.getLogger(__name__)

# Module-level client cache - keyed by account email
_calendar_services: dict[str, Resource] = {}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class CalendarInfo:
    """Calendar metadata from calendarList."""

    id: str
    summary: str
    description: str = ""
    timezone: str = ""
    color_id: str = ""
    background_color: str = ""
    foreground_color: str = ""
    access_role: str = ""
    primary: bool = False
    selected: bool = True


@dataclass
class EventAttendee:
    """Event attendee."""

    email: str
    display_name: str = ""
    response_status: str = ""  # needsAction, declined, tentative, accepted
    optional: bool = False
    organizer: bool = False
    self_: bool = False


@dataclass
class CalendarEvent:
    """Calendar event."""

    id: str
    calendar_id: str
    summary: str = ""
    description: str = ""
    location: str = ""
    start: str = ""
    end: str = ""
    start_timezone: str = ""
    end_timezone: str = ""
    all_day: bool = False
    status: str = "confirmed"  # confirmed, tentative, cancelled
    html_link: str = ""
    hangout_link: str = ""
    meet_link: str = ""
    creator_email: str = ""
    organizer_email: str = ""
    attendees: list[EventAttendee] = field(default_factory=list)
    recurrence: list[str] = field(default_factory=list)
    recurring_event_id: str = ""
    color_id: str = ""
    reminders_use_default: bool = True
    reminders_overrides: list[dict] = field(default_factory=list)
    created: str = ""
    updated: str = ""
    event_type: str = "default"
    transparency: str = "opaque"
    visibility: str = "default"
    etag: str = ""


@dataclass
class FreeBusySlot:
    """A busy time slot from FreeBusy query."""

    calendar_id: str
    start: str
    end: str


# ---------------------------------------------------------------------------
# Service / account helpers
# ---------------------------------------------------------------------------


def get_calendar_service(account: str | None = None) -> Resource:
    """
    Get authenticated Calendar API service for a specific account.
    """
    global _calendar_services

    if account is None:
        accounts = list_authenticated_accounts()
        if not accounts:
            msg = (
                "No authenticated Calendar accounts found. Run:\n"
                "  python -m childermass.calendar_mcp.auth --account=your@email.com"
            )
            raise RuntimeError(msg)
        account = accounts[0]
        if account == "default":
            account = None

    cache_key = account or "default"
    if cache_key in _calendar_services:
        return _calendar_services[cache_key]

    creds = get_authenticated_credentials(account)
    service = build("calendar", "v3", credentials=creds)
    _calendar_services[cache_key] = service
    return service


def get_account_email(account: str | None = None) -> str:
    """Get the email address for an authenticated account."""
    service = get_calendar_service(account)
    # Use calendarList to get primary calendar which has the user email
    primary = service.calendarList().get(calendarId="primary").execute()
    return primary.get("id", "")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now_rfc3339() -> str:
    """Get current time in RFC3339 format."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S%z")


def _date_offset_rfc3339(days: int = 0) -> str:
    """Get RFC3339 datetime offset by N days from now."""
    dt = datetime.now(UTC) + timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%S%z")


def _today_start_rfc3339() -> str:
    """Get start of today in RFC3339 (UTC)."""
    now = datetime.now(UTC)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ")


def _today_end_rfc3339() -> str:
    """Get end of today in RFC3339 (UTC)."""
    now = datetime.now(UTC)
    end = now.replace(hour=23, minute=59, second=59, microsecond=0)
    return end.strftime("%Y-%m-%dT%H:%M:%SZ")


def _week_start_rfc3339() -> str:
    """Get start of current week (Monday) in RFC3339."""
    now = datetime.now(UTC)
    monday = now - timedelta(days=now.weekday())
    start = monday.replace(hour=0, minute=0, second=0, microsecond=0)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ")


def _week_end_rfc3339(weeks: int = 1) -> str:
    """Get end of Nth week from start of current week."""
    now = datetime.now(UTC)
    monday = now - timedelta(days=now.weekday())
    end = monday + timedelta(weeks=weeks)
    end = end.replace(hour=23, minute=59, second=59, microsecond=0)
    # Go to Sunday
    end = end - timedelta(days=1)
    return end.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_event(event: dict, calendar_id: str = "") -> CalendarEvent:
    """Parse Calendar API event resource to CalendarEvent object."""
    start = event.get("start", {})
    end = event.get("end", {})
    reminders = event.get("reminders", {})
    conference = event.get("conferenceData", {})

    # Determine if all-day
    all_day = "date" in start

    # Extract start/end times
    start_time = start.get("dateTime", start.get("date", ""))
    end_time = end.get("dateTime", end.get("date", ""))

    # Extract Meet link from conference data
    meet_link = ""
    entry_points = conference.get("entryPoints", [])
    for ep in entry_points:
        if ep.get("entryPointType") == "video":
            meet_link = ep.get("uri", "")
            break

    # Parse attendees
    attendees = []
    for att in event.get("attendees", []):
        attendees.append(
            EventAttendee(
                email=att.get("email", ""),
                display_name=att.get("displayName", ""),
                response_status=att.get("responseStatus", ""),
                optional=att.get("optional", False),
                organizer=att.get("organizer", False),
                self_=att.get("self", False),
            )
        )

    return CalendarEvent(
        id=event.get("id", ""),
        calendar_id=calendar_id,
        summary=event.get("summary", "(No title)"),
        description=event.get("description", ""),
        location=event.get("location", ""),
        start=start_time,
        end=end_time,
        start_timezone=start.get("timeZone", ""),
        end_timezone=end.get("timeZone", ""),
        all_day=all_day,
        status=event.get("status", "confirmed"),
        html_link=event.get("htmlLink", ""),
        hangout_link=event.get("hangoutLink", ""),
        meet_link=meet_link,
        creator_email=event.get("creator", {}).get("email", ""),
        organizer_email=event.get("organizer", {}).get("email", ""),
        attendees=attendees,
        recurrence=event.get("recurrence", []),
        recurring_event_id=event.get("recurringEventId", ""),
        color_id=event.get("colorId", ""),
        reminders_use_default=reminders.get("useDefault", True),
        reminders_overrides=reminders.get("overrides", []),
        created=event.get("created", ""),
        updated=event.get("updated", ""),
        event_type=event.get("eventType", "default"),
        transparency=event.get("transparency", "opaque"),
        visibility=event.get("visibility", "default"),
        etag=event.get("etag", ""),
    )


# ---------------------------------------------------------------------------
# Calendar operations
# ---------------------------------------------------------------------------


def list_calendars(account: str | None = None) -> list[CalendarInfo]:
    """
    List all calendars visible to the user.

    Returns:
        List of CalendarInfo objects
    """
    acct_key = account or "default"
    rate_limiter.check(acct_key, "list_calendars")

    service = get_calendar_service(account)
    calendars = []
    page_token = None

    while True:
        result = service.calendarList().list(pageToken=page_token).execute()

        for cal in result.get("items", []):
            calendars.append(
                CalendarInfo(
                    id=cal.get("id", ""),
                    summary=cal.get("summary", ""),
                    description=cal.get("description", ""),
                    timezone=cal.get("timeZone", ""),
                    color_id=cal.get("colorId", ""),
                    background_color=cal.get("backgroundColor", ""),
                    foreground_color=cal.get("foregroundColor", ""),
                    access_role=cal.get("accessRole", ""),
                    primary=cal.get("primary", False),
                    selected=cal.get("selected", True),
                )
            )

        page_token = result.get("nextPageToken")
        if not page_token:
            break

    return calendars


def get_calendar(
    calendar_id: str,
    account: str | None = None,
) -> CalendarInfo:
    """Get metadata for a single calendar."""
    calendar_id = validate_calendar_id(calendar_id)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "list_calendars")

    service = get_calendar_service(account)
    cal = service.calendarList().get(calendarId=calendar_id).execute()

    return CalendarInfo(
        id=cal.get("id", ""),
        summary=cal.get("summary", ""),
        description=cal.get("description", ""),
        timezone=cal.get("timeZone", ""),
        color_id=cal.get("colorId", ""),
        background_color=cal.get("backgroundColor", ""),
        foreground_color=cal.get("foregroundColor", ""),
        access_role=cal.get("accessRole", ""),
        primary=cal.get("primary", False),
        selected=cal.get("selected", True),
    )


# ---------------------------------------------------------------------------
# Event operations
# ---------------------------------------------------------------------------


def list_events(
    calendar_id: str = "primary",
    time_min: str = "",
    time_max: str = "",
    query: str = "",
    max_results: int = 250,
    single_events: bool = True,
    order_by: str = "startTime",
    account: str | None = None,
) -> list[CalendarEvent]:
    """
    List events from a specific calendar.

    Args:
        calendar_id: Calendar ID (default: "primary")
        time_min: Lower bound (RFC3339) – defaults to now
        time_max: Upper bound (RFC3339)
        query: Free-text search
        max_results: Max events to return (1-2500)
        single_events: Expand recurring events into instances
        order_by: "startTime" (requires singleEvents=True) or "updated"
        account: Account to use

    Returns:
        List of CalendarEvent objects
    """
    calendar_id = validate_calendar_id(calendar_id)
    if query:
        query = validate_search_query(query)
    max_results = validate_max_results(max_results)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "list_events")

    service = get_calendar_service(account)

    # Default time_min to now if not specified
    time_min = _now_rfc3339() if not time_min else validate_datetime(time_min)

    if time_max:
        time_max = validate_datetime(time_max)

    # If ordering by startTime, singleEvents must be True
    if order_by == "startTime":
        single_events = True

    kwargs: dict = {
        "calendarId": calendar_id,
        "timeMin": time_min,
        "singleEvents": single_events,
        "orderBy": order_by,
        "maxResults": max_results,
    }

    if time_max:
        kwargs["timeMax"] = time_max
    if query:
        kwargs["q"] = query

    events = []
    page_token = None

    while True:
        if page_token:
            kwargs["pageToken"] = page_token

        result = service.events().list(**kwargs).execute()

        for event in result.get("items", []):
            events.append(_parse_event(event, calendar_id))

        page_token = result.get("nextPageToken")
        if not page_token or len(events) >= max_results:
            break

    return events[:max_results]


def list_events_all_calendars(
    time_min: str = "",
    time_max: str = "",
    query: str = "",
    max_results_per_calendar: int = 100,
    owned_only: bool = True,
    account: str | None = None,
) -> list[CalendarEvent]:
    """
    List events from ALL user calendars, aggregated and sorted.

    Args:
        time_min: Lower bound (RFC3339) – defaults to now
        time_max: Upper bound (RFC3339)
        query: Free-text search
        max_results_per_calendar: Max events per calendar
        owned_only: If True (default), only include calendars where
            access_role is "owner" (excludes shared calendars from others)
        account: Account to use

    Returns:
        Sorted list of CalendarEvent from calendars
    """
    calendars = list_calendars(account)

    # Filter to owned calendars only if requested
    if owned_only:
        calendars = [cal for cal in calendars if cal.access_role == "owner"]

    all_events: list[CalendarEvent] = []

    for cal in calendars:
        try:
            events = list_events(
                calendar_id=cal.id,
                time_min=time_min,
                time_max=time_max,
                query=query,
                max_results=max_results_per_calendar,
                account=account,
            )
            all_events.extend(events)
        except Exception as e:
            logger.warning(
                "Failed to list events from calendar %s: %s",
                cal.summary,
                sanitize_error_message(e),
            )

    # Sort by start time
    all_events.sort(key=lambda e: e.start)

    return all_events


def get_event(
    calendar_id: str,
    event_id: str,
    account: str | None = None,
) -> CalendarEvent:
    """
    Get a single event by ID.

    Args:
        calendar_id: Calendar ID
        event_id: Event ID
        account: Account to use

    Returns:
        CalendarEvent with full details
    """
    calendar_id = validate_calendar_id(calendar_id)
    event_id = validate_event_id(event_id)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "get_event")

    service = get_calendar_service(account)
    event = service.events().get(calendarId=calendar_id, eventId=event_id).execute()

    return _parse_event(event, calendar_id)


def create_event(
    calendar_id: str = "primary",
    summary: str = "",
    start: str = "",
    end: str = "",
    description: str = "",
    location: str = "",
    attendees: str = "",
    timezone: str = "",
    recurrence: list[str] | None = None,
    reminders_minutes: list[int] | None = None,
    color_id: str = "",
    transparency: str = "opaque",
    visibility: str = "default",
    send_updates: str = "none",
    add_meet: bool = False,
    account: str | None = None,
) -> CalendarEvent:
    """
    Create a new calendar event.

    Args:
        calendar_id: Calendar ID (default: "primary")
        summary: Event title
        start: Start time (RFC3339 or yyyy-mm-dd for all-day)
        end: End time (RFC3339 or yyyy-mm-dd for all-day)
        description: Event description (can contain HTML)
        location: Event location
        attendees: Comma-separated attendee emails
        timezone: Timezone for start/end (IANA format)
        recurrence: List of RRULE strings (e.g., ["RRULE:FREQ=WEEKLY;COUNT=10"])
        reminders_minutes: List of reminder times in minutes before event
        color_id: Event color (1-11)
        transparency: "opaque" (busy) or "transparent" (available)
        visibility: "default", "public", "private", "confidential"
        send_updates: "all", "externalOnly", "none"
        add_meet: If True, create a Google Meet link
        account: Account to use

    Returns:
        Created CalendarEvent
    """
    # Validate inputs
    calendar_id = validate_calendar_id(calendar_id)
    summary = validate_event_summary(summary)
    start = validate_datetime(start)
    end = validate_datetime(end)
    description = validate_event_description(description)
    location = validate_location(location)
    send_updates = validate_send_updates(send_updates)

    attendee_list = []
    if attendees:
        attendee_list = validate_attendees(attendees)

    if timezone:
        timezone = validate_timezone(timezone)

    if recurrence:
        recurrence = validate_recurrence(recurrence)

    if color_id:
        color_id = validate_color_id(color_id)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "create")

    service = get_calendar_service(account)

    # Build event body
    is_all_day = len(start) == 10  # yyyy-mm-dd format

    event_body: dict = {
        "summary": summary,
    }

    if is_all_day:
        event_body["start"] = {"date": start}
        event_body["end"] = {"date": end}
    else:
        start_obj: dict = {"dateTime": start}
        end_obj: dict = {"dateTime": end}
        if timezone:
            start_obj["timeZone"] = timezone
            end_obj["timeZone"] = timezone
        event_body["start"] = start_obj
        event_body["end"] = end_obj

    if description:
        event_body["description"] = description
    if location:
        event_body["location"] = location
    if attendee_list:
        event_body["attendees"] = [{"email": email} for email in attendee_list]
    if recurrence:
        event_body["recurrence"] = recurrence
    if color_id:
        event_body["colorId"] = color_id
    if transparency != "opaque":
        event_body["transparency"] = transparency
    if visibility != "default":
        event_body["visibility"] = visibility

    # Reminders
    if reminders_minutes:
        event_body["reminders"] = {
            "useDefault": False,
            "overrides": [{"method": "popup", "minutes": m} for m in reminders_minutes],
        }

    # Google Meet
    conference_data_version = 0
    if add_meet:
        import uuid

        event_body["conferenceData"] = {
            "createRequest": {
                "requestId": str(uuid.uuid4()),
                "conferenceSolutionKey": {"type": "hangoutsMeet"},
            }
        }
        conference_data_version = 1

    # Create event
    created = (
        service.events()
        .insert(
            calendarId=calendar_id,
            body=event_body,
            sendUpdates=send_updates,
            conferenceDataVersion=conference_data_version,
        )
        .execute()
    )

    result = _parse_event(created, calendar_id)

    # Audit log
    audit_log(
        operation="create_event",
        account=acct_key,
        details={
            "calendar_id": calendar_id,
            "event_id": result.id,
            "summary": summary,
        },
    )

    return result


def update_event(
    calendar_id: str,
    event_id: str,
    summary: str | None = None,
    start: str | None = None,
    end: str | None = None,
    description: str | None = None,
    location: str | None = None,
    attendees: str | None = None,
    timezone: str | None = None,
    recurrence: list[str] | None = None,
    reminders_minutes: list[int] | None = None,
    color_id: str | None = None,
    transparency: str | None = None,
    visibility: str | None = None,
    send_updates: str = "none",
    account: str | None = None,
) -> CalendarEvent:
    """
    Update an existing event using get+update with etag atomicity.

    Only the provided (non-None) fields are changed; the rest are kept as-is.
    Uses etag to ensure no concurrent modifications.

    Args:
        calendar_id: Calendar ID
        event_id: Event ID to update
        summary: New title (None = keep existing)
        start: New start time (None = keep existing)
        end: New end time (None = keep existing)
        description: New description (None = keep existing)
        location: New location (None = keep existing)
        attendees: New attendee list – comma-separated (None = keep existing)
        timezone: New timezone (None = keep existing)
        recurrence: New recurrence rules (None = keep existing)
        reminders_minutes: New reminder times (None = keep existing)
        color_id: New color (None = keep existing)
        transparency: New transparency (None = keep existing)
        visibility: New visibility (None = keep existing)
        send_updates: Notification preference
        account: Account to use

    Returns:
        Updated CalendarEvent
    """
    calendar_id = validate_calendar_id(calendar_id)
    event_id = validate_event_id(event_id)
    send_updates = validate_send_updates(send_updates)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "update")

    service = get_calendar_service(account)

    # Step 1: GET current event (with etag)
    existing = service.events().get(calendarId=calendar_id, eventId=event_id).execute()

    # Step 2: Merge changes
    if summary is not None:
        existing["summary"] = validate_event_summary(summary)
    if description is not None:
        existing["description"] = validate_event_description(description)
    if location is not None:
        existing["location"] = validate_location(location)
    if transparency is not None:
        existing["transparency"] = transparency
    if visibility is not None:
        existing["visibility"] = visibility
    if color_id is not None:
        color_id = validate_color_id(color_id)
        if color_id:
            existing["colorId"] = color_id
        elif "colorId" in existing:
            del existing["colorId"]

    if start is not None:
        start = validate_datetime(start)
        tz = timezone or existing.get("start", {}).get("timeZone", "")
        if len(start) == 10:
            existing["start"] = {"date": start}
        else:
            start_obj: dict = {"dateTime": start}
            if tz:
                start_obj["timeZone"] = tz
            existing["start"] = start_obj

    if end is not None:
        end = validate_datetime(end)
        tz = timezone or existing.get("end", {}).get("timeZone", "")
        if len(end) == 10:
            existing["end"] = {"date": end}
        else:
            end_obj: dict = {"dateTime": end}
            if tz:
                end_obj["timeZone"] = tz
            existing["end"] = end_obj

    if timezone is not None and start is None and end is None:
        # Update timezone on existing start/end
        timezone = validate_timezone(timezone)
        if "dateTime" in existing.get("start", {}):
            existing["start"]["timeZone"] = timezone
        if "dateTime" in existing.get("end", {}):
            existing["end"]["timeZone"] = timezone

    if attendees is not None:
        attendee_list = validate_attendees(attendees)
        existing["attendees"] = [{"email": email} for email in attendee_list]

    if recurrence is not None:
        existing["recurrence"] = validate_recurrence(recurrence)

    if reminders_minutes is not None:
        existing["reminders"] = {
            "useDefault": False,
            "overrides": [{"method": "popup", "minutes": m} for m in reminders_minutes],
        }

    # Step 3: UPDATE with etag (If-Match header for atomicity)
    updated = (
        service.events()
        .update(
            calendarId=calendar_id,
            eventId=event_id,
            body=existing,
            sendUpdates=send_updates,
        )
        .execute()
    )

    result = _parse_event(updated, calendar_id)

    audit_log(
        operation="update_event",
        account=acct_key,
        details={
            "calendar_id": calendar_id,
            "event_id": event_id,
            "summary": result.summary,
        },
    )

    return result


def delete_event(
    calendar_id: str,
    event_id: str,
    send_updates: str = "none",
    account: str | None = None,
) -> dict:
    """
    Delete a calendar event.

    Args:
        calendar_id: Calendar ID
        event_id: Event ID to delete
        send_updates: "all", "externalOnly", "none"
        account: Account to use

    Returns:
        Success dict
    """
    calendar_id = validate_calendar_id(calendar_id)
    event_id = validate_event_id(event_id)
    send_updates = validate_send_updates(send_updates)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "delete")

    service = get_calendar_service(account)

    service.events().delete(
        calendarId=calendar_id,
        eventId=event_id,
        sendUpdates=send_updates,
    ).execute()

    audit_log(
        operation="delete_event",
        account=acct_key,
        details={
            "calendar_id": calendar_id,
            "event_id": event_id,
        },
    )

    return {"success": True, "event_id": event_id}


def quick_add_event(
    calendar_id: str = "primary",
    text: str = "",
    send_updates: str = "none",
    account: str | None = None,
) -> CalendarEvent:
    """
    Create an event from natural language text.

    Google Calendar parses the text to extract date, time, and title.
    Examples:
        "Meeting with John tomorrow at 3pm"
        "Dentist appointment Friday 2-3pm"
        "Weekly team standup every Monday at 9am"

    Args:
        calendar_id: Calendar ID (default: "primary")
        text: Natural language event description
        send_updates: "all", "externalOnly", "none"
        account: Account to use

    Returns:
        Created CalendarEvent
    """
    calendar_id = validate_calendar_id(calendar_id)
    text = validate_quick_add_text(text)
    send_updates = validate_send_updates(send_updates)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "quick_add")

    service = get_calendar_service(account)

    created = (
        service.events()
        .quickAdd(
            calendarId=calendar_id,
            text=text,
            sendUpdates=send_updates,
        )
        .execute()
    )

    result = _parse_event(created, calendar_id)

    audit_log(
        operation="quick_add_event",
        account=acct_key,
        details={
            "calendar_id": calendar_id,
            "event_id": result.id,
            "text": text,
        },
    )

    return result


def move_event(
    calendar_id: str,
    event_id: str,
    destination_calendar_id: str,
    send_updates: str = "none",
    account: str | None = None,
) -> CalendarEvent:
    """
    Move an event to another calendar.

    Only 'default' events can be moved (not birthday, focusTime, etc.).

    Args:
        calendar_id: Source calendar ID
        event_id: Event ID
        destination_calendar_id: Target calendar ID
        send_updates: Notification preference
        account: Account to use

    Returns:
        Updated CalendarEvent in new calendar
    """
    calendar_id = validate_calendar_id(calendar_id)
    event_id = validate_event_id(event_id)
    destination_calendar_id = validate_calendar_id(destination_calendar_id)
    send_updates = validate_send_updates(send_updates)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "move")

    service = get_calendar_service(account)

    moved = (
        service.events()
        .move(
            calendarId=calendar_id,
            eventId=event_id,
            destination=destination_calendar_id,
            sendUpdates=send_updates,
        )
        .execute()
    )

    result = _parse_event(moved, destination_calendar_id)

    audit_log(
        operation="move_event",
        account=acct_key,
        details={
            "event_id": event_id,
            "from_calendar": calendar_id,
            "to_calendar": destination_calendar_id,
        },
    )

    return result


def list_recurring_instances(
    calendar_id: str,
    event_id: str,
    time_min: str = "",
    time_max: str = "",
    max_results: int = 50,
    account: str | None = None,
) -> list[CalendarEvent]:
    """
    List instances of a recurring event.

    Args:
        calendar_id: Calendar ID
        event_id: Recurring event ID
        time_min: Lower bound (RFC3339) – defaults to now
        time_max: Upper bound (RFC3339)
        max_results: Max instances to return
        account: Account to use

    Returns:
        List of CalendarEvent instances
    """
    calendar_id = validate_calendar_id(calendar_id)
    event_id = validate_event_id(event_id)
    max_results = validate_max_results(max_results)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "instances")

    service = get_calendar_service(account)

    kwargs: dict = {
        "calendarId": calendar_id,
        "eventId": event_id,
        "maxResults": max_results,
    }

    time_min = _now_rfc3339() if not time_min else validate_datetime(time_min)
    kwargs["timeMin"] = time_min

    if time_max:
        kwargs["timeMax"] = validate_datetime(time_max)

    instances = []
    page_token = None

    while True:
        if page_token:
            kwargs["pageToken"] = page_token

        result = service.events().instances(**kwargs).execute()

        for event in result.get("items", []):
            instances.append(_parse_event(event, calendar_id))

        page_token = result.get("nextPageToken")
        if not page_token or len(instances) >= max_results:
            break

    return instances[:max_results]


def query_free_busy(
    calendar_ids: list[str],
    time_min: str,
    time_max: str,
    account: str | None = None,
) -> dict:
    """
    Query free/busy information for calendars.

    Args:
        calendar_ids: List of calendar IDs to check
        time_min: Start of range (RFC3339)
        time_max: End of range (RFC3339)
        account: Account to use

    Returns:
        Dict with:
            - calendars: dict of calendar_id -> list of FreeBusySlot
            - errors: dict of calendar_id -> error message
    """
    validated_ids = [validate_calendar_id(cid) for cid in calendar_ids]
    time_min = validate_datetime(time_min)
    time_max = validate_datetime(time_max)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "freebusy")

    service = get_calendar_service(account)

    body = {
        "timeMin": time_min,
        "timeMax": time_max,
        "items": [{"id": cid} for cid in validated_ids],
    }

    result = service.freebusy().query(body=body).execute()

    calendars_busy: dict[str, list[dict]] = {}
    errors: dict[str, str] = {}

    for cal_id, cal_data in result.get("calendars", {}).items():
        if cal_data.get("errors"):
            errors[cal_id] = str(cal_data["errors"])
        else:
            slots = []
            for busy in cal_data.get("busy", []):
                slots.append(
                    {
                        "calendar_id": cal_id,
                        "start": busy.get("start", ""),
                        "end": busy.get("end", ""),
                    }
                )
            calendars_busy[cal_id] = slots

    return {"calendars": calendars_busy, "errors": errors}


# ---------------------------------------------------------------------------
# Convenience aggregations (for AI assistant)
# ---------------------------------------------------------------------------


def get_today_agenda(
    owned_only: bool = True,
    account: str | None = None,
) -> list[CalendarEvent]:
    """
    Get today's events sorted chronologically.

    This is the most common query for an AI assistant.

    Args:
        owned_only: If True (default), only include events from owned
            calendars (excludes shared calendars from others)
        account: Account to use

    Returns:
        Sorted list of today's events
    """
    return list_events_all_calendars(
        time_min=_today_start_rfc3339(),
        time_max=_today_end_rfc3339(),
        owned_only=owned_only,
        account=account,
    )


def get_week_agenda(
    weeks: int = 1,
    owned_only: bool = True,
    account: str | None = None,
) -> list[CalendarEvent]:
    """
    Get this week's (or next N weeks') events.

    Args:
        weeks: Number of weeks to include (1 = current week only)
        owned_only: If True (default), only include events from owned
            calendars (excludes shared calendars from others)
        account: Account to use

    Returns:
        Sorted list of events for the week(s)
    """
    return list_events_all_calendars(
        time_min=_week_start_rfc3339(),
        time_max=_week_end_rfc3339(weeks),
        owned_only=owned_only,
        account=account,
    )
