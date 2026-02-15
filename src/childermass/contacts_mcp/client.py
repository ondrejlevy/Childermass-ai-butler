"""
Google People API Client Wrapper

Provides a clean interface for Google People API operations with
integrated security. All data stays local - we only call official
Google APIs.

Security features:
- Input validation on all public functions
- Rate limiting per account / operation
- Audit logging for write operations (create, update, delete)
- Error message sanitization to prevent credential leaks

API reference: https://developers.google.com/people/api/rest
"""

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

from googleapiclient.discovery import Resource, build

from .auth import get_authenticated_credentials, list_authenticated_accounts
from .security import (
    DEFAULT_PERSON_FIELDS,
    SecurityError,
    audit_log,
    rate_limiter,
    sanitize_error_message,
    validate_address,
    validate_birthday,
    validate_contact_name,
    validate_email,
    validate_etag,
    validate_group_name,
    validate_group_resource_name,
    validate_job_title,
    validate_max_results,
    validate_notes,
    validate_organization,
    validate_phone_number,
    validate_resource_name,
    validate_search_query,
    validate_url,
)


logger = logging.getLogger(__name__)

# Module-level client cache - keyed by account email
_people_services: dict[str, Resource] = {}

# Whether search warmup has been done per account
_search_warmed_up: set[str] = set()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ContactEmail:
    """Contact email address."""

    value: str
    type: str = ""  # home, work, other


@dataclass
class ContactPhone:
    """Contact phone number."""

    value: str
    type: str = ""  # home, work, mobile, etc.


@dataclass
class ContactAddress:
    """Contact address."""

    formatted_value: str = ""
    type: str = ""  # home, work, other
    street_address: str = ""
    city: str = ""
    region: str = ""
    postal_code: str = ""
    country: str = ""


@dataclass
class ContactOrganization:
    """Contact organization/work details."""

    name: str = ""
    title: str = ""
    department: str = ""


@dataclass
class Contact:
    """A contact person from Google People API."""

    resource_name: str  # "people/c1234567890"
    etag: str = ""
    display_name: str = ""
    given_name: str = ""
    family_name: str = ""
    nickname: str = ""
    emails: list[ContactEmail] = field(default_factory=list)
    phones: list[ContactPhone] = field(default_factory=list)
    addresses: list[ContactAddress] = field(default_factory=list)
    organizations: list[ContactOrganization] = field(default_factory=list)
    birthday: str = ""  # "YYYY-MM-DD" or "MM-DD"
    notes: str = ""  # biography
    photo_url: str = ""
    groups: list[str] = field(default_factory=list)  # group resourceNames
    urls: list[str] = field(default_factory=list)
    relations: list[dict] = field(default_factory=list)  # [{person, type}]
    occupation: str = ""
    events: list[dict] = field(default_factory=list)  # [{date, type}]


@dataclass
class ContactGroup:
    """A Google Contacts group."""

    resource_name: str  # "contactGroups/abc123"
    name: str = ""
    member_count: int = 0
    group_type: str = ""  # USER_CONTACT_GROUP or SYSTEM_CONTACT_GROUP


# ---------------------------------------------------------------------------
# Service / account helpers
# ---------------------------------------------------------------------------


def get_people_service(account: str | None = None) -> Resource:
    """
    Get authenticated People API service for a specific account.
    """
    global _people_services

    if account is None:
        accounts = list_authenticated_accounts()
        if not accounts:
            msg = (
                "No authenticated Contacts accounts found. Run:\n"
                "  python -m childermass.contacts_mcp.auth "
                "--account=your@email.com"
            )
            raise RuntimeError(msg)
        account = accounts[0]
        if account == "default":
            account = None

    cache_key = account or "default"
    if cache_key in _people_services:
        return _people_services[cache_key]

    creds = get_authenticated_credentials(account)
    service = build("people", "v1", credentials=creds)
    _people_services[cache_key] = service
    return service


# ---------------------------------------------------------------------------
# Internal helpers – parsing People API responses
# ---------------------------------------------------------------------------


def _parse_person(person: dict) -> Contact:
    """Parse a People API Person resource into a Contact dataclass."""
    # Names
    names = person.get("names", [])
    display_name = ""
    given_name = ""
    family_name = ""
    if names:
        primary = _get_primary(names) or names[0]
        display_name = primary.get("displayName", "")
        given_name = primary.get("givenName", "")
        family_name = primary.get("familyName", "")

    # Nicknames
    nicknames = person.get("nicknames", [])
    nickname = ""
    if nicknames:
        primary_nick = _get_primary(nicknames) or nicknames[0]
        nickname = primary_nick.get("value", "")

    # Emails
    emails = []
    for e in person.get("emailAddresses", []):
        emails.append(
            ContactEmail(
                value=e.get("value", ""),
                type=e.get("type", ""),
            )
        )

    # Phones
    phones = []
    for p in person.get("phoneNumbers", []):
        phones.append(
            ContactPhone(
                value=p.get("value", ""),
                type=p.get("type", ""),
            )
        )

    # Addresses
    addresses = []
    for a in person.get("addresses", []):
        addresses.append(
            ContactAddress(
                formatted_value=a.get("formattedValue", ""),
                type=a.get("type", ""),
                street_address=a.get("streetAddress", ""),
                city=a.get("city", ""),
                region=a.get("region", ""),
                postal_code=a.get("postalCode", ""),
                country=a.get("country", ""),
            )
        )

    # Organizations
    organizations = []
    for o in person.get("organizations", []):
        organizations.append(
            ContactOrganization(
                name=o.get("name", ""),
                title=o.get("title", ""),
                department=o.get("department", ""),
            )
        )

    # Birthday
    birthday = ""
    birthdays = person.get("birthdays", [])
    if birthdays:
        bday = _get_primary(birthdays) or birthdays[0]
        date_obj = bday.get("date", {})
        year = date_obj.get("year", 0)
        month = date_obj.get("month", 0)
        day = date_obj.get("day", 0)
        if year and month and day:
            birthday = f"{year:04d}-{month:02d}-{day:02d}"
        elif month and day:
            birthday = f"{month:02d}-{day:02d}"

    # Notes / biography
    notes = ""
    biographies = person.get("biographies", [])
    if biographies:
        bio = _get_primary(biographies) or biographies[0]
        notes = bio.get("value", "")

    # Photo
    photo_url = ""
    photos = person.get("photos", [])
    if photos:
        photo = _get_primary(photos) or photos[0]
        if not photo.get("default", False):
            photo_url = photo.get("url", "")

    # Extract Groups (memberships)
    groups = []
    for m in person.get("memberships", []):
        cgm = m.get("contactGroupMembership", {})
        rn = cgm.get("contactGroupResourceName", "")
        if rn:
            groups.append(rn)

    # URLs
    urls = []
    for u in person.get("urls", []):
        val = u.get("value", "")
        if val:
            urls.append(val)

    # Relations
    relations = []
    for r in person.get("relations", []):
        relations.append(
            {
                "person": r.get("person", ""),
                "type": r.get("type", ""),
            }
        )

    # Occupation
    occupation = ""
    occupations = person.get("occupations", [])
    if occupations:
        occ = _get_primary(occupations) or occupations[0]
        occupation = occ.get("value", "")

    # Events (anniversaries etc.)
    events = []
    for ev in person.get("events", []):
        date_obj = ev.get("date", {})
        year = date_obj.get("year", 0)
        month = date_obj.get("month", 0)
        day = date_obj.get("day", 0)
        date_str = ""
        if year and month and day:
            date_str = f"{year:04d}-{month:02d}-{day:02d}"
        elif month and day:
            date_str = f"{month:02d}-{day:02d}"
        events.append(
            {
                "date": date_str,
                "type": ev.get("type", ""),
            }
        )

    # Etag
    etag = person.get("etag", "")

    return Contact(
        resource_name=person.get("resourceName", ""),
        etag=etag,
        display_name=display_name,
        given_name=given_name,
        family_name=family_name,
        nickname=nickname,
        emails=emails,
        phones=phones,
        addresses=addresses,
        organizations=organizations,
        birthday=birthday,
        notes=notes,
        photo_url=photo_url,
        groups=groups,
        urls=urls,
        relations=relations,
        occupation=occupation,
        events=events,
    )


def _get_primary(items: list[dict]) -> dict | None:
    """Return the primary item from a list of People API field values."""
    for item in items:
        metadata = item.get("metadata", {})
        if metadata.get("primary", False):
            return item
    return None


def _parse_contact_group(group: dict) -> ContactGroup:
    """Parse a ContactGroup resource."""
    return ContactGroup(
        resource_name=group.get("resourceName", ""),
        name=group.get("name", "") or group.get("formattedName", ""),
        member_count=group.get("memberCount", 0),
        group_type=group.get("groupType", ""),
    )


def _build_person_body(
    *,
    given_name: str = "",
    family_name: str = "",
    emails: list[tuple[str, str]] | None = None,
    phones: list[tuple[str, str]] | None = None,
    organization: str = "",
    job_title: str = "",
    birthday: str = "",
    notes: str = "",
    addresses: list[tuple[str, str]] | None = None,
    urls: list[str] | None = None,
) -> dict:
    """Build a Person resource body for create/update API calls."""
    body: dict = {}

    # Names (singleton)
    if given_name or family_name:
        body["names"] = [
            {
                "givenName": given_name,
                "familyName": family_name,
            }
        ]

    # Email addresses
    if emails:
        body["emailAddresses"] = [{"value": addr, "type": typ or "other"} for addr, typ in emails]

    # Phone numbers
    if phones:
        body["phoneNumbers"] = [{"value": num, "type": typ or "other"} for num, typ in phones]

    # Organization
    if organization or job_title:
        org: dict = {}
        if organization:
            org["name"] = organization
        if job_title:
            org["title"] = job_title
        body["organizations"] = [org]

    # Add Birthday (singleton)
    if birthday:
        date_obj: dict = {}
        parts = birthday.split("-")
        if len(parts) == 3:
            date_obj = {
                "year": int(parts[0]),
                "month": int(parts[1]),
                "day": int(parts[2]),
            }
        elif len(parts) == 2:
            date_obj = {
                "month": int(parts[0]),
                "day": int(parts[1]),
            }
        if date_obj:
            body["birthdays"] = [{"date": date_obj}]

    # Add Notes / biography (singleton)
    if notes:
        body["biographies"] = [{"value": notes, "contentType": "TEXT_PLAIN"}]

    # Addresses
    if addresses:
        body["addresses"] = [
            {"formattedValue": addr, "type": typ or "other"} for addr, typ in addresses
        ]

    # URLs
    if urls:
        body["urls"] = [{"value": u} for u in urls]

    return body


# ---------------------------------------------------------------------------
# Search warmup
# ---------------------------------------------------------------------------


def _ensure_search_warmup(account: str | None = None) -> None:
    """
    Send a warmup request for searchContacts if not already done.

    Google People API requires a warmup request with empty query
    before the search cache is populated.
    """
    acct_key = account or "default"
    if acct_key in _search_warmed_up:
        return

    try:
        service = get_people_service(account)
        service.people().searchContacts(
            query="",
            readMask="names",
            pageSize=1,
        ).execute()
    except Exception:
        pass  # Warmup failure is not critical

    _search_warmed_up.add(acct_key)


# ---------------------------------------------------------------------------
# Read operations
# ---------------------------------------------------------------------------


def search_contacts(
    query: str,
    max_results: int = 10,
    account: str | None = None,
) -> list[Contact]:
    """
    Search contacts by name, email, phone, or organization.

    Uses people.searchContacts – matches prefix phrases on contact fields.

    Args:
        query: Search query (e.g. "John", "john@", "Acme Corp")
        max_results: Max results (1-30, default 10)
        account: Optional account email
    """
    query = validate_search_query(query)
    if not query:
        msg = "Search query is required"
        raise SecurityError(msg)
    max_results = validate_max_results(max_results, limit=30)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "search")

    # Warmup if needed
    _ensure_search_warmup(account)

    try:
        service = get_people_service(account)
        result = (
            service.people()
            .searchContacts(
                query=query,
                readMask=DEFAULT_PERSON_FIELDS,
                pageSize=max_results,
            )
            .execute()
        )

        contacts = []
        for item in result.get("results", []):
            person = item.get("person", {})
            if person:
                contacts.append(_parse_person(person))

        audit_log(
            "search_contacts",
            acct_key,
            {
                "query": query,
                "count": len(contacts),
            },
        )
        return contacts

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def list_contacts(
    max_results: int = 100,
    sort_order: str = "LAST_MODIFIED_DESCENDING",
    account: str | None = None,
) -> list[Contact]:
    """
    List all contacts with pagination.

    Args:
        max_results: Maximum contacts to return (1-1000, default 100)
        sort_order: LAST_MODIFIED_ASCENDING, LAST_MODIFIED_DESCENDING,
                    FIRST_NAME_ASCENDING, LAST_NAME_ASCENDING
        account: Optional account email
    """
    max_results = validate_max_results(max_results, limit=1000)

    valid_sorts = {
        "LAST_MODIFIED_ASCENDING",
        "LAST_MODIFIED_DESCENDING",
        "FIRST_NAME_ASCENDING",
        "LAST_NAME_ASCENDING",
    }
    if sort_order not in valid_sorts:
        msg = f"Invalid sort order: {sort_order}. Must be one of: {', '.join(sorted(valid_sorts))}"
        raise SecurityError(msg)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "list")

    try:
        service = get_people_service(account)
        contacts: list[Contact] = []
        page_token = None

        while len(contacts) < max_results:
            page_size = min(100, max_results - len(contacts))
            params: dict = {
                "resourceName": "people/me",
                "personFields": DEFAULT_PERSON_FIELDS,
                "pageSize": page_size,
                "sortOrder": sort_order,
            }
            if page_token:
                params["pageToken"] = page_token

            result = service.people().connections().list(**params).execute()

            for person in result.get("connections", []):
                contacts.append(_parse_person(person))

            page_token = result.get("nextPageToken")
            if not page_token:
                break

        audit_log("list_contacts", acct_key, {"count": len(contacts)})
        return contacts

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def get_contact(
    resource_name: str,
    account: str | None = None,
) -> Contact:
    """
    Get full details of a single contact.

    Args:
        resource_name: Contact resource name (e.g. "people/c1234567890")
        account: Optional account email
    """
    resource_name = validate_resource_name(resource_name)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "get")

    try:
        service = get_people_service(account)
        person = (
            service.people()
            .get(
                resourceName=resource_name,
                personFields=DEFAULT_PERSON_FIELDS,
            )
            .execute()
        )

        audit_log(
            "get_contact",
            acct_key,
            {
                "resource_name": resource_name,
            },
        )
        return _parse_person(person)

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def get_my_profile(account: str | None = None) -> Contact:
    """
    Get the authenticated user's own profile.
    """
    acct_key = account or "default"
    rate_limiter.check(acct_key, "get")

    try:
        service = get_people_service(account)
        person = (
            service.people()
            .get(
                resourceName="people/me",
                personFields=DEFAULT_PERSON_FIELDS,
            )
            .execute()
        )

        audit_log("get_my_profile", acct_key)
        return _parse_person(person)

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def find_contacts_by_email(
    email: str,
    account: str | None = None,
) -> list[Contact]:
    """
    Find contacts that have a specific email address.

    Convenience wrapper around search_contacts that filters results
    by exact email match.
    """
    email = validate_email(email)
    results = search_contacts(query=email, max_results=10, account=account)

    # Filter to exact email match
    matched = []
    for contact in results:
        for ce in contact.emails:
            if ce.value.lower() == email.lower():
                matched.append(contact)
                break

    return matched


def find_contacts_by_organization(
    organization: str,
    max_results: int = 10,
    account: str | None = None,
) -> list[Contact]:
    """
    Find contacts by organization name.

    Searches for contacts whose organization matches the query.
    """
    organization = validate_organization(organization)
    if not organization:
        msg = "Organization name is required"
        raise SecurityError(msg)

    results = search_contacts(
        query=organization,
        max_results=max_results,
        account=account,
    )

    # Filter to those with matching organization
    matched = []
    for contact in results:
        for org in contact.organizations:
            if organization.lower() in org.name.lower():
                matched.append(contact)
                break

    return matched


def find_birthday_upcoming(
    days: int = 30,
    account: str | None = None,
) -> list[Contact]:
    """
    Find contacts with birthdays in the next N days.

    Args:
        days: Number of days ahead to look (default: 30)
        account: Optional account email

    Returns:
        List of contacts with upcoming birthdays, sorted by date.
    """
    if days < 1 or days > 365:
        msg = "days must be between 1 and 365"
        raise SecurityError(msg)

    # Get all contacts with birthday info
    all_contacts = list_contacts(max_results=1000, account=account)

    today = datetime.now(UTC).date()
    upcoming: list[tuple[int, Contact]] = []  # (days_until, contact)

    for contact in all_contacts:
        if not contact.birthday:
            continue

        parts = contact.birthday.split("-")
        try:
            if len(parts) == 3:
                month, day = int(parts[1]), int(parts[2])
            elif len(parts) == 2:
                month, day = int(parts[0]), int(parts[1])
            else:
                continue
        except (ValueError, IndexError):
            continue

        # Calculate days until birthday this year
        try:
            bday_this_year = today.replace(month=month, day=day)
        except ValueError:
            continue  # Invalid date (e.g. Feb 29 in non-leap year)

        if bday_this_year < today:
            # Birthday already passed this year – check next year
            try:
                bday_this_year = bday_this_year.replace(year=today.year + 1)
            except ValueError:
                continue

        days_until = (bday_this_year - today).days
        if 0 <= days_until <= days:
            upcoming.append((days_until, contact))

    # Sort by days until birthday
    upcoming.sort(key=lambda x: x[0])

    audit_log(
        "find_birthday_upcoming",
        account or "default",
        {
            "days": days,
            "count": len(upcoming),
        },
    )

    return [contact for _, contact in upcoming]


# ---------------------------------------------------------------------------
# Write operations
# ---------------------------------------------------------------------------


def create_contact(
    given_name: str,
    family_name: str = "",
    emails: list[tuple[str, str]] | None = None,
    phones: list[tuple[str, str]] | None = None,
    organization: str = "",
    job_title: str = "",
    birthday: str = "",
    notes: str = "",
    addresses: list[tuple[str, str]] | None = None,
    urls: list[str] | None = None,
    account: str | None = None,
) -> Contact:
    """
    Create a new contact.

    Args:
        given_name: First name (required)
        family_name: Last name
        emails: List of (email, type) tuples. Type: home/work/other
        phones: List of (phone, type) tuples. Type: home/work/mobile/other
        organization: Company name
        job_title: Job title
        birthday: Birthday in YYYY-MM-DD or MM-DD format
        notes: Notes / biography
        addresses: List of (address, type) tuples. Type: home/work/other
        urls: List of URL strings
        account: Optional account email

    Returns:
        Created Contact with resource_name for future reference.
    """
    # Validate inputs
    given_name = validate_contact_name(given_name)
    if family_name:
        family_name = validate_contact_name(family_name)
    if emails:
        emails = [(validate_email(e), t) for e, t in emails]
    if phones:
        phones = [(validate_phone_number(p), t) for p, t in phones]
    if organization:
        organization = validate_organization(organization)
    if job_title:
        job_title = validate_job_title(job_title)
    if birthday:
        birthday = validate_birthday(birthday)
    if notes:
        notes = validate_notes(notes)
    if addresses:
        addresses = [(validate_address(a), t) for a, t in addresses]
    if urls:
        urls = [validate_url(u) for u in urls]

    acct_key = account or "default"
    rate_limiter.check(acct_key, "create")

    try:
        service = get_people_service(account)

        body = _build_person_body(
            given_name=given_name,
            family_name=family_name,
            emails=emails,
            phones=phones,
            organization=organization,
            job_title=job_title,
            birthday=birthday,
            notes=notes,
            addresses=addresses,
            urls=urls,
        )

        person = (
            service.people()
            .createContact(
                body=body,
                personFields=DEFAULT_PERSON_FIELDS,
            )
            .execute()
        )

        contact = _parse_person(person)

        audit_log(
            "create_contact",
            acct_key,
            {
                "resource_name": contact.resource_name,
                "name": f"{given_name} {family_name}".strip(),
            },
        )

        return contact

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def update_contact(
    resource_name: str,
    etag: str,
    given_name: str = "",
    family_name: str = "",
    emails: list[tuple[str, str]] | None = None,
    phones: list[tuple[str, str]] | None = None,
    organization: str = "",
    job_title: str = "",
    birthday: str = "",
    notes: str = "",
    addresses: list[tuple[str, str]] | None = None,
    urls: list[str] | None = None,
    account: str | None = None,
) -> Contact:
    """
    Update an existing contact.

    IMPORTANT: Requires etag from a previous get_contact call for
    optimistic concurrency control. All specified fields are REPLACED.

    Args:
        resource_name: Contact resource name (e.g. "people/c1234567890")
        etag: Etag from get_contact (required for conflict detection)
        given_name: First name
        family_name: Last name
        emails: List of (email, type) tuples to SET (replaces existing)
        phones: List of (phone, type) tuples to SET (replaces existing)
        organization: Company name
        job_title: Job title
        birthday: Birthday in YYYY-MM-DD or MM-DD format
        notes: Notes / biography
        addresses: List of (address, type) tuples to SET
        urls: List of URL strings to SET
        account: Optional account email

    Returns:
        Updated Contact.
    """
    resource_name = validate_resource_name(resource_name)
    etag = validate_etag(etag)

    # Validate provided inputs
    if given_name:
        given_name = validate_contact_name(given_name)
    if family_name:
        family_name = validate_contact_name(family_name)
    if emails:
        emails = [(validate_email(e), t) for e, t in emails]
    if phones:
        phones = [(validate_phone_number(p), t) for p, t in phones]
    if organization:
        organization = validate_organization(organization)
    if job_title:
        job_title = validate_job_title(job_title)
    if birthday:
        birthday = validate_birthday(birthday)
    if notes:
        notes = validate_notes(notes)
    if addresses:
        addresses = [(validate_address(a), t) for a, t in addresses]
    if urls:
        urls = [validate_url(u) for u in urls]

    acct_key = account or "default"
    rate_limiter.check(acct_key, "update")

    try:
        service = get_people_service(account)

        body = _build_person_body(
            given_name=given_name,
            family_name=family_name,
            emails=emails,
            phones=phones,
            organization=organization,
            job_title=job_title,
            birthday=birthday,
            notes=notes,
            addresses=addresses,
            urls=urls,
        )

        # Set etag and resourceName on the body
        body["etag"] = etag
        body["resourceName"] = resource_name

        # Build updatePersonFields mask from provided fields
        update_fields = []
        if given_name or family_name:
            update_fields.append("names")
        if emails is not None:
            update_fields.append("emailAddresses")
        if phones is not None:
            update_fields.append("phoneNumbers")
        if organization or job_title:
            update_fields.append("organizations")
        if birthday:
            update_fields.append("birthdays")
        if notes:
            update_fields.append("biographies")
        if addresses is not None:
            update_fields.append("addresses")
        if urls is not None:
            update_fields.append("urls")

        if not update_fields:
            msg = "At least one field must be specified for update"
            raise SecurityError(msg)

        person = (
            service.people()
            .updateContact(
                resourceName=resource_name,
                body=body,
                updatePersonFields=",".join(update_fields),
                personFields=DEFAULT_PERSON_FIELDS,
            )
            .execute()
        )

        contact = _parse_person(person)

        audit_log(
            "update_contact",
            acct_key,
            {
                "resource_name": resource_name,
                "updated_fields": update_fields,
            },
        )

        return contact

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def delete_contact(
    resource_name: str,
    account: str | None = None,
) -> dict:
    """
    Delete a contact.

    WARNING: This permanently deletes the contact. Cannot be undone.

    Args:
        resource_name: Contact resource name (e.g. "people/c1234567890")
        account: Optional account email

    Returns:
        Success confirmation.
    """
    resource_name = validate_resource_name(resource_name)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "delete")

    try:
        service = get_people_service(account)
        service.people().deleteContact(
            resourceName=resource_name,
        ).execute()

        audit_log(
            "delete_contact",
            acct_key,
            {
                "resource_name": resource_name,
            },
        )

        return {
            "success": True,
            "deleted": resource_name,
        }

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


# ---------------------------------------------------------------------------
# Contact group operations
# ---------------------------------------------------------------------------


def list_contact_groups(
    account: str | None = None,
) -> list[ContactGroup]:
    """
    List all contact groups.

    Returns both system groups (myContacts, starred, etc.) and
    user-defined groups.
    """
    acct_key = account or "default"
    rate_limiter.check(acct_key, "list_groups")

    try:
        service = get_people_service(account)
        groups: list[ContactGroup] = []
        page_token = None

        while True:
            params: dict = {"pageSize": 100}
            if page_token:
                params["pageToken"] = page_token

            result = service.contactGroups().list(**params).execute()

            for group in result.get("contactGroups", []):
                groups.append(_parse_contact_group(group))

            page_token = result.get("nextPageToken")
            if not page_token:
                break

        audit_log(
            "list_contact_groups",
            acct_key,
            {
                "count": len(groups),
            },
        )
        return groups

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def get_contact_group(
    resource_name: str,
    max_members: int = 100,
    account: str | None = None,
) -> ContactGroup:
    """
    Get a contact group with member details.

    Args:
        resource_name: Group resource name (e.g. "contactGroups/abc123")
        max_members: Max members to return in response (default 100)
        account: Optional account email
    """
    resource_name = validate_group_resource_name(resource_name)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "get_group")

    try:
        service = get_people_service(account)
        group = (
            service.contactGroups()
            .get(
                resourceName=resource_name,
                maxMembers=max_members,
            )
            .execute()
        )

        audit_log(
            "get_contact_group",
            acct_key,
            {
                "resource_name": resource_name,
            },
        )
        return _parse_contact_group(group)

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def create_contact_group(
    name: str,
    account: str | None = None,
) -> ContactGroup:
    """
    Create a new contact group.

    Args:
        name: Group name (must be unique)
        account: Optional account email
    """
    name = validate_group_name(name)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "create_group")

    try:
        service = get_people_service(account)
        group = (
            service.contactGroups()
            .create(
                body={"contactGroup": {"name": name}},
            )
            .execute()
        )

        audit_log(
            "create_contact_group",
            acct_key,
            {
                "name": name,
                "resource_name": group.get("resourceName", ""),
            },
        )
        return _parse_contact_group(group)

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def add_to_group(
    group_resource_name: str,
    contact_resource_names: list[str],
    account: str | None = None,
) -> dict:
    """
    Add contacts to a contact group.

    Args:
        group_resource_name: Group resource name
        contact_resource_names: List of contact resource names to add
        account: Optional account email
    """
    group_resource_name = validate_group_resource_name(group_resource_name)
    contact_resource_names = [validate_resource_name(rn) for rn in contact_resource_names]

    acct_key = account or "default"
    rate_limiter.check(acct_key, "modify_group_members")

    try:
        service = get_people_service(account)
        service.contactGroups().members().modify(
            resourceName=group_resource_name,
            body={
                "resourceNamesToAdd": contact_resource_names,
            },
        ).execute()

        audit_log(
            "add_to_group",
            acct_key,
            {
                "group": group_resource_name,
                "contacts_added": len(contact_resource_names),
            },
        )

        return {
            "success": True,
            "group": group_resource_name,
            "added": contact_resource_names,
        }

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def remove_from_group(
    group_resource_name: str,
    contact_resource_names: list[str],
    account: str | None = None,
) -> dict:
    """
    Remove contacts from a contact group.

    Args:
        group_resource_name: Group resource name
        contact_resource_names: List of contact resource names to remove
        account: Optional account email
    """
    group_resource_name = validate_group_resource_name(group_resource_name)
    contact_resource_names = [validate_resource_name(rn) for rn in contact_resource_names]

    acct_key = account or "default"
    rate_limiter.check(acct_key, "modify_group_members")

    try:
        service = get_people_service(account)
        service.contactGroups().members().modify(
            resourceName=group_resource_name,
            body={
                "resourceNamesToRemove": contact_resource_names,
            },
        ).execute()

        audit_log(
            "remove_from_group",
            acct_key,
            {
                "group": group_resource_name,
                "contacts_removed": len(contact_resource_names),
            },
        )

        return {
            "success": True,
            "group": group_resource_name,
            "removed": contact_resource_names,
        }

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None
