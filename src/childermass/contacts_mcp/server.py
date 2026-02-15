"""
Childermass Google Contacts MCP Server

Custom Google Contacts MCP server for Claude Code / OpenCode.
All data stays local - we only call official Google APIs (People API).

Security: All tool responses go through error sanitization so that
OAuth tokens, credentials, or internal paths are never leaked to the LLM.

Run with: python -m childermass.contacts_mcp.server
"""

from dataclasses import asdict

from mcp.server.fastmcp import FastMCP

from . import client
from .security import SecurityError, sanitize_error_message

# Create FastMCP server
mcp = FastMCP("childermass-contacts")


# ---------------------------------------------------------------------------
# Helper: safe tool wrapper
# ---------------------------------------------------------------------------


def _safe_call(func, *args, **kwargs):
    """Execute a client call with error sanitization."""
    try:
        return func(*args, **kwargs)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Search & Read tools
# ---------------------------------------------------------------------------


@mcp.tool()
def contacts_search(
    query: str,
    max_results: int = 10,
) -> list[dict] | dict:
    """
    Search contacts by name, email, phone, or organization.

    Uses prefix matching – e.g. "Joh" matches "John", "nam" matches
    "Name". Searches across names, nicknames, email addresses, phone
    numbers, and organizations.

    IMPORTANT: This is the primary tool for finding contacts. Use it
    before contacts_get to find the right resourceName.

    Args:
        query: Search text (e.g. "John", "john@example.com", "Acme")
        max_results: Maximum results to return (1-30, default: 10)

    Returns:
        List of matching contacts with names, emails, phones,
        organizations, and resourceName for further operations.
    """
    try:
        contacts = client.search_contacts(
            query=query,
            max_results=max_results,
        )
        return [asdict(c) for c in contacts]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def contacts_list(
    max_results: int = 100,
    sort_order: str = "LAST_MODIFIED_DESCENDING",
) -> list[dict] | dict:
    """
    List all contacts with optional sorting.

    Args:
        max_results: Maximum contacts to return (1-1000, default: 100)
        sort_order: Sort order. Options:
            - "LAST_MODIFIED_DESCENDING" (default, newest changes first)
            - "LAST_MODIFIED_ASCENDING" (oldest changes first)
            - "FIRST_NAME_ASCENDING" (alphabetical by first name)
            - "LAST_NAME_ASCENDING" (alphabetical by last name)

    Returns:
        List of contacts with full details.
    """
    try:
        contacts = client.list_contacts(
            max_results=max_results,
            sort_order=sort_order,
        )
        return [asdict(c) for c in contacts]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def contacts_get(resource_name: str) -> dict:
    """
    Get full details of a specific contact.

    Args:
        resource_name: Contact resource name (e.g. "people/c1234567890").
            Get this from contacts_search or contacts_list.

    Returns:
        Full contact details including name, emails, phones, addresses,
        organization, birthday, notes, photo URL, groups, and etag
        (needed for updates).
    """
    try:
        contact = client.get_contact(resource_name=resource_name)
        return asdict(contact)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def contacts_find_by_email(email: str) -> list[dict] | dict:
    """
    Find contacts by exact email address.

    Args:
        email: Email address to search for (e.g. "john@example.com")

    Returns:
        List of contacts that have this email address.
    """
    try:
        contacts = client.find_contacts_by_email(email=email)
        return [asdict(c) for c in contacts]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def contacts_find_by_organization(
    organization: str,
    max_results: int = 10,
) -> list[dict] | dict:
    """
    Find contacts by organization/company name.

    Useful to answer "who works at X?" or "find people from company Y".

    Args:
        organization: Organization name (e.g. "Google", "Acme Corp")
        max_results: Maximum results to return (default: 10)

    Returns:
        List of contacts at the specified organization.
    """
    try:
        contacts = client.find_contacts_by_organization(
            organization=organization,
            max_results=max_results,
        )
        return [asdict(c) for c in contacts]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def contacts_birthday_upcoming(days: int = 30) -> list[dict] | dict:
    """
    Find contacts with birthdays in the next N days.

    Great for planning birthday greetings, gifts, or reminders.

    Args:
        days: Number of days to look ahead (1-365, default: 30)

    Returns:
        List of contacts with upcoming birthdays, sorted by date.
        Each contact includes birthday field.
    """
    try:
        contacts = client.find_birthday_upcoming(days=days)
        return [asdict(c) for c in contacts]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def contacts_get_my_profile() -> dict:
    """
    Get the authenticated user's own profile information.

    Returns:
        User's profile with name, emails, phone numbers, etc.
    """
    try:
        contact = client.get_my_profile()
        return asdict(contact)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Write tools
# ---------------------------------------------------------------------------


@mcp.tool()
def contacts_create(
    given_name: str,
    family_name: str = "",
    email: str = "",
    email_type: str = "other",
    phone: str = "",
    phone_type: str = "mobile",
    organization: str = "",
    job_title: str = "",
    birthday: str = "",
    notes: str = "",
    address: str = "",
    address_type: str = "home",
    url: str = "",
) -> dict:
    """
    Create a new contact.

    Args:
        given_name: First name (required)
        family_name: Last name
        email: Email address
        email_type: Email type: "home", "work", or "other" (default: "other")
        phone: Phone number (e.g. "+420 123 456 789")
        phone_type: Phone type: "home", "work", "mobile", "other"
            (default: "mobile")
        organization: Company/organization name
        job_title: Job title at the organization
        birthday: Birthday in YYYY-MM-DD or MM-DD format (e.g. "1990-03-15")
        notes: Notes about the contact
        address: Street address (free-form text)
        address_type: Address type: "home", "work", "other" (default: "home")
        url: Website URL

    Returns:
        Created contact with resourceName (save this for future operations).
    """
    try:
        emails = [(email, email_type)] if email else None
        phones = [(phone, phone_type)] if phone else None
        addresses = [(address, address_type)] if address else None
        urls = [url] if url else None

        contact = client.create_contact(
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
        return asdict(contact)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def contacts_update(
    resource_name: str,
    etag: str,
    given_name: str = "",
    family_name: str = "",
    email: str = "",
    email_type: str = "other",
    phone: str = "",
    phone_type: str = "mobile",
    organization: str = "",
    job_title: str = "",
    birthday: str = "",
    notes: str = "",
    address: str = "",
    address_type: str = "home",
    url: str = "",
) -> dict:
    """
    Update an existing contact.

    IMPORTANT: You must first call contacts_get to obtain the current etag.
    Only specify fields you want to REPLACE. Unspecified fields remain unchanged.

    Args:
        resource_name: Contact resource name (e.g. "people/c1234567890")
        etag: Current etag from contacts_get (required for conflict detection)
        given_name: New first name (leave empty to keep current)
        family_name: New last name (leave empty to keep current)
        email: New email address (replaces all existing emails)
        email_type: Email type
        phone: New phone number (replaces all existing phones)
        phone_type: Phone type
        organization: New organization
        job_title: New job title
        birthday: New birthday (YYYY-MM-DD or MM-DD)
        notes: New notes
        address: New address (replaces all existing)
        address_type: Address type
        url: New URL (replaces all existing)

    Returns:
        Updated contact with new etag.
    """
    try:
        emails = [(email, email_type)] if email else None
        phones = [(phone, phone_type)] if phone else None
        addresses = [(address, address_type)] if address else None
        urls = [url] if url else None

        contact = client.update_contact(
            resource_name=resource_name,
            etag=etag,
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
        return asdict(contact)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def contacts_delete(resource_name: str) -> dict:
    """
    Delete a contact permanently.

    WARNING: This cannot be undone. The contact will be permanently removed.

    Args:
        resource_name: Contact resource name (e.g. "people/c1234567890")

    Returns:
        Success confirmation.
    """
    try:
        return client.delete_contact(resource_name=resource_name)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Contact group tools
# ---------------------------------------------------------------------------


@mcp.tool()
def contacts_list_groups() -> list[dict] | dict:
    """
    List all contact groups (labels).

    Returns both system groups (My Contacts, Starred) and
    user-created groups.

    Returns:
        List of groups with resourceName, name, member count, and type.
    """
    try:
        groups = client.list_contact_groups()
        return [asdict(g) for g in groups]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def contacts_get_group(resource_name: str) -> dict:
    """
    Get details of a contact group.

    Args:
        resource_name: Group resource name (e.g. "contactGroups/abc123")

    Returns:
        Group details with name, member count, and type.
    """
    try:
        group = client.get_contact_group(resource_name=resource_name)
        return asdict(group)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def contacts_create_group(name: str) -> dict:
    """
    Create a new contact group (label).

    Args:
        name: Group name (must be unique among user groups)

    Returns:
        Created group with resourceName.
    """
    try:
        group = client.create_contact_group(name=name)
        return asdict(group)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def contacts_add_to_group(
    group_resource_name: str,
    contact_resource_names: str,
) -> dict:
    """
    Add contacts to a contact group.

    Args:
        group_resource_name: Group resource name
            (e.g. "contactGroups/abc123")
        contact_resource_names: Comma-separated contact resource names
            (e.g. "people/c111,people/c222")

    Returns:
        Success confirmation with list of added contacts.
    """
    try:
        names = [
            n.strip()
            for n in contact_resource_names.split(",")
            if n.strip()
        ]
        return client.add_to_group(
            group_resource_name=group_resource_name,
            contact_resource_names=names,
        )
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def contacts_remove_from_group(
    group_resource_name: str,
    contact_resource_names: str,
) -> dict:
    """
    Remove contacts from a contact group.

    Args:
        group_resource_name: Group resource name
            (e.g. "contactGroups/abc123")
        contact_resource_names: Comma-separated contact resource names
            (e.g. "people/c111,people/c222")

    Returns:
        Success confirmation with list of removed contacts.
    """
    try:
        names = [
            n.strip()
            for n in contact_resource_names.split(",")
            if n.strip()
        ]
        return client.remove_from_group(
            group_resource_name=group_resource_name,
            contact_resource_names=names,
        )
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
