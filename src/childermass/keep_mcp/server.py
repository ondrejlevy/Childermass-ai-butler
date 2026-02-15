"""
Childermass Google Keep MCP Server

Custom Google Keep MCP server for Claude Code / OpenCode.
All data stays local - we only call Google APIs via gkeepapi.

Security: All tool responses go through error sanitization so that
master tokens, credentials, or internal paths are never leaked to the LLM.

Run with: python -m childermass.keep_mcp.server
"""

from dataclasses import asdict

from mcp.server.fastmcp import FastMCP

from . import client
from .security import SecurityError, sanitize_error_message


# Create FastMCP server
mcp = FastMCP("childermass-keep")


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
# Note CRUD tools
# ---------------------------------------------------------------------------


@mcp.tool()
def keep_create_note(
    title: str,
    content: str = "",
    note_type: str = "text",
    color: str = "",
    pinned: bool = False,
    labels: str = "",
    items: str = "",
) -> dict:
    """
    Create a new Google Keep note or list.

    Args:
        title: Note title
        content: Text content (for text notes) or ignored if items provided
        note_type: Type of note - "text" for regular note, "list" for checklist
        color: Note color (white, red, orange, yellow, green, teal, blue, cerulean, purple, pink, brown, gray)
        pinned: Whether to pin the note to the top
        labels: Comma-separated label names to apply (created if they don't exist)
        items: For list notes: comma-separated items, or newline-separated items.
            Prefix with [x] to mark as checked. Example: "Milk, Bread, [x] Eggs"

    Returns:
        Created note with id, title, type, content/items, and metadata
    """
    try:
        # Parse labels
        label_list = (
            [label.strip() for label in labels.split(",") if label.strip()] if labels else None
        )

        # Parse items for list notes
        item_tuples = None
        if items and note_type == "list":
            item_tuples = []
            # Support both comma and newline separation
            raw_items = items.replace("\n", ",").split(",")
            for item in raw_items:
                item = item.strip()
                if not item:
                    continue
                checked = item.startswith(("[x]", "[X]"))
                if checked:
                    item = item[3:].strip()
                item_tuples.append((item, checked))

        result = client.create_note(
            title=title,
            content=content,
            note_type=note_type,
            color=color or "",
            pinned=pinned,
            labels=label_list,
            items=item_tuples,
        )
        return asdict(result)

    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_list_notes(
    query: str = "",
    pinned: bool | None = None,
    archived: bool | None = None,
    labels: str = "",
    colors: str = "",
    max_results: int = 50,
) -> list[dict] | dict:
    """
    List Google Keep notes with optional filtering.

    Args:
        query: Text search query to filter notes
        pinned: Filter by pinned state (True/False, or omit for all)
        archived: Filter by archived state (True/False, or omit for all)
        labels: Comma-separated label names to filter by
        colors: Comma-separated color names to filter by
        max_results: Maximum number of notes to return (default: 50)

    Returns:
        List of notes with id, title, type, color, pinned, archived, labels
    """
    try:
        label_list = (
            [label.strip() for label in labels.split(",") if label.strip()] if labels else None
        )
        color_list = [c.strip() for c in colors.split(",") if c.strip()] if colors else None

        notes = client.list_notes(
            query=query,
            pinned=pinned,
            archived=archived,
            labels=label_list,
            colors=color_list,
            max_results=max_results,
        )
        return [asdict(n) for n in notes]

    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_get_note(note_id: str) -> dict:
    """
    Get full details of a Google Keep note.

    Args:
        note_id: The note ID (from keep_list_notes)

    Returns:
        Full note with title, content/items, color, labels, collaborators, timestamps
    """
    try:
        result = client.get_note(note_id)
        return asdict(result)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_search_notes(query: str, max_results: int = 50) -> list[dict] | dict:
    """
    Search Google Keep notes by text content.

    Args:
        query: Search query string
        max_results: Maximum results to return (default: 50)

    Returns:
        List of matching notes
    """
    try:
        notes = client.search_notes(query=query, max_results=max_results)
        return [asdict(n) for n in notes]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_update_note(
    note_id: str,
    title: str = "",
    text: str = "",
    color: str = "",
    pinned: bool | None = None,
    archived: bool | None = None,
) -> dict:
    """
    Update a Google Keep note's attributes.

    Args:
        note_id: The note ID to update
        title: New title (empty = no change)
        text: New text content for text notes (empty = no change)
        color: New color (empty = no change)
        pinned: Set pinned state (True/False, or omit for no change)
        archived: Set archived state (True/False, or omit for no change)

    Returns:
        Updated note details
    """
    try:
        result = client.update_note(
            note_id=note_id,
            title=title or None,
            text=text or None,
            color=color or None,
            pinned=pinned,
            archived=archived,
        )
        return asdict(result)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_delete_note(note_id: str) -> dict:
    """
    Delete (trash) a Google Keep note.

    Args:
        note_id: The note ID to delete

    Returns:
        Success status
    """
    try:
        return client.delete_note(note_id)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# List item tools
# ---------------------------------------------------------------------------


@mcp.tool()
def keep_list_items(note_id: str) -> list[dict] | dict:
    """
    Get all items from a Google Keep list/checklist.

    Args:
        note_id: The list note ID

    Returns:
        List of items with id, text, checked status, and children
    """
    try:
        items = client.get_list_items(note_id)
        return [asdict(item) for item in items]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_add_list_item(
    note_id: str,
    text: str,
    checked: bool = False,
    position: str = "bottom",
) -> dict:
    """
    Add an item to a Google Keep list/checklist.

    Args:
        note_id: The list note ID
        text: Item text
        checked: Whether the item is checked (default: False)
        position: Where to add - "top" or "bottom" (default: "bottom")

    Returns:
        Created item with id, text, checked status
    """
    try:
        result = client.add_list_item(
            note_id=note_id,
            text=text,
            checked=checked,
            position=position,
        )
        return asdict(result)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_update_list_item(
    note_id: str,
    item_id: str,
    text: str = "",
    checked: bool | None = None,
) -> dict:
    """
    Update a list item's text or checked state.

    Args:
        note_id: The list note ID
        item_id: The item ID (from keep_list_items)
        text: New text (empty = no change)
        checked: New checked state (True/False, or omit for no change)

    Returns:
        Updated item details
    """
    try:
        result = client.update_list_item(
            note_id=note_id,
            item_id=item_id,
            text=text or None,
            checked=checked,
        )
        return asdict(result)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_check_item(note_id: str, item_id: str) -> dict:
    """
    Mark a list item as done/checked.

    Args:
        note_id: The list note ID
        item_id: The item ID to check

    Returns:
        Updated item details
    """
    try:
        result = client.check_list_item(note_id, item_id)
        return asdict(result)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_uncheck_item(note_id: str, item_id: str) -> dict:
    """
    Mark a list item as not done/unchecked.

    Args:
        note_id: The list note ID
        item_id: The item ID to uncheck

    Returns:
        Updated item details
    """
    try:
        result = client.uncheck_list_item(note_id, item_id)
        return asdict(result)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_delete_list_item(note_id: str, item_id: str) -> dict:
    """
    Delete an item from a Google Keep list.

    Args:
        note_id: The list note ID
        item_id: The item ID to delete

    Returns:
        Success status
    """
    try:
        return client.delete_list_item(note_id, item_id)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_sort_list(note_id: str) -> list[dict] | dict:
    """
    Sort list items alphabetically (unchecked items on top).

    Args:
        note_id: The list note ID

    Returns:
        Sorted list of items
    """
    try:
        items = client.sort_list(note_id)
        return [asdict(item) for item in items]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_get_unchecked_items(note_id: str) -> list[dict] | dict:
    """
    Get only unchecked/remaining items from a list (what's left to do).

    Args:
        note_id: The list note ID

    Returns:
        List of unchecked items
    """
    try:
        items = client.get_unchecked_items(note_id)
        return [asdict(item) for item in items]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_bulk_check_items(
    note_id: str,
    item_ids: str,
    checked: bool = True,
) -> list[dict] | dict:
    """
    Bulk check or uncheck multiple list items at once.

    Args:
        note_id: The list note ID
        item_ids: Comma-separated item IDs to check/uncheck
        checked: Whether to check (True) or uncheck (False) the items

    Returns:
        Updated items
    """
    try:
        ids = [iid.strip() for iid in item_ids.split(",") if iid.strip()]
        items = client.bulk_check_items(note_id, ids, checked)
        return [asdict(item) for item in items]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Sharing tools
# ---------------------------------------------------------------------------


@mcp.tool()
def keep_share_note(note_id: str, email: str) -> dict:
    """
    Share a Google Keep note with another user.

    Args:
        note_id: The note ID to share
        email: Email address of the collaborator to add

    Returns:
        Success status with shared email
    """
    try:
        return client.share_note(note_id, email)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_unshare_note(note_id: str, email: str) -> dict:
    """
    Remove a collaborator from a Google Keep note.

    Args:
        note_id: The note ID
        email: Email address of the collaborator to remove

    Returns:
        Success status
    """
    try:
        return client.unshare_note(note_id, email)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_list_collaborators(note_id: str) -> list[str] | dict:
    """
    List all collaborators on a Google Keep note.

    Args:
        note_id: The note ID

    Returns:
        List of collaborator email addresses
    """
    try:
        return client.list_collaborators(note_id)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Label tools
# ---------------------------------------------------------------------------


@mcp.tool()
def keep_list_labels() -> list[dict] | dict:
    """
    List all Google Keep labels.

    Returns:
        List of labels with id and name
    """
    try:
        labels = client.list_labels()
        return [asdict(label) for label in labels]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_create_label(name: str) -> dict:
    """
    Create a new Google Keep label.

    Args:
        name: Label name

    Returns:
        Created label with id and name
    """
    try:
        result = client.create_label(name)
        return asdict(result)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_delete_label(name: str) -> dict:
    """
    Delete a Google Keep label (removes from all notes).

    Args:
        name: Label name to delete

    Returns:
        Success status
    """
    try:
        return client.delete_label(name)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_add_label(note_id: str, label_name: str) -> dict:
    """
    Add a label to a note (creates label if it doesn't exist).

    Args:
        note_id: The note ID
        label_name: Label name to add

    Returns:
        Success status
    """
    try:
        return client.add_label_to_note(note_id, label_name)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_remove_label(note_id: str, label_name: str) -> dict:
    """
    Remove a label from a note.

    Args:
        note_id: The note ID
        label_name: Label name to remove

    Returns:
        Success status
    """
    try:
        return client.remove_label_from_note(note_id, label_name)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Quick action tools
# ---------------------------------------------------------------------------


@mcp.tool()
def keep_pin_note(note_id: str) -> dict:
    """
    Pin a note to the top of Google Keep.

    Args:
        note_id: The note ID to pin

    Returns:
        Updated note details
    """
    try:
        result = client.pin_note(note_id)
        return asdict(result)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_unpin_note(note_id: str) -> dict:
    """
    Unpin a note from the top of Google Keep.

    Args:
        note_id: The note ID to unpin

    Returns:
        Updated note details
    """
    try:
        result = client.unpin_note(note_id)
        return asdict(result)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_archive_note(note_id: str) -> dict:
    """
    Archive a Google Keep note.

    Args:
        note_id: The note ID to archive

    Returns:
        Updated note details
    """
    try:
        result = client.archive_note(note_id)
        return asdict(result)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_unarchive_note(note_id: str) -> dict:
    """
    Unarchive a Google Keep note.

    Args:
        note_id: The note ID to unarchive

    Returns:
        Updated note details
    """
    try:
        result = client.unarchive_note(note_id)
        return asdict(result)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_set_color(note_id: str, color: str) -> dict:
    """
    Set the color of a Google Keep note.

    Color coding suggestions for AI assistant:
    - red: urgent/important
    - orange: work tasks
    - yellow: shopping/errands
    - green: household/home
    - blue: personal/hobbies
    - purple: ideas/brainstorming
    - teal: health/wellness
    - pink: family/social

    Args:
        note_id: The note ID
        color: Color name (white, red, orange, yellow, green, teal, blue, cerulean, purple, pink, brown, gray)

    Returns:
        Updated note details
    """
    try:
        result = client.set_note_color(note_id, color)
        return asdict(result)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_create_shopping_list(
    title: str = "Nákupní seznam",
    items: str = "",
) -> dict:
    """
    Quick shortcut to create a pinned shopping list (yellow, pinned).

    Args:
        title: List title (default: "Nákupní seznam")
        items: Comma-separated items to add. Example: "Mléko, Chleba, Máslo"

    Returns:
        Created shopping list with all items
    """
    try:
        item_list = [i.strip() for i in items.split(",") if i.strip()] if items else []
        result = client.create_shopping_list(title=title, items=item_list)
        return asdict(result)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def keep_duplicate_note(note_id: str, new_title: str = "") -> dict:
    """
    Duplicate a note (useful for templates like weekly shopping lists).

    For list notes, all items are duplicated as unchecked.

    Args:
        note_id: The note ID to duplicate
        new_title: Title for the copy (default: original title + " (kopie)")

    Returns:
        Created duplicate note
    """
    try:
        result = client.duplicate_note(
            note_id=note_id,
            new_title=new_title or None,
        )
        return asdict(result)
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
