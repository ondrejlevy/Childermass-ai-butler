"""
Google Keep API Client Wrapper

Provides a clean interface for Google Keep operations via gkeepapi
with integrated security validation.

All data stays local - we only call official Google APIs (via gkeepapi).

Security features:
- Input validation on all public functions
- Rate limiting per account / operation
- Audit logging for write operations
- Error message sanitization to prevent credential leaks
"""

import logging
from dataclasses import dataclass, field

import gkeepapi
from gkeepapi.node import ColorValue, List, Note, TopLevelNode

from .auth import get_authenticated_keep, list_authenticated_accounts
from .security import (
    SecurityError,
    audit_log,
    rate_limiter,
    sanitize_error_message,
    validate_color,
    validate_email,
    validate_item_id,
    validate_label_name,
    validate_list_item_text,
    validate_max_results,
    validate_note_id,
    validate_note_text,
    validate_note_title,
    validate_note_type,
    validate_query,
)


logger = logging.getLogger(__name__)

# Module-level Keep client cache - keyed by account email
_keep_clients: dict[str, gkeepapi.Keep] = {}

# Color name -> gkeepapi ColorValue mapping
COLOR_MAP: dict[str, ColorValue] = {
    "white": ColorValue.White,
    "red": ColorValue.Red,
    "orange": ColorValue.Orange,
    "yellow": ColorValue.Yellow,
    "green": ColorValue.Green,
    "teal": ColorValue.Teal,
    "blue": ColorValue.Blue,
    "cerulean": ColorValue.DarkBlue,
    "purple": ColorValue.Purple,
    "pink": ColorValue.Pink,
    "brown": ColorValue.Brown,
    "gray": ColorValue.Gray,
}

# Reverse mapping
COLOR_REVERSE: dict[ColorValue, str] = {v: k for k, v in COLOR_MAP.items()}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ListItemInfo:
    """List item metadata."""

    id: str
    text: str
    checked: bool
    children: list["ListItemInfo"] = field(default_factory=list)


@dataclass
class LabelInfo:
    """Label metadata."""

    id: str
    name: str


@dataclass
class NoteInfo:
    """Basic note metadata."""

    id: str
    title: str
    note_type: str  # "text" or "list"
    color: str
    pinned: bool
    archived: bool
    trashed: bool
    labels: list[str]
    collaborators: list[str]
    created: str
    updated: str


@dataclass
class NoteDetail(NoteInfo):
    """Full note with content."""

    text: str = ""
    items: list[ListItemInfo] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Service / account helpers
# ---------------------------------------------------------------------------


def get_keep_client(account: str | None = None) -> gkeepapi.Keep:
    """
    Get authenticated Keep client for a specific account.
    """
    global _keep_clients

    if account is None:
        accounts = list_authenticated_accounts()
        if not accounts:
            msg = (
                "No authenticated Keep accounts found. Run:\n"
                "  python -m childermass.keep_mcp.auth --account=your@email.com"
            )
            raise RuntimeError(msg)
        account = accounts[0]
        if account == "default":
            account = None

    cache_key = account or "default"
    if cache_key in _keep_clients:
        return _keep_clients[cache_key]

    keep = get_authenticated_keep(account)
    _keep_clients[cache_key] = keep
    return keep


def _color_to_str(color: ColorValue) -> str:
    """Convert gkeepapi ColorValue to string."""
    return COLOR_REVERSE.get(color, "white")


def _str_to_color(color_str: str) -> ColorValue:
    """Convert string to gkeepapi ColorValue."""
    return COLOR_MAP.get(color_str.lower(), ColorValue.White)


def _node_to_info(node: TopLevelNode) -> NoteInfo:
    """Convert gkeepapi node to NoteInfo."""
    note_type = "list" if isinstance(node, List) else "text"
    labels = [label.name for label in node.labels.all()]
    collabs = list(node.collaborators.all())

    return NoteInfo(
        id=node.id,
        title=node.title,
        note_type=note_type,
        color=_color_to_str(node.color),
        pinned=node.pinned,
        archived=node.archived,
        trashed=node.trashed,
        labels=labels,
        collaborators=collabs,
        created=str(node.timestamps.created) if node.timestamps.created else "",
        updated=str(node.timestamps.updated) if node.timestamps.updated else "",
    )


def _node_to_detail(node: TopLevelNode) -> NoteDetail:
    """Convert gkeepapi node to NoteDetail."""
    info = _node_to_info(node)

    text = ""
    items: list[ListItemInfo] = []

    if isinstance(node, List):
        for item in node.items:
            children = []
            if hasattr(item, "subitems"):
                for child in item.subitems:
                    children.append(
                        ListItemInfo(
                            id=child.id,
                            text=child.text or "",
                            checked=child.checked,
                        )
                    )
            items.append(
                ListItemInfo(
                    id=item.id,
                    text=item.text or "",
                    checked=item.checked,
                    children=children,
                )
            )
    else:
        text = node.text or ""

    return NoteDetail(
        id=info.id,
        title=info.title,
        note_type=info.note_type,
        color=info.color,
        pinned=info.pinned,
        archived=info.archived,
        trashed=info.trashed,
        labels=info.labels,
        collaborators=info.collaborators,
        created=info.created,
        updated=info.updated,
        text=text,
        items=items,
    )


def _find_note(keep: gkeepapi.Keep, note_id: str) -> TopLevelNode:
    """Find a note by ID. Raises SecurityError if not found."""
    node = keep.get(note_id)
    if node is None:
        msg = f"Note not found: {note_id}"
        raise SecurityError(msg)
    return node


def _find_list_item(note: List, item_id: str):
    """Find a list item by ID. Raises SecurityError if not found."""
    for item in note.items:
        if item.id == item_id:
            return item
        # Check children
        if hasattr(item, "subitems"):
            for child in item.subitems:
                if child.id == item_id:
                    return child
    msg = f"List item not found: {item_id}"
    raise SecurityError(msg)


# ---------------------------------------------------------------------------
# Note CRUD operations
# ---------------------------------------------------------------------------


def create_note(
    title: str,
    content: str = "",
    note_type: str = "text",
    color: str = "",
    pinned: bool = False,
    labels: list[str] | None = None,
    items: list[tuple[str, bool]] | None = None,
    account: str | None = None,
) -> NoteDetail:
    """
    Create a new note or list.

    Args:
        title: Note title
        content: Text content (for text notes)
        note_type: "text" or "list"
        color: Note color name
        pinned: Whether to pin the note
        labels: Label names to apply
        items: List items as (text, checked) tuples (for list notes)
        account: Account to use
    """
    # Validate inputs
    title = validate_note_title(title)
    content = validate_note_text(content)
    note_type = validate_note_type(note_type)

    if items:
        for item_text, _ in items:
            validate_list_item_text(item_text)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "create")

    try:
        keep = get_keep_client(account)

        if note_type == "list":
            list_items = items or []
            if not list_items and content:
                # Convert text lines to list items
                list_items = [(line.strip(), False) for line in content.split("\n") if line.strip()]

            node = keep.createList(title, list_items)
        else:
            node = keep.createNote(title, content)

        # Apply optional attributes
        if color:
            color = validate_color(color)
            node.color = _str_to_color(color)

        if pinned:
            node.pinned = True

        if labels:
            for label_name in labels:
                label_name = validate_label_name(label_name)
                label = keep.findLabel(label_name)
                if label is None:
                    label = keep.createLabel(label_name)
                node.labels.add(label)

        keep.sync()

        audit_log(
            "create_note",
            acct_key,
            {
                "note_id": node.id,
                "type": note_type,
                "title": title[:50],
            },
        )

        return _node_to_detail(node)

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def get_note(note_id: str, account: str | None = None) -> NoteDetail:
    """Get full note details."""
    note_id = validate_note_id(note_id)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "get")

    try:
        keep = get_keep_client(account)
        node = _find_note(keep, note_id)
        return _node_to_detail(node)
    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def list_notes(
    query: str = "",
    pinned: bool | None = None,
    archived: bool | None = None,
    trashed: bool = False,
    labels: list[str] | None = None,
    colors: list[str] | None = None,
    max_results: int = 50,
    account: str | None = None,
) -> list[NoteInfo]:
    """
    List notes with optional filtering.
    """
    query = validate_query(query)
    max_results = validate_max_results(max_results)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "list")

    try:
        keep = get_keep_client(account)

        # Build find kwargs
        find_kwargs: dict = {}
        if query:
            find_kwargs["query"] = query
        if pinned is not None:
            find_kwargs["pinned"] = pinned
        if archived is not None:
            find_kwargs["archived"] = archived
        find_kwargs["trashed"] = trashed

        if labels:
            label_objs = []
            for label_name in labels:
                label_name = validate_label_name(label_name)
                label = keep.findLabel(label_name)
                if label:
                    label_objs.append(label)
            if label_objs:
                find_kwargs["labels"] = label_objs

        if colors:
            color_vals = []
            for c in colors:
                c = validate_color(c)
                color_vals.append(_str_to_color(c))
            find_kwargs["colors"] = color_vals

        notes = list(keep.find(**find_kwargs))
        notes = notes[:max_results]

        audit_log("list_notes", acct_key, {"count": len(notes), "query": query})

        return [_node_to_info(n) for n in notes]

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def search_notes(query: str, max_results: int = 50, account: str | None = None) -> list[NoteInfo]:
    """Search notes by text query."""
    query = validate_query(query)
    if not query:
        msg = "Search query is required"
        raise SecurityError(msg)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "search")

    return list_notes(query=query, max_results=max_results, account=account)


def update_note(
    note_id: str,
    title: str | None = None,
    text: str | None = None,
    color: str | None = None,
    pinned: bool | None = None,
    archived: bool | None = None,
    account: str | None = None,
) -> NoteDetail:
    """
    Update note attributes.
    """
    note_id = validate_note_id(note_id)
    if title is not None:
        title = validate_note_title(title)
    if text is not None:
        text = validate_note_text(text)
    if color is not None:
        color = validate_color(color)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "update")

    try:
        keep = get_keep_client(account)
        node = _find_note(keep, note_id)

        if title is not None:
            node.title = title

        if text is not None and isinstance(node, Note):
            node.text = text

        if color is not None:
            node.color = _str_to_color(color)

        if pinned is not None:
            node.pinned = pinned

        if archived is not None:
            node.archived = archived

        keep.sync()

        audit_log("update_note", acct_key, {"note_id": note_id})

        return _node_to_detail(node)

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def delete_note(note_id: str, account: str | None = None) -> dict:
    """Delete (trash) a note."""
    note_id = validate_note_id(note_id)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "delete")

    try:
        keep = get_keep_client(account)
        node = _find_note(keep, note_id)
        node.trash()
        keep.sync()

        audit_log("delete_note", acct_key, {"note_id": note_id})

        return {"success": True, "note_id": note_id}

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


# ---------------------------------------------------------------------------
# List item operations
# ---------------------------------------------------------------------------


def get_list_items(note_id: str, account: str | None = None) -> list[ListItemInfo]:
    """Get all items in a list note."""
    note_id = validate_note_id(note_id)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "get")

    try:
        keep = get_keep_client(account)
        node = _find_note(keep, note_id)

        if not isinstance(node, List):
            msg = f"Note {note_id} is not a list"
            raise SecurityError(msg)

        items: list[ListItemInfo] = []
        for item in node.items:
            children = []
            if hasattr(item, "subitems"):
                for child in item.subitems:
                    children.append(
                        ListItemInfo(
                            id=child.id,
                            text=child.text or "",
                            checked=child.checked,
                        )
                    )
            items.append(
                ListItemInfo(
                    id=item.id,
                    text=item.text or "",
                    checked=item.checked,
                    children=children,
                )
            )

        return items

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def add_list_item(
    note_id: str,
    text: str,
    checked: bool = False,
    position: str = "bottom",
    account: str | None = None,
) -> ListItemInfo:
    """
    Add an item to a list note.

    Args:
        note_id: List note ID
        text: Item text
        checked: Whether item is checked
        position: "top" or "bottom"
        account: Account to use
    """
    note_id = validate_note_id(note_id)
    text = validate_list_item_text(text)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "add_item")

    try:
        keep = get_keep_client(account)
        node = _find_note(keep, note_id)

        if not isinstance(node, List):
            msg = f"Note {note_id} is not a list"
            raise SecurityError(msg)

        placement = (
            gkeepapi.node.NewListItemPlacementValue.Top
            if position.lower() == "top"
            else gkeepapi.node.NewListItemPlacementValue.Bottom
        )

        item = node.add(text, checked, placement)
        keep.sync()

        audit_log(
            "add_list_item",
            acct_key,
            {
                "note_id": note_id,
                "text": text[:50],
            },
        )

        return ListItemInfo(
            id=item.id,
            text=item.text or "",
            checked=item.checked,
        )

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def update_list_item(
    note_id: str,
    item_id: str,
    text: str | None = None,
    checked: bool | None = None,
    account: str | None = None,
) -> ListItemInfo:
    """Update a list item's text or checked state."""
    note_id = validate_note_id(note_id)
    item_id = validate_item_id(item_id)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "update")

    try:
        keep = get_keep_client(account)
        node = _find_note(keep, note_id)

        if not isinstance(node, List):
            msg = f"Note {note_id} is not a list"
            raise SecurityError(msg)

        item = _find_list_item(node, item_id)

        if text is not None:
            text = validate_list_item_text(text)
            item.text = text

        if checked is not None:
            item.checked = checked

        keep.sync()

        audit_log(
            "update_list_item",
            acct_key,
            {
                "note_id": note_id,
                "item_id": item_id,
            },
        )

        return ListItemInfo(
            id=item.id,
            text=item.text or "",
            checked=item.checked,
        )

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def check_list_item(note_id: str, item_id: str, account: str | None = None) -> ListItemInfo:
    """Mark a list item as checked."""
    return update_list_item(note_id, item_id, checked=True, account=account)


def uncheck_list_item(note_id: str, item_id: str, account: str | None = None) -> ListItemInfo:
    """Mark a list item as unchecked."""
    return update_list_item(note_id, item_id, checked=False, account=account)


def delete_list_item(note_id: str, item_id: str, account: str | None = None) -> dict:
    """Delete a list item."""
    note_id = validate_note_id(note_id)
    item_id = validate_item_id(item_id)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "delete_item")

    try:
        keep = get_keep_client(account)
        node = _find_note(keep, note_id)

        if not isinstance(node, List):
            msg = f"Note {note_id} is not a list"
            raise SecurityError(msg)

        item = _find_list_item(node, item_id)
        item.delete()
        keep.sync()

        audit_log(
            "delete_list_item",
            acct_key,
            {
                "note_id": note_id,
                "item_id": item_id,
            },
        )

        return {"success": True, "note_id": note_id, "item_id": item_id}

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def sort_list(note_id: str, account: str | None = None) -> list[ListItemInfo]:
    """Sort list items alphabetically (unchecked on top)."""
    note_id = validate_note_id(note_id)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "update")

    try:
        keep = get_keep_client(account)
        node = _find_note(keep, note_id)

        if not isinstance(node, List):
            msg = f"Note {note_id} is not a list"
            raise SecurityError(msg)

        node.sort_items()
        keep.sync()

        audit_log("sort_list", acct_key, {"note_id": note_id})

        return get_list_items(note_id, account)

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def get_unchecked_items(note_id: str, account: str | None = None) -> list[ListItemInfo]:
    """Get only unchecked items from a list."""
    note_id = validate_note_id(note_id)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "get")

    try:
        keep = get_keep_client(account)
        node = _find_note(keep, note_id)

        if not isinstance(node, List):
            msg = f"Note {note_id} is not a list"
            raise SecurityError(msg)

        return [
            ListItemInfo(
                id=item.id,
                text=item.text or "",
                checked=item.checked,
            )
            for item in node.unchecked
        ]

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def bulk_check_items(
    note_id: str,
    item_ids: list[str],
    checked: bool = True,
    account: str | None = None,
) -> list[ListItemInfo]:
    """Bulk check or uncheck multiple list items."""
    note_id = validate_note_id(note_id)
    validated_ids = [validate_item_id(iid) for iid in item_ids]
    acct_key = account or "default"
    rate_limiter.check(acct_key, "check")

    try:
        keep = get_keep_client(account)
        node = _find_note(keep, note_id)

        if not isinstance(node, List):
            msg = f"Note {note_id} is not a list"
            raise SecurityError(msg)

        results = []
        for iid in validated_ids:
            item = _find_list_item(node, iid)
            item.checked = checked
            results.append(
                ListItemInfo(
                    id=item.id,
                    text=item.text or "",
                    checked=item.checked,
                )
            )

        keep.sync()

        audit_log(
            "bulk_check_items",
            acct_key,
            {
                "note_id": note_id,
                "count": len(validated_ids),
                "checked": checked,
            },
        )

        return results

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


# ---------------------------------------------------------------------------
# Sharing / Collaborator operations
# ---------------------------------------------------------------------------


def share_note(note_id: str, email: str, account: str | None = None) -> dict:
    """Share a note with a collaborator."""
    note_id = validate_note_id(note_id)
    email = validate_email(email)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "share")

    try:
        keep = get_keep_client(account)
        node = _find_note(keep, note_id)
        node.collaborators.add(email)
        keep.sync()

        audit_log(
            "share_note",
            acct_key,
            {
                "note_id": note_id,
                "email": email,
            },
        )

        return {"success": True, "note_id": note_id, "shared_with": email}

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def unshare_note(note_id: str, email: str, account: str | None = None) -> dict:
    """Remove a collaborator from a note."""
    note_id = validate_note_id(note_id)
    email = validate_email(email)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "unshare")

    try:
        keep = get_keep_client(account)
        node = _find_note(keep, note_id)
        node.collaborators.remove(email)
        keep.sync()

        audit_log(
            "unshare_note",
            acct_key,
            {
                "note_id": note_id,
                "email": email,
            },
        )

        return {"success": True, "note_id": note_id, "unshared": email}

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def list_collaborators(note_id: str, account: str | None = None) -> list[str]:
    """List all collaborators on a note."""
    note_id = validate_note_id(note_id)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "get")

    try:
        keep = get_keep_client(account)
        node = _find_note(keep, note_id)
        return list(node.collaborators.all())

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


# ---------------------------------------------------------------------------
# Label operations
# ---------------------------------------------------------------------------


def list_labels(account: str | None = None) -> list[LabelInfo]:
    """List all labels."""
    acct_key = account or "default"
    rate_limiter.check(acct_key, "label")

    try:
        keep = get_keep_client(account)
        return [LabelInfo(id=label.id, name=label.name) for label in keep.labels()]
    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def create_label(name: str, account: str | None = None) -> LabelInfo:
    """Create a new label."""
    name = validate_label_name(name)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "label")

    try:
        keep = get_keep_client(account)

        # Check if label already exists
        existing = keep.findLabel(name)
        if existing:
            return LabelInfo(id=existing.id, name=existing.name)

        label = keep.createLabel(name)
        keep.sync()

        audit_log("create_label", acct_key, {"name": name})

        return LabelInfo(id=label.id, name=label.name)

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def delete_label(name: str, account: str | None = None) -> dict:
    """Delete a label (removes from all notes)."""
    name = validate_label_name(name)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "label")

    try:
        keep = get_keep_client(account)
        label = keep.findLabel(name)

        if not label:
            msg = f"Label not found: {name}"
            raise SecurityError(msg)

        keep.deleteLabel(label)
        keep.sync()

        audit_log("delete_label", acct_key, {"name": name})

        return {"success": True, "label": name}

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def add_label_to_note(note_id: str, label_name: str, account: str | None = None) -> dict:
    """Add a label to a note."""
    note_id = validate_note_id(note_id)
    label_name = validate_label_name(label_name)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "label")

    try:
        keep = get_keep_client(account)
        node = _find_note(keep, note_id)

        label = keep.findLabel(label_name)
        if not label:
            label = keep.createLabel(label_name)

        node.labels.add(label)
        keep.sync()

        audit_log(
            "add_label_to_note",
            acct_key,
            {
                "note_id": note_id,
                "label": label_name,
            },
        )

        return {"success": True, "note_id": note_id, "label": label_name}

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def remove_label_from_note(note_id: str, label_name: str, account: str | None = None) -> dict:
    """Remove a label from a note."""
    note_id = validate_note_id(note_id)
    label_name = validate_label_name(label_name)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "label")

    try:
        keep = get_keep_client(account)
        node = _find_note(keep, note_id)

        label = keep.findLabel(label_name)
        if not label:
            msg = f"Label not found: {label_name}"
            raise SecurityError(msg)

        node.labels.remove(label)
        keep.sync()

        audit_log(
            "remove_label_from_note",
            acct_key,
            {
                "note_id": note_id,
                "label": label_name,
            },
        )

        return {"success": True, "note_id": note_id, "label": label_name}

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


# ---------------------------------------------------------------------------
# Quick actions
# ---------------------------------------------------------------------------


def pin_note(note_id: str, account: str | None = None) -> NoteDetail:
    """Pin a note."""
    return update_note(note_id, pinned=True, account=account)


def unpin_note(note_id: str, account: str | None = None) -> NoteDetail:
    """Unpin a note."""
    return update_note(note_id, pinned=False, account=account)


def archive_note(note_id: str, account: str | None = None) -> NoteDetail:
    """Archive a note."""
    return update_note(note_id, archived=True, account=account)


def unarchive_note(note_id: str, account: str | None = None) -> NoteDetail:
    """Unarchive a note."""
    return update_note(note_id, archived=False, account=account)


def set_note_color(note_id: str, color: str, account: str | None = None) -> NoteDetail:
    """Set note color."""
    return update_note(note_id, color=color, account=account)


def create_shopping_list(
    title: str,
    items: list[str],
    account: str | None = None,
) -> NoteDetail:
    """
    Shortcut: create a shopping list.

    Args:
        title: List title (e.g. "Nákupní seznam")
        items: List of item texts
        account: Account to use
    """
    item_tuples = [(item, False) for item in items]
    return create_note(
        title=title,
        note_type="list",
        items=item_tuples,
        color="yellow",
        pinned=True,
        account=account,
    )


def duplicate_note(
    note_id: str,
    new_title: str | None = None,
    account: str | None = None,
) -> NoteDetail:
    """
    Duplicate a note (useful for templates like weekly shopping list).
    """
    note_id = validate_note_id(note_id)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "create")

    try:
        keep = get_keep_client(account)
        original = _find_note(keep, note_id)
        detail = _node_to_detail(original)

        title = new_title if new_title else f"{detail.title} (kopie)"
        title = validate_note_title(title)

        if detail.note_type == "list":
            # Duplicate as list with unchecked items
            items = [(item.text, False) for item in detail.items]
            return create_note(
                title=title,
                note_type="list",
                items=items,
                color=detail.color,
                pinned=detail.pinned,
                labels=detail.labels if detail.labels else None,
                account=account,
            )
        return create_note(
            title=title,
            content=detail.text,
            note_type="text",
            color=detail.color,
            pinned=detail.pinned,
            labels=detail.labels if detail.labels else None,
            account=account,
        )

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None
