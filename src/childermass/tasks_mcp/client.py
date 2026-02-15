"""
Google Tasks API Client Wrapper

Provides a clean interface for Google Tasks API operations with integrated security.
All data stays local - we only call official Google APIs.

Security features:
- Input validation on all public functions
- Rate limiting per account / operation
- Audit logging for write operations (create, update, delete, complete)
- Error message sanitization to prevent credential leaks
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from googleapiclient.discovery import Resource, build

from .auth import get_authenticated_credentials, list_authenticated_accounts
from .security import (
    audit_log,
    rate_limiter,
    sanitize_error_message,
    validate_due_date,
    validate_max_results,
    validate_search_query,
    validate_task_id,
    validate_task_notes,
    validate_task_status,
    validate_task_title,
    validate_tasklist_id,
    validate_tasklist_title,
)

logger = logging.getLogger(__name__)

# Module-level client cache - keyed by account email
_tasks_services: dict[str, Resource] = {}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class TaskList:
    """Task list metadata."""

    id: str
    title: str
    updated: str = ""
    etag: str = ""


@dataclass
class Task:
    """A single task."""

    id: str
    tasklist_id: str
    title: str = ""
    notes: str = ""
    status: str = "needsAction"  # "needsAction" | "completed"
    due: str = ""                # RFC3339 (date portion only)
    completed: str = ""          # RFC3339 timestamp
    parent: str = ""             # parent task ID (for subtasks)
    position: str = ""
    hidden: bool = False
    deleted: bool = False
    links: list[dict] = field(default_factory=list)
    web_view_link: str = ""
    updated: str = ""
    etag: str = ""


# ---------------------------------------------------------------------------
# Service / account helpers
# ---------------------------------------------------------------------------


def get_tasks_service(account: str | None = None) -> Resource:
    """
    Get authenticated Tasks API service for a specific account.
    """
    global _tasks_services

    if account is None:
        accounts = list_authenticated_accounts()
        if not accounts:
            raise RuntimeError(
                "No authenticated Tasks accounts found. Run:\n"
                "  python -m childermass.tasks_mcp.auth --account=your@email.com"
            )
        account = accounts[0]
        if account == "default":
            account = None

    cache_key = account or "default"
    if cache_key in _tasks_services:
        return _tasks_services[cache_key]

    creds = get_authenticated_credentials(account)
    service = build("tasks", "v1", credentials=creds)
    _tasks_services[cache_key] = service
    return service


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now_rfc3339() -> str:
    """Get current time in RFC3339 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z")


def _today_rfc3339() -> str:
    """Get start of today in RFC3339 (UTC)."""
    now = datetime.now(timezone.utc)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ")


def _tomorrow_rfc3339() -> str:
    """Get start of tomorrow in RFC3339 (UTC)."""
    now = datetime.now(timezone.utc) + timedelta(days=1)
    end = now.replace(hour=23, minute=59, second=59, microsecond=0)
    return end.strftime("%Y-%m-%dT%H:%M:%SZ")


def _date_offset_rfc3339(days: int = 0) -> str:
    """Get RFC3339 datetime offset by N days from now."""
    dt = datetime.now(timezone.utc) + timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_task(task: dict, tasklist_id: str = "") -> Task:
    """Parse Tasks API task resource to Task object."""
    links = []
    for link in task.get("links", []):
        links.append({
            "type": link.get("type", ""),
            "description": link.get("description", ""),
            "link": link.get("link", ""),
        })

    return Task(
        id=task.get("id", ""),
        tasklist_id=tasklist_id,
        title=task.get("title", ""),
        notes=task.get("notes", ""),
        status=task.get("status", "needsAction"),
        due=task.get("due", ""),
        completed=task.get("completed", ""),
        parent=task.get("parent", ""),
        position=task.get("position", ""),
        hidden=task.get("hidden", False),
        deleted=task.get("deleted", False),
        links=links,
        web_view_link=task.get("webViewLink", ""),
        updated=task.get("updated", ""),
        etag=task.get("etag", ""),
    )


def _parse_tasklist(tasklist: dict) -> TaskList:
    """Parse Tasks API tasklist resource to TaskList object."""
    return TaskList(
        id=tasklist.get("id", ""),
        title=tasklist.get("title", ""),
        updated=tasklist.get("updated", ""),
        etag=tasklist.get("etag", ""),
    )


# ---------------------------------------------------------------------------
# TaskList operations
# ---------------------------------------------------------------------------


def list_tasklists(account: str | None = None) -> list[TaskList]:
    """
    List all task lists for the authenticated user.

    Returns:
        List of TaskList objects
    """
    acct_key = account or "default"
    rate_limiter.check(acct_key, "list_tasklists")

    service = get_tasks_service(account)
    tasklists = []
    page_token = None

    while True:
        result = (
            service.tasklists()
            .list(
                maxResults=100,
                pageToken=page_token,
            )
            .execute()
        )

        for tl in result.get("items", []):
            tasklists.append(_parse_tasklist(tl))

        page_token = result.get("nextPageToken")
        if not page_token:
            break

    return tasklists


def get_tasklist(
    tasklist_id: str,
    account: str | None = None,
) -> TaskList:
    """Get a single task list by ID."""
    tasklist_id = validate_tasklist_id(tasklist_id)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "get_tasklist")

    service = get_tasks_service(account)
    tl = service.tasklists().get(tasklist=tasklist_id).execute()

    return _parse_tasklist(tl)


def create_tasklist(
    title: str,
    account: str | None = None,
) -> TaskList:
    """
    Create a new task list.

    Args:
        title: Task list title (max 1024 chars)
        account: Account to use

    Returns:
        Created TaskList
    """
    title = validate_tasklist_title(title)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "create_tasklist")

    service = get_tasks_service(account)

    body = {"title": title}
    created = service.tasklists().insert(body=body).execute()

    result = _parse_tasklist(created)

    audit_log(
        operation="create_tasklist",
        account=acct_key,
        details={
            "tasklist_id": result.id,
            "title": title,
        },
    )

    return result


def update_tasklist(
    tasklist_id: str,
    title: str,
    account: str | None = None,
) -> TaskList:
    """
    Update a task list title.

    Args:
        tasklist_id: Task list ID
        title: New title
        account: Account to use

    Returns:
        Updated TaskList
    """
    tasklist_id = validate_tasklist_id(tasklist_id)
    title = validate_tasklist_title(title)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "update_tasklist")

    service = get_tasks_service(account)

    body = {"title": title}
    updated = (
        service.tasklists()
        .update(tasklist=tasklist_id, body=body)
        .execute()
    )

    result = _parse_tasklist(updated)

    audit_log(
        operation="update_tasklist",
        account=acct_key,
        details={
            "tasklist_id": tasklist_id,
            "title": title,
        },
    )

    return result


def delete_tasklist(
    tasklist_id: str,
    account: str | None = None,
) -> dict:
    """
    Delete a task list.

    Args:
        tasklist_id: Task list ID
        account: Account to use

    Returns:
        Success dict
    """
    tasklist_id = validate_tasklist_id(tasklist_id)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "delete_tasklist")

    service = get_tasks_service(account)
    service.tasklists().delete(tasklist=tasklist_id).execute()

    audit_log(
        operation="delete_tasklist",
        account=acct_key,
        details={"tasklist_id": tasklist_id},
    )

    return {"success": True, "tasklist_id": tasklist_id}


# ---------------------------------------------------------------------------
# Task operations
# ---------------------------------------------------------------------------


def list_tasks(
    tasklist_id: str,
    show_completed: bool = False,
    show_hidden: bool = False,
    due_min: str = "",
    due_max: str = "",
    max_results: int = 100,
    account: str | None = None,
) -> list[Task]:
    """
    List tasks from a specific task list.

    Args:
        tasklist_id: Task list ID
        show_completed: Include completed tasks (default: False)
        show_hidden: Include hidden tasks (default: False)
        due_min: Lower bound for due date (RFC3339)
        due_max: Upper bound for due date (RFC3339)
        max_results: Max tasks to return (1-100)
        account: Account to use

    Returns:
        List of Task objects
    """
    tasklist_id = validate_tasklist_id(tasklist_id)
    max_results = validate_max_results(max_results)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "list_tasks")

    service = get_tasks_service(account)

    kwargs: dict = {
        "tasklist": tasklist_id,
        "maxResults": max_results,
        "showCompleted": show_completed,
        "showHidden": show_hidden,
    }

    if due_min:
        kwargs["dueMin"] = validate_due_date(due_min)
    if due_max:
        kwargs["dueMax"] = validate_due_date(due_max)

    tasks = []
    page_token = None

    while True:
        if page_token:
            kwargs["pageToken"] = page_token

        result = service.tasks().list(**kwargs).execute()

        for task in result.get("items", []):
            tasks.append(_parse_task(task, tasklist_id))

        page_token = result.get("nextPageToken")
        if not page_token or len(tasks) >= max_results:
            break

    return tasks[:max_results]


def get_task(
    tasklist_id: str,
    task_id: str,
    account: str | None = None,
) -> Task:
    """
    Get a single task by ID.

    Args:
        tasklist_id: Task list ID
        task_id: Task ID
        account: Account to use

    Returns:
        Task with full details
    """
    tasklist_id = validate_tasklist_id(tasklist_id)
    task_id = validate_task_id(task_id)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "get_task")

    service = get_tasks_service(account)
    task = (
        service.tasks()
        .get(tasklist=tasklist_id, task=task_id)
        .execute()
    )

    return _parse_task(task, tasklist_id)


def create_task(
    tasklist_id: str,
    title: str,
    notes: str = "",
    due: str = "",
    parent: str = "",
    previous: str = "",
    account: str | None = None,
) -> Task:
    """
    Create a new task.

    Args:
        tasklist_id: Task list ID
        title: Task title (required, max 1024 chars)
        notes: Task notes (optional, max 8192 chars)
        due: Due date in RFC3339 or yyyy-mm-dd format (optional)
        parent: Parent task ID for subtask (optional)
        previous: Previous sibling task ID for ordering (optional)
        account: Account to use

    Returns:
        Created Task
    """
    tasklist_id = validate_tasklist_id(tasklist_id)
    title = validate_task_title(title)
    notes = validate_task_notes(notes)

    if parent:
        parent = validate_task_id(parent)
    if previous:
        previous = validate_task_id(previous)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "create_task")

    service = get_tasks_service(account)

    body: dict = {"title": title}
    if notes:
        body["notes"] = notes
    if due:
        body["due"] = validate_due_date(due)

    # parent and previous go as query params, not body
    insert_kwargs: dict = {
        "tasklist": tasklist_id,
        "body": body,
    }
    if parent:
        insert_kwargs["parent"] = parent
    if previous:
        insert_kwargs["previous"] = previous

    created = service.tasks().insert(**insert_kwargs).execute()

    result = _parse_task(created, tasklist_id)

    audit_log(
        operation="create_task",
        account=acct_key,
        details={
            "tasklist_id": tasklist_id,
            "task_id": result.id,
            "title": title,
        },
    )

    return result


def update_task(
    tasklist_id: str,
    task_id: str,
    title: str | None = None,
    notes: str | None = None,
    due: str | None = None,
    status: str | None = None,
    account: str | None = None,
) -> Task:
    """
    Update an existing task using get+update pattern.

    Only provided (non-None) fields are changed.

    Args:
        tasklist_id: Task list ID
        task_id: Task ID to update
        title: New title (None = keep existing)
        notes: New notes (None = keep existing, "" = clear)
        due: New due date (None = keep existing, "" = clear)
        status: New status (None = keep existing)
        account: Account to use

    Returns:
        Updated Task
    """
    tasklist_id = validate_tasklist_id(tasklist_id)
    task_id = validate_task_id(task_id)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "update_task")

    service = get_tasks_service(account)

    # Step 1: GET current task
    existing = (
        service.tasks()
        .get(tasklist=tasklist_id, task=task_id)
        .execute()
    )

    # Step 2: Merge changes
    if title is not None:
        existing["title"] = validate_task_title(title)
    if notes is not None:
        existing["notes"] = validate_task_notes(notes)
    if due is not None:
        if due == "":
            # Clear due date
            existing.pop("due", None)
        else:
            existing["due"] = validate_due_date(due)
    if status is not None:
        existing["status"] = validate_task_status(status)
        if status == "completed":
            existing["completed"] = _now_rfc3339()
        elif status == "needsAction":
            existing.pop("completed", None)

    # Step 3: UPDATE
    updated = (
        service.tasks()
        .update(tasklist=tasklist_id, task=task_id, body=existing)
        .execute()
    )

    result = _parse_task(updated, tasklist_id)

    audit_log(
        operation="update_task",
        account=acct_key,
        details={
            "tasklist_id": tasklist_id,
            "task_id": task_id,
            "title": result.title,
        },
    )

    return result


def complete_task(
    tasklist_id: str,
    task_id: str,
    account: str | None = None,
) -> Task:
    """
    Mark a task as completed.

    Args:
        tasklist_id: Task list ID
        task_id: Task ID to complete
        account: Account to use

    Returns:
        Updated Task with status="completed"
    """
    tasklist_id = validate_tasklist_id(tasklist_id)
    task_id = validate_task_id(task_id)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "complete_task")

    service = get_tasks_service(account)

    # GET + UPDATE to preserve etag
    existing = (
        service.tasks()
        .get(tasklist=tasklist_id, task=task_id)
        .execute()
    )

    existing["status"] = "completed"
    existing["completed"] = _now_rfc3339()

    updated = (
        service.tasks()
        .update(tasklist=tasklist_id, task=task_id, body=existing)
        .execute()
    )

    result = _parse_task(updated, tasklist_id)

    audit_log(
        operation="complete_task",
        account=acct_key,
        details={
            "tasklist_id": tasklist_id,
            "task_id": task_id,
            "title": result.title,
        },
    )

    return result


def uncomplete_task(
    tasklist_id: str,
    task_id: str,
    account: str | None = None,
) -> Task:
    """
    Mark a completed task as not completed (reopen).

    Args:
        tasklist_id: Task list ID
        task_id: Task ID to uncomplete
        account: Account to use

    Returns:
        Updated Task with status="needsAction"
    """
    tasklist_id = validate_tasklist_id(tasklist_id)
    task_id = validate_task_id(task_id)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "update_task")

    service = get_tasks_service(account)

    existing = (
        service.tasks()
        .get(tasklist=tasklist_id, task=task_id)
        .execute()
    )

    existing["status"] = "needsAction"
    existing.pop("completed", None)

    updated = (
        service.tasks()
        .update(tasklist=tasklist_id, task=task_id, body=existing)
        .execute()
    )

    result = _parse_task(updated, tasklist_id)

    audit_log(
        operation="uncomplete_task",
        account=acct_key,
        details={
            "tasklist_id": tasklist_id,
            "task_id": task_id,
            "title": result.title,
        },
    )

    return result


def delete_task(
    tasklist_id: str,
    task_id: str,
    account: str | None = None,
) -> dict:
    """
    Delete a task.

    Args:
        tasklist_id: Task list ID
        task_id: Task ID to delete
        account: Account to use

    Returns:
        Success dict
    """
    tasklist_id = validate_tasklist_id(tasklist_id)
    task_id = validate_task_id(task_id)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "delete_task")

    service = get_tasks_service(account)
    service.tasks().delete(tasklist=tasklist_id, task=task_id).execute()

    audit_log(
        operation="delete_task",
        account=acct_key,
        details={
            "tasklist_id": tasklist_id,
            "task_id": task_id,
        },
    )

    return {"success": True, "task_id": task_id}


def move_task(
    tasklist_id: str,
    task_id: str,
    parent: str = "",
    previous: str = "",
    account: str | None = None,
) -> Task:
    """
    Move a task to another position or under a different parent.

    Args:
        tasklist_id: Task list ID
        task_id: Task ID to move
        parent: New parent task ID (empty = move to top level)
        previous: Previous sibling task ID for ordering
        account: Account to use

    Returns:
        Moved Task
    """
    tasklist_id = validate_tasklist_id(tasklist_id)
    task_id = validate_task_id(task_id)

    if parent:
        parent = validate_task_id(parent)
    if previous:
        previous = validate_task_id(previous)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "move_task")

    service = get_tasks_service(account)

    move_kwargs: dict = {
        "tasklist": tasklist_id,
        "task": task_id,
    }
    if parent:
        move_kwargs["parent"] = parent
    if previous:
        move_kwargs["previous"] = previous

    moved = service.tasks().move(**move_kwargs).execute()

    result = _parse_task(moved, tasklist_id)

    audit_log(
        operation="move_task",
        account=acct_key,
        details={
            "tasklist_id": tasklist_id,
            "task_id": task_id,
            "parent": parent,
        },
    )

    return result


def clear_completed(
    tasklist_id: str,
    account: str | None = None,
) -> dict:
    """
    Clear all completed tasks from a task list.

    Removes completed tasks permanently – they cannot be recovered.

    Args:
        tasklist_id: Task list ID
        account: Account to use

    Returns:
        Success dict
    """
    tasklist_id = validate_tasklist_id(tasklist_id)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "clear_completed")

    service = get_tasks_service(account)
    service.tasks().clear(tasklist=tasklist_id).execute()

    audit_log(
        operation="clear_completed",
        account=acct_key,
        details={"tasklist_id": tasklist_id},
    )

    return {"success": True, "tasklist_id": tasklist_id}


# ---------------------------------------------------------------------------
# Convenience aggregations (for AI assistant)
# ---------------------------------------------------------------------------


def list_all_tasks(
    show_completed: bool = False,
    due_min: str = "",
    due_max: str = "",
    max_results_per_list: int = 100,
    account: str | None = None,
) -> list[Task]:
    """
    List tasks from ALL task lists, aggregated.

    Args:
        show_completed: Include completed tasks
        due_min: Lower bound for due date (RFC3339)
        due_max: Upper bound for due date (RFC3339)
        max_results_per_list: Max tasks per list
        account: Account to use

    Returns:
        List of Task objects from all lists, sorted by due date
    """
    tasklists = list_tasklists(account)
    all_tasks: list[Task] = []

    for tl in tasklists:
        try:
            tasks = list_tasks(
                tasklist_id=tl.id,
                show_completed=show_completed,
                due_min=due_min,
                due_max=due_max,
                max_results=max_results_per_list,
                account=account,
            )
            all_tasks.extend(tasks)
        except Exception as e:
            logger.warning(
                "Failed to list tasks from %s: %s",
                tl.title,
                sanitize_error_message(e),
            )

    # Sort: tasks with due dates first (chronologically), then tasks without
    def _sort_key(t: Task) -> tuple[int, str]:
        if t.due:
            return (0, t.due)
        return (1, t.title.lower())

    all_tasks.sort(key=_sort_key)

    return all_tasks


def list_due_today(
    account: str | None = None,
) -> list[Task]:
    """
    List tasks due today across all task lists.

    Returns:
        List of Task objects due today
    """
    return list_all_tasks(
        show_completed=False,
        due_min=_today_rfc3339(),
        due_max=_tomorrow_rfc3339(),
        account=account,
    )


def list_overdue(
    account: str | None = None,
) -> list[Task]:
    """
    List overdue tasks (due before today) across all task lists.

    Returns:
        List of overdue Task objects
    """
    return list_all_tasks(
        show_completed=False,
        due_min="2000-01-01T00:00:00Z",  # far past
        due_max=_today_rfc3339(),
        account=account,
    )


def search_tasks(
    query: str,
    show_completed: bool = False,
    account: str | None = None,
) -> list[Task]:
    """
    Search tasks by text across all task lists.

    Note: The Tasks API doesn't support server-side search,
    so this fetches all tasks and filters client-side.

    Args:
        query: Search text (case-insensitive match against title and notes)
        show_completed: Include completed tasks
        account: Account to use

    Returns:
        List of matching Task objects
    """
    query = validate_search_query(query)
    if not query:
        return []

    query_lower = query.lower()
    all_tasks = list_all_tasks(
        show_completed=show_completed,
        account=account,
    )

    return [
        task
        for task in all_tasks
        if query_lower in task.title.lower()
        or query_lower in task.notes.lower()
    ]


def bulk_complete(
    tasklist_id: str,
    task_ids: list[str],
    account: str | None = None,
) -> list[dict]:
    """
    Complete multiple tasks at once.

    Args:
        tasklist_id: Task list ID
        task_ids: List of task IDs to complete
        account: Account to use

    Returns:
        List of results for each task (success or error)
    """
    tasklist_id = validate_tasklist_id(tasklist_id)

    results = []
    for task_id in task_ids:
        try:
            task_id = validate_task_id(task_id)
            task = complete_task(
                tasklist_id=tasklist_id,
                task_id=task_id,
                account=account,
            )
            results.append({
                "task_id": task_id,
                "title": task.title,
                "success": True,
            })
        except Exception as e:
            results.append({
                "task_id": task_id,
                "success": False,
                "error": sanitize_error_message(e),
            })

    return results
