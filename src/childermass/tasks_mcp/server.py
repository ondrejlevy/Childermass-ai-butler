"""
Childermass Google Tasks MCP Server

Custom Google Tasks MCP server for Claude Code / OpenCode.
All data stays local - we only call official Google APIs.

Security: All tool responses go through error sanitization so that
OAuth tokens, credentials, or internal paths are never leaked to the LLM.

Run with: python -m childermass.tasks_mcp.server
"""

from dataclasses import asdict

from mcp.server.fastmcp import FastMCP

from . import client
from .security import SecurityError, sanitize_error_message


# Create FastMCP server
mcp = FastMCP("childermass-tasks")


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
# Task list tools
# ---------------------------------------------------------------------------


@mcp.tool()
def tasks_list_tasklists() -> list[dict] | dict:
    """
    List all task lists in the user's Google Tasks account.

    Returns:
        List of task lists with id, title, and last updated timestamp.
        The default list is named "My Tasks" (or localized equivalent).
    """
    try:
        tasklists = client.list_tasklists()
        return [asdict(tl) for tl in tasklists]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def tasks_create_tasklist(title: str) -> dict:
    """
    Create a new task list.

    Args:
        title: Name for the new task list (max 1024 characters)

    Returns:
        Created task list with id and title.
    """
    try:
        tasklist = client.create_tasklist(title=title)
        return asdict(tasklist)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def tasks_update_tasklist(
    tasklist_id: str,
    title: str,
) -> dict:
    """
    Rename an existing task list.

    Args:
        tasklist_id: Task list ID (from tasks_list_tasklists)
        title: New name for the task list

    Returns:
        Updated task list with new title.
    """
    try:
        tasklist = client.update_tasklist(
            tasklist_id=tasklist_id,
            title=title,
        )
        return asdict(tasklist)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def tasks_delete_tasklist(tasklist_id: str) -> dict:
    """
    Delete a task list and all its tasks.

    WARNING: This permanently deletes the task list and ALL tasks in it.
    Cannot be undone. The default "My Tasks" list cannot be deleted.

    Args:
        tasklist_id: Task list ID to delete

    Returns:
        Success confirmation.
    """
    try:
        return client.delete_tasklist(tasklist_id=tasklist_id)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Task read tools
# ---------------------------------------------------------------------------


@mcp.tool()
def tasks_list_tasks(
    tasklist_id: str,
    show_completed: bool = False,
    show_hidden: bool = False,
    due_min: str = "",
    due_max: str = "",
    max_results: int = 100,
) -> list[dict] | dict:
    """
    List tasks from a specific task list.

    Args:
        tasklist_id: Task list ID (from tasks_list_tasklists,
            or use the ID of the default "My Tasks" list)
        show_completed: Include completed tasks (default: False,
            only shows active tasks)
        show_hidden: Include hidden tasks (default: False)
        due_min: Filter tasks due on or after this date.
            Format: "2024-01-15" or RFC3339 "2024-01-15T00:00:00Z"
        due_max: Filter tasks due on or before this date.
            Format: "2024-01-31" or RFC3339 "2024-01-31T00:00:00Z"
        max_results: Maximum number of tasks to return (1-100, default: 100)

    Returns:
        List of tasks with id, title, notes, status, due date,
        parent (for subtasks), and position.
    """
    try:
        tasks = client.list_tasks(
            tasklist_id=tasklist_id,
            show_completed=show_completed,
            show_hidden=show_hidden,
            due_min=due_min or "",
            due_max=due_max or "",
            max_results=max_results,
        )
        return [asdict(t) for t in tasks]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def tasks_get_task(
    tasklist_id: str,
    task_id: str,
) -> dict:
    """
    Get full details of a specific task.

    Args:
        tasklist_id: Task list ID
        task_id: Task ID (from tasks_list_tasks)

    Returns:
        Full task details including title, notes, status, due date,
        completion time, subtask parent, and web link.
    """
    try:
        task = client.get_task(
            tasklist_id=tasklist_id,
            task_id=task_id,
        )
        return asdict(task)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Task write tools
# ---------------------------------------------------------------------------


@mcp.tool()
def tasks_create_task(
    tasklist_id: str,
    title: str,
    notes: str = "",
    due: str = "",
    parent: str = "",
    previous: str = "",
) -> dict:
    """
    Create a new task.

    Args:
        tasklist_id: Task list ID to add the task to
        title: Task title (required, max 1024 characters)
        notes: Task description / notes (optional, max 8192 characters)
        due: Due date. Format: "2024-01-15" or "2024-01-15T00:00:00Z".
            Optional – tasks without a due date appear at the top.
        parent: Parent task ID to create this as a subtask (optional).
            Subtasks appear indented under the parent in Google Tasks UI.
        previous: ID of the task this one should appear after (optional).
            Used for manual ordering within the list.

    Returns:
        Created task with id, title, and all details.
    """
    try:
        task = client.create_task(
            tasklist_id=tasklist_id,
            title=title,
            notes=notes or "",
            due=due or "",
            parent=parent or "",
            previous=previous or "",
        )
        return asdict(task)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def tasks_create_subtask(
    tasklist_id: str,
    parent_task_id: str,
    title: str,
    notes: str = "",
    due: str = "",
) -> dict:
    """
    Create a subtask under an existing task.

    Convenience wrapper around tasks_create_task that creates a subtask
    (a task nested under a parent task).

    Args:
        tasklist_id: Task list ID
        parent_task_id: ID of the parent task to nest under
        title: Subtask title
        notes: Subtask notes (optional)
        due: Due date (optional). Format: "2024-01-15"

    Returns:
        Created subtask with all details. The parent field will be set.
    """
    try:
        task = client.create_task(
            tasklist_id=tasklist_id,
            title=title,
            notes=notes or "",
            due=due or "",
            parent=parent_task_id,
        )
        return asdict(task)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def tasks_update_task(
    tasklist_id: str,
    task_id: str,
    title: str = "",
    notes: str = "",
    due: str = "",
    status: str = "",
) -> dict:
    """
    Update an existing task.

    Only specify the fields you want to change – unspecified fields
    remain unchanged. Uses atomic get+update to prevent race conditions.

    Args:
        tasklist_id: Task list ID
        task_id: Task ID to update
        title: New title. Empty = keep existing.
        notes: New notes. Empty = keep existing. Use "CLEAR" to remove notes.
        due: New due date ("2024-01-15"). Empty = keep existing.
            Use "CLEAR" to remove due date.
        status: New status. Empty = keep existing.
            Valid values: "needsAction" (active) or "completed" (done).

    Returns:
        Updated task with all details.
    """
    try:
        # Map empty strings to None (keep existing), special "CLEAR" to ""
        title_val = title if title else None
        notes_val = None
        if notes == "CLEAR":
            notes_val = ""
        elif notes:
            notes_val = notes
        due_val = None
        if due == "CLEAR":
            due_val = ""
        elif due:
            due_val = due
        status_val = status if status else None

        task = client.update_task(
            tasklist_id=tasklist_id,
            task_id=task_id,
            title=title_val,
            notes=notes_val,
            due=due_val,
            status=status_val,
        )
        return asdict(task)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def tasks_complete_task(
    tasklist_id: str,
    task_id: str,
) -> dict:
    """
    Mark a task as completed.

    Sets the task status to "completed" and records the completion timestamp.

    Args:
        tasklist_id: Task list ID
        task_id: Task ID to mark as done

    Returns:
        Updated task with status="completed" and completion time.
    """
    try:
        task = client.complete_task(
            tasklist_id=tasklist_id,
            task_id=task_id,
        )
        return asdict(task)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def tasks_uncomplete_task(
    tasklist_id: str,
    task_id: str,
) -> dict:
    """
    Reopen a completed task.

    Sets the task status back to "needsAction" and clears the completion timestamp.

    Args:
        tasklist_id: Task list ID
        task_id: Task ID to reopen

    Returns:
        Updated task with status="needsAction".
    """
    try:
        task = client.uncomplete_task(
            tasklist_id=tasklist_id,
            task_id=task_id,
        )
        return asdict(task)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def tasks_delete_task(
    tasklist_id: str,
    task_id: str,
) -> dict:
    """
    Delete a task permanently.

    WARNING: This cannot be undone. The task is permanently removed.

    Args:
        tasklist_id: Task list ID
        task_id: Task ID to delete

    Returns:
        Success confirmation with task ID.
    """
    try:
        return client.delete_task(
            tasklist_id=tasklist_id,
            task_id=task_id,
        )
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def tasks_move_task(
    tasklist_id: str,
    task_id: str,
    parent: str = "",
    previous: str = "",
) -> dict:
    """
    Move a task to a different position or make it a subtask.

    Can be used to:
    - Reorder tasks within a list
    - Make a task a subtask of another task (set parent)
    - Move a subtask to top level (leave parent empty)

    Args:
        tasklist_id: Task list ID
        task_id: Task ID to move
        parent: New parent task ID (empty = move to top level).
            Set this to nest the task as a subtask.
        previous: ID of the task this one should appear after (optional).
            Used for manual ordering.

    Returns:
        Moved task with updated position and parent.
    """
    try:
        task = client.move_task(
            tasklist_id=tasklist_id,
            task_id=task_id,
            parent=parent or "",
            previous=previous or "",
        )
        return asdict(task)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def tasks_clear_completed(tasklist_id: str) -> dict:
    """
    Clear all completed tasks from a task list.

    WARNING: This permanently removes all completed tasks from the list.
    They cannot be recovered. Active (needsAction) tasks are not affected.

    Args:
        tasklist_id: Task list ID

    Returns:
        Success confirmation.
    """
    try:
        return client.clear_completed(tasklist_id=tasklist_id)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Bulk operations
# ---------------------------------------------------------------------------


@mcp.tool()
def tasks_bulk_complete(
    tasklist_id: str,
    task_ids: str,
) -> list[dict] | dict:
    """
    Complete multiple tasks at once.

    Useful for checking off a batch of tasks that are all done.

    Args:
        tasklist_id: Task list ID
        task_ids: Comma-separated list of task IDs to complete.
            Example: "abc123, def456, ghi789"

    Returns:
        List of results for each task: success status, title, and any errors.
    """
    try:
        ids = [tid.strip() for tid in task_ids.split(",") if tid.strip()]
        if not ids:
            return {"error": "No task IDs provided"}
        return client.bulk_complete(
            tasklist_id=tasklist_id,
            task_ids=ids,
        )
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Convenience / aggregation tools (most used by AI assistant)
# ---------------------------------------------------------------------------


@mcp.tool()
def tasks_list_all_tasks(
    show_completed: bool = False,
    due_min: str = "",
    due_max: str = "",
    max_results_per_list: int = 100,
) -> list[dict] | dict:
    """
    List tasks from ALL task lists, aggregated and sorted by due date.

    Useful for getting a complete overview of all your tasks across
    every task list. Tasks with due dates appear first (chronologically),
    followed by tasks without due dates.

    Args:
        show_completed: Include completed tasks (default: False)
        due_min: Filter tasks due on or after this date ("2024-01-15")
        due_max: Filter tasks due on or before this date ("2024-01-31")
        max_results_per_list: Max tasks per individual list (default: 100)

    Returns:
        Sorted list of tasks from all lists. Each task includes
        tasklist_id to identify which list it belongs to.
    """
    try:
        tasks = client.list_all_tasks(
            show_completed=show_completed,
            due_min=due_min or "",
            due_max=due_max or "",
            max_results_per_list=max_results_per_list,
        )
        return [asdict(t) for t in tasks]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def tasks_list_due_today() -> list[dict] | dict:
    """
    List all tasks due today across all task lists.

    This is the most common tasks query. Returns all active tasks
    that are due today, from all task lists.

    Returns:
        List of today's tasks sorted by due date.
        Empty list if no tasks are due today.
    """
    try:
        tasks = client.list_due_today()
        return [asdict(t) for t in tasks]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def tasks_list_overdue() -> list[dict] | dict:
    """
    List all overdue tasks across all task lists.

    Returns tasks whose due date is before today and are not yet completed.
    Useful for daily review to catch missed tasks.

    Returns:
        List of overdue tasks sorted by due date (oldest first).
        Empty list if no overdue tasks.
    """
    try:
        tasks = client.list_overdue()
        return [asdict(t) for t in tasks]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def tasks_search(
    query: str,
    show_completed: bool = False,
) -> list[dict] | dict:
    """
    Search tasks by text across all task lists.

    Searches task title and notes for the given text (case-insensitive).
    Note: Google Tasks API doesn't support server-side search, so this
    fetches all tasks and filters locally.

    Args:
        query: Search text (e.g., "groceries", "meeting prep", "report")
        show_completed: Include completed tasks in search (default: False)

    Returns:
        List of matching tasks from all lists.
    """
    try:
        tasks = client.search_tasks(
            query=query,
            show_completed=show_completed,
        )
        return [asdict(t) for t in tasks]
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
