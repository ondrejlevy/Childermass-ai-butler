"""
Childermass Gmail MCP Server

Custom Gmail MCP server for Claude Code / OpenCode.
All data stays local - we only call official Google APIs.

Security: All tool responses go through error sanitization so that
OAuth tokens, credentials, or internal paths are never leaked to the LLM.

Run with: python -m childermass.gmail_mcp.server
"""

from dataclasses import asdict

from mcp.server.fastmcp import FastMCP

from . import client
from .security import SecurityError, sanitize_error_message, sanitize_filename

# Create FastMCP server
mcp = FastMCP("childermass-gmail")


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
# Read tools
# ---------------------------------------------------------------------------


@mcp.tool()
def gmail_list_emails(
    query: str = "",
    max_results: int = 20,
    label: str = "",
) -> list[dict] | dict:
    """
    List emails from Gmail inbox.

    Args:
        query: Gmail search query (e.g., "from:boss@company.com", "is:unread", "subject:urgent")
        max_results: Maximum number of emails to return (default: 20)
        label: Filter by label (e.g., "INBOX", "SENT", "STARRED")

    Returns:
        List of emails with id, subject, from, date, snippet, and status
    """
    try:
        label_ids = [label] if label else None
        emails = client.list_emails(
            query=query,
            max_results=max_results,
            label_ids=label_ids,
        )
        return [asdict(email) for email in emails]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def gmail_read_email(message_id: str) -> dict:
    """
    Read full email content.

    Args:
        message_id: The email message ID (from gmail_list_emails)

    Returns:
        Full email with body, attachments, and metadata
    """
    try:
        email = client.get_email(message_id)
        return asdict(email)
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def gmail_search(query: str, max_results: int = 20) -> list[dict] | dict:
    """
    Search emails using Gmail query syntax.

    Args:
        query: Gmail search query. Examples:
            - "from:boss@company.com" - emails from specific sender
            - "to:me subject:meeting" - emails to me about meetings
            - "has:attachment filename:pdf" - emails with PDF attachments
            - "after:2024/01/01 before:2024/12/31" - date range
            - "is:unread in:inbox" - unread inbox emails
            - "label:work" - emails with specific label
        max_results: Maximum results to return (default: 20)

    Returns:
        List of matching emails
    """
    try:
        emails = client.search_emails(query=query, max_results=max_results)
        return [asdict(email) for email in emails]
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Write tools
# ---------------------------------------------------------------------------


@mcp.tool()
def gmail_send_email(
    to: str,
    subject: str,
    body: str,
    cc: str = "",
    bcc: str = "",
    reply_to_message_id: str = "",
    attachment_paths: str = "",
    forward_attachments: str = "",
    account: str = "",
) -> dict:
    """
    Send an email with optional attachments.

    IMPORTANT: When sending a new email (not a reply), you MUST specify which account to send from.
    Use AskUserQuestion to ask which account to use if not specified.

    Args:
        to: Recipient email address
        subject: Email subject
        body: Email body (plain text)
        cc: CC recipients (comma-separated)
        bcc: BCC recipients (comma-separated)
        reply_to_message_id: Message ID to reply to (for threading, prefer gmail_reply)
        attachment_paths: Local file paths to attach (comma-separated).
            Example: "/path/to/file1.pdf, /path/to/file2.docx"
        forward_attachments: Attachments from other emails to include (comma-separated).
            Format: "message_id:attachment_id, message_id:attachment_id"
            Get attachment_id from gmail_read_email response.
        account: Email account to send from (e.g., "user@gmail.com").
            REQUIRED for new emails. Use AskUserQuestion to get this from the user.

    Returns:
        Sent message ID, thread ID, and account used
    """
    try:
        # Parse attachment paths
        paths_list = None
        if attachment_paths:
            paths_list = [
                p.strip() for p in attachment_paths.split(",") if p.strip()
            ]

        # Parse forward attachments (format: "msg_id:att_id, msg_id:att_id")
        forward_list = None
        if forward_attachments:
            forward_list = []
            for item in forward_attachments.split(","):
                item = item.strip()
                if ":" in item:
                    msg_id, att_id = item.split(":", 1)
                    forward_list.append((msg_id.strip(), att_id.strip()))

        result = client.send_email(
            to=to,
            subject=subject,
            body=body,
            cc=cc or None,
            bcc=bcc or None,
            reply_to_message_id=reply_to_message_id or None,
            attachment_paths=paths_list,
            forward_attachments=forward_list,
            account=account or None,
        )
        return result

    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def gmail_create_draft(
    to: str,
    subject: str,
    body: str,
    cc: str = "",
    bcc: str = "",
    attachment_paths: str = "",
    forward_attachments: str = "",
) -> dict:
    """
    Create an email draft with optional attachments.

    Args:
        to: Recipient email address
        subject: Email subject
        body: Email body (plain text)
        cc: CC recipients (comma-separated)
        bcc: BCC recipients (comma-separated)
        attachment_paths: Local file paths to attach (comma-separated).
            Example: "/path/to/file1.pdf, /path/to/file2.docx"
        forward_attachments: Attachments from other emails to include (comma-separated).
            Format: "message_id:attachment_id, message_id:attachment_id"

    Returns:
        Draft ID and message ID
    """
    try:
        paths_list = None
        if attachment_paths:
            paths_list = [
                p.strip() for p in attachment_paths.split(",") if p.strip()
            ]

        forward_list = None
        if forward_attachments:
            forward_list = []
            for item in forward_attachments.split(","):
                item = item.strip()
                if ":" in item:
                    msg_id, att_id = item.split(":", 1)
                    forward_list.append((msg_id.strip(), att_id.strip()))

        result = client.create_draft(
            to=to,
            subject=subject,
            body=body,
            cc=cc or None,
            bcc=bcc or None,
            attachment_paths=paths_list,
            forward_attachments=forward_list,
        )
        return result

    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Label tools
# ---------------------------------------------------------------------------


@mcp.tool()
def gmail_list_labels() -> list[dict] | dict:
    """
    List all Gmail labels.

    Returns:
        List of labels with id, name, and type
    """
    try:
        labels = client.list_labels()
        return [asdict(label) for label in labels]
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def gmail_modify_labels(
    message_id: str,
    add_labels: str = "",
    remove_labels: str = "",
) -> dict:
    """
    Modify labels on an email.

    Args:
        message_id: The email message ID
        add_labels: Comma-separated label IDs to add
        remove_labels: Comma-separated label IDs to remove

    Returns:
        Success status
    """
    try:
        add_list = (
            [label.strip() for label in add_labels.split(",") if label.strip()]
            if add_labels
            else None
        )
        remove_list = (
            [
                label.strip()
                for label in remove_labels.split(",")
                if label.strip()
            ]
            if remove_labels
            else None
        )

        client.modify_labels(
            message_id=message_id,
            add_label_ids=add_list,
            remove_label_ids=remove_list,
        )
        return {"success": True, "message_id": message_id}

    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def gmail_mark_as_read(message_id: str) -> dict:
    """
    Mark an email as read.

    Args:
        message_id: The email message ID

    Returns:
        Success status
    """
    try:
        client.mark_as_read(message_id)
        return {"success": True, "message_id": message_id}
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def gmail_mark_as_unread(message_id: str) -> dict:
    """
    Mark an email as unread.

    Args:
        message_id: The email message ID

    Returns:
        Success status
    """
    try:
        client.mark_as_unread(message_id)
        return {"success": True, "message_id": message_id}
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def gmail_archive(message_id: str) -> dict:
    """
    Archive an email (remove from inbox).

    Args:
        message_id: The email message ID

    Returns:
        Success status
    """
    try:
        client.archive_email(message_id)
        return {"success": True, "message_id": message_id}
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


# ---------------------------------------------------------------------------
# Reply / Forward tools
# ---------------------------------------------------------------------------


@mcp.tool()
def gmail_reply(
    message_id: str,
    body: str,
    reply_all: bool = False,
    quote_original: bool = True,
    account: str = "",
) -> dict:
    """
    Reply to an email. Properly threads the conversation on both sender and recipient sides.

    IMPORTANT: This tool automatically detects which account received the original email
    and sends the reply from that account. You should NOT need to specify account manually.

    Args:
        message_id: The email message ID to reply to
        body: Reply body text (plain text)
        reply_all: If True, reply to all recipients (sender + To + Cc)
        quote_original: If True, include quoted original message in reply
        account: (Optional) Account to send from. If empty, auto-detects from original email.

    Returns:
        Sent message ID, thread ID, and account used
    """
    try:
        result = client.reply_to_email(
            message_id=message_id,
            body=body,
            reply_all=reply_all,
            quote_original=quote_original,
            account=account or None,
        )
        return result
    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def gmail_download_attachment(
    message_id: str,
    attachment_id: str,
    filename: str = "",
    save_path: str = "",
) -> dict:
    """
    Download an attachment from an email.

    Args:
        message_id: The email message ID (from gmail_list_emails or gmail_read_email)
        attachment_id: The attachment ID (from gmail_read_email response, in attachments list)
        filename: Original filename (from gmail_read_email attachments list).
            If not provided, will use 'attachment' as default.
        save_path: Optional path to save the file. If not provided, saves to ~/Downloads/
            with original filename.

    Returns:
        Dict with filename, size, and saved file path
    """
    try:
        from pathlib import Path as PathLib

        # Sanitize filename
        if not filename:
            filename = "attachment"
        filename = sanitize_filename(filename)

        # Download the data
        data = client.download_attachment(message_id, attachment_id)

        # Determine save path
        if save_path:
            file_path = PathLib(save_path).expanduser().resolve()
        else:
            downloads_dir = PathLib.home() / "Downloads"
            downloads_dir.mkdir(exist_ok=True)
            file_path = downloads_dir / filename

        # Handle filename conflicts
        if file_path.exists():
            base = file_path.stem
            suffix = file_path.suffix
            counter = 1
            while file_path.exists():
                file_path = file_path.parent / f"{base}_{counter}{suffix}"
                counter += 1

        # Save file
        file_path.write_bytes(data)

        return {
            "success": True,
            "filename": filename,
            "size": len(data),
            "saved_to": str(file_path),
        }

    except SecurityError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": sanitize_error_message(e)}


@mcp.tool()
def gmail_forward(
    message_id: str,
    to: str,
    body: str = "",
    include_attachments: bool = True,
    account: str = "",
) -> dict:
    """
    Forward an email to another recipient.

    Args:
        message_id: The email message ID to forward
        to: Recipient email address
        body: Optional message to prepend before forwarded content
        include_attachments: If True, include original attachments (default: True)
        account: (Optional) Account to send from. If empty, uses first available account.
            Consider using AskUserQuestion to let user choose.

    Returns:
        Sent message ID, thread ID, and account used
    """
    try:
        result = client.forward_email(
            message_id=message_id,
            to=to,
            body=body,
            include_attachments=include_attachments,
            account=account or None,
        )
        return result
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
