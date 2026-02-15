"""
Gmail API Client Wrapper

Provides a clean interface for Gmail API operations with integrated security.
All data stays local - we only call official Google APIs.

Threading implementation follows RFC 5322 and Gmail API best practices:
- https://developers.google.com/workspace/gmail/api/guides/threads
- https://datatracker.ietf.org/doc/html/rfc5322

Security features:
- Input validation on all public functions
- Rate limiting per account / operation
- Audit logging for sensitive operations (send, forward, delete)
- Error message sanitization to prevent credential leaks
- File size / MIME type validation for attachments
"""

import base64
import mimetypes
import re
from dataclasses import dataclass, field
from email import encoders
from email.header import Header
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, parseaddr

from googleapiclient.discovery import Resource, build

from .auth import get_authenticated_credentials, list_authenticated_accounts
from .security import (
    SecurityError,
    audit_log,
    rate_limiter,
    sanitize_error_message,
    sanitize_filename,
    validate_attachment_size,
    validate_body,
    validate_email,
    validate_email_list,
    validate_file_path,
    validate_gmail_query,
    validate_label_id,
    validate_message_id,
    validate_mime_type,
    validate_subject,
    validate_total_attachment_size,
)

# Module-level client cache - keyed by account email
_gmail_services: dict[str, Resource] = {}


@dataclass
class Attachment:
    """Email attachment metadata"""

    id: str
    filename: str
    mime_type: str
    size: int
    data: bytes | None = None


@dataclass
class Email:
    """Basic email metadata"""

    id: str
    thread_id: str
    snippet: str
    subject: str
    from_addr: str
    to_addr: str
    cc_addr: str
    date: str
    labels: list[str]
    is_unread: bool
    has_attachments: bool
    message_id: str  # RFC 5322 Message-ID header
    references: str  # RFC 5322 References header


@dataclass
class EmailDetail(Email):
    """Full email with body and attachments"""

    body: str = ""
    body_html: str | None = None
    attachments: list[Attachment] = field(default_factory=list)


@dataclass
class Label:
    """Gmail label"""

    id: str
    name: str
    type: str


# ---------------------------------------------------------------------------
# Service / account helpers
# ---------------------------------------------------------------------------


def get_gmail_service(account: str | None = None) -> Resource:
    """
    Get authenticated Gmail API service for a specific account.
    """
    global _gmail_services

    if account is None:
        accounts = list_authenticated_accounts()
        if not accounts:
            raise RuntimeError(
                "No authenticated Gmail accounts found. Run:\n"
                "  python -m childermass.gmail_mcp.auth --account=your@email.com"
            )
        account = accounts[0]
        if account == "default":
            account = None

    cache_key = account or "default"
    if cache_key in _gmail_services:
        return _gmail_services[cache_key]

    creds = get_authenticated_credentials(account)
    service = build("gmail", "v1", credentials=creds)
    _gmail_services[cache_key] = service
    return service


def get_account_email(account: str | None = None) -> str:
    """Get the email address for an authenticated account."""
    service = get_gmail_service(account)
    profile = service.users().getProfile(userId="me").execute()
    return profile.get("emailAddress", "")


def detect_account_from_email(email: EmailDetail) -> str | None:
    """
    Detect which authenticated account received an email.

    Checks To and Cc headers against all authenticated accounts.
    """
    accounts = list_authenticated_accounts()

    email_to_account: dict[str, str] = {}
    for acc in accounts:
        try:
            acc_param = None if acc == "default" else acc
            email_addr = get_account_email(acc_param)
            email_to_account[email_addr.lower()] = acc
        except Exception:
            continue

    all_recipients: list[str] = []
    if email.to_addr:
        all_recipients.extend([r.strip() for r in email.to_addr.split(",")])
    if email.cc_addr:
        all_recipients.extend([r.strip() for r in email.cc_addr.split(",")])

    for recipient in all_recipients:
        recipient_email = _extract_email_address(recipient).lower()
        if recipient_email in email_to_account:
            return email_to_account[recipient_email]

    return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_header(headers: list[dict], name: str) -> str:
    """Extract header value by name."""
    for header in headers:
        if header.get("name", "").lower() == name.lower():
            return header.get("value", "")
    return ""


def _decode_base64url(data: str) -> str:
    """Decode base64url encoded content."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data).decode("utf-8")


def _parse_message(msg: dict) -> Email:
    """Parse Gmail API message to Email object."""
    payload = msg.get("payload", {})
    headers = payload.get("headers", [])
    label_ids = msg.get("labelIds", [])

    has_attachments = False
    for part in payload.get("parts", []):
        if part.get("filename"):
            has_attachments = True
            break

    return Email(
        id=msg.get("id", ""),
        thread_id=msg.get("threadId", ""),
        snippet=msg.get("snippet", ""),
        subject=_get_header(headers, "Subject"),
        from_addr=_get_header(headers, "From"),
        to_addr=_get_header(headers, "To"),
        cc_addr=_get_header(headers, "Cc"),
        date=_get_header(headers, "Date"),
        labels=label_ids,
        is_unread="UNREAD" in label_ids,
        has_attachments=has_attachments,
        message_id=(
            _get_header(headers, "Message-ID")
            or _get_header(headers, "Message-Id")
        ),
        references=_get_header(headers, "References"),
    )


def _extract_body(payload: dict) -> tuple[str, str | None]:
    """Extract email body from message parts."""
    text = ""
    html = None

    def process_part(part: dict) -> None:
        nonlocal text, html

        mime_type = part.get("mimeType", "")
        body = part.get("body", {})
        data = body.get("data")

        if mime_type == "text/plain" and data:
            text = _decode_base64url(data)
        elif mime_type == "text/html" and data:
            html = _decode_base64url(data)

        for sub_part in part.get("parts", []):
            process_part(sub_part)

    process_part(payload)

    if not text and not html:
        body = payload.get("body", {})
        if body.get("data"):
            text = _decode_base64url(body["data"])

    return text, html


def _extract_attachments(payload: dict) -> list[Attachment]:
    """Extract attachment metadata from message payload."""
    attachments: list[Attachment] = []

    def process_parts(parts: list[dict]) -> None:
        for part in parts:
            filename = part.get("filename")
            body = part.get("body", {})
            attachment_id = body.get("attachmentId")

            if filename and attachment_id:
                attachments.append(
                    Attachment(
                        id=attachment_id,
                        filename=sanitize_filename(filename),
                        mime_type=part.get(
                            "mimeType", "application/octet-stream"
                        ),
                        size=body.get("size", 0),
                        data=None,
                    )
                )

            if part.get("parts"):
                process_parts(part["parts"])

    if payload.get("parts"):
        process_parts(payload["parts"])

    return attachments


def _extract_email_address(addr: str) -> str:
    """Extract email address from 'Name <email>' format."""
    match = re.search(r"<([^>]+)>", addr)
    return match.group(1) if match else addr.strip()


def _get_my_email(account: str | None = None) -> str:
    """Get authenticated user's email address."""
    return get_account_email(account)


def _encode_address(addr: str) -> str:
    """Encode a single email address for MIME headers (RFC 2047)."""
    name, email = parseaddr(addr)
    if name:
        return formataddr((str(Header(name, "utf-8")), email))
    return addr


def _encode_address_list(addrs: str) -> str:
    """Encode comma-separated email addresses for MIME headers."""
    return ", ".join(
        _encode_address(a.strip()) for a in addrs.split(",") if a.strip()
    )


# ---------------------------------------------------------------------------
# Read operations
# ---------------------------------------------------------------------------


def list_emails(
    query: str = "",
    max_results: int = 20,
    label_ids: list[str] | None = None,
    account: str | None = None,
) -> list[Email]:
    """
    List emails with optional query and labels.

    All inputs are validated and the operation is rate-limited.
    """
    # Validate inputs
    query = validate_gmail_query(query)
    max_results = min(max(1, max_results), 500)

    if label_ids:
        label_ids = [validate_label_id(lid) for lid in label_ids]

    # Rate limit
    acct_key = account or "default"
    rate_limiter.check(acct_key, "list")

    try:
        service = get_gmail_service(account)

        request_params: dict = {
            "userId": "me",
            "maxResults": max_results,
        }
        if query:
            request_params["q"] = query
        if label_ids:
            request_params["labelIds"] = label_ids

        response = (
            service.users().messages().list(**request_params).execute()
        )
        messages = response.get("messages", [])

        if not messages:
            return []

        emails: list[Email] = []
        for msg_ref in messages:
            msg = (
                service.users()
                .messages()
                .get(
                    userId="me",
                    id=msg_ref["id"],
                    format="metadata",
                    metadataHeaders=[
                        "From",
                        "To",
                        "Cc",
                        "Subject",
                        "Date",
                        "Message-ID",
                        "Message-Id",
                        "References",
                    ],
                )
                .execute()
            )
            emails.append(_parse_message(msg))

        audit_log("list_emails", acct_key, {"count": len(emails), "query": query})
        return emails

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def get_email(message_id: str, account: str | None = None) -> EmailDetail:
    """Get full email details."""
    message_id = validate_message_id(message_id)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "read")

    try:
        service = get_gmail_service(account)

        msg = (
            service.users()
            .messages()
            .get(userId="me", id=message_id, format="full")
            .execute()
        )

        basic = _parse_message(msg)
        payload = msg.get("payload", {})
        text, html = _extract_body(payload)
        attachments = _extract_attachments(payload)

        return EmailDetail(
            id=basic.id,
            thread_id=basic.thread_id,
            snippet=basic.snippet,
            subject=basic.subject,
            from_addr=basic.from_addr,
            to_addr=basic.to_addr,
            cc_addr=basic.cc_addr,
            date=basic.date,
            labels=basic.labels,
            is_unread=basic.is_unread,
            has_attachments=basic.has_attachments,
            message_id=basic.message_id,
            references=basic.references,
            body=text,
            body_html=html,
            attachments=attachments,
        )

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def search_emails(
    query: str, max_results: int = 20, account: str | None = None
) -> list[Email]:
    """Search emails using Gmail query syntax."""
    query = validate_gmail_query(query)
    acct_key = account or "default"
    rate_limiter.check(acct_key, "search")
    return list_emails(query=query, max_results=max_results, account=account)


# ---------------------------------------------------------------------------
# Attachment helpers (secured)
# ---------------------------------------------------------------------------


def _load_file_attachment(file_path: str) -> tuple[str, str, bytes]:
    """
    Load a file from disk as attachment.

    Validates path, size, and MIME type.

    Returns:
        (filename, mime_type, data)
    """
    # Validate path
    path = validate_file_path(file_path)

    # Validate size
    file_size = path.stat().st_size
    validate_attachment_size(file_size, path.name)

    # Detect and validate MIME type
    mime_type, _ = mimetypes.guess_type(str(path))
    if mime_type is None:
        mime_type = "application/octet-stream"
    mime_type = validate_mime_type(mime_type)

    # Read file data
    data = path.read_bytes()

    return sanitize_filename(path.name), mime_type, data


def _load_email_attachment(
    message_id: str,
    attachment_id: str,
) -> tuple[str, str, bytes]:
    """
    Load an attachment from an existing email.

    Returns:
        (filename, mime_type, data)
    """
    message_id = validate_message_id(message_id)

    email = get_email(message_id)

    att_meta = None
    for att in email.attachments:
        if att.id == attachment_id:
            att_meta = att
            break

    if att_meta is None:
        raise ValueError(
            f"Attachment {attachment_id} not found in message {message_id}"
        )

    # Validate MIME type
    validate_mime_type(att_meta.mime_type)

    data = download_attachment(message_id, attachment_id)

    return sanitize_filename(att_meta.filename), att_meta.mime_type, data


# ---------------------------------------------------------------------------
# Write operations (with full validation + audit)
# ---------------------------------------------------------------------------


def send_email(
    to: str,
    subject: str,
    body: str,
    cc: str | None = None,
    bcc: str | None = None,
    reply_to_message_id: str | None = None,
    attachment_paths: list[str] | None = None,
    forward_attachments: list[tuple[str, str]] | None = None,
    account: str | None = None,
) -> dict:
    """
    Send an email with optional attachments.

    All inputs are validated, rate-limited, and audit-logged.
    """
    # --- Input validation ---
    validate_email(to)
    subject = validate_subject(subject)
    body = validate_body(body)

    if cc:
        validate_email_list(cc)
    if bcc:
        validate_email_list(bcc)
    if reply_to_message_id:
        reply_to_message_id = validate_message_id(reply_to_message_id)

    # --- Rate limit ---
    acct_key = account or "default"
    rate_limiter.check(acct_key, "send")

    try:
        service = get_gmail_service(account)

        # Verify account
        actual_account = get_account_email(account)
        if account is not None and actual_account.lower() != account.lower():
            raise ValueError(
                f"Account mismatch: requested '{account}' but loaded "
                f"credentials are for '{actual_account}'. Re-authenticate."
            )
        account = actual_account

        # --- Collect & validate attachments ---
        attachments: list[tuple[str, str, bytes]] = []
        attachment_sizes: list[int] = []

        if attachment_paths:
            for file_path in attachment_paths:
                fname, mime, data = _load_file_attachment(file_path)
                attachments.append((fname, mime, data))
                attachment_sizes.append(len(data))

        if forward_attachments:
            for msg_id, att_id in forward_attachments:
                fname, mime, data = _load_email_attachment(msg_id, att_id)
                attachments.append((fname, mime, data))
                attachment_sizes.append(len(data))

        if attachment_sizes:
            validate_total_attachment_size(attachment_sizes)

        # --- Create message ---
        message = _create_message_with_attachments(
            to=to,
            subject=subject,
            body=body,
            from_addr=account,
            cc=cc,
            bcc=bcc,
            in_reply_to=reply_to_message_id,
            references=reply_to_message_id,
            attachments=attachments if attachments else None,
        )

        result = (
            service.users()
            .messages()
            .send(userId="me", body=message)
            .execute()
        )

        # --- Audit log ---
        audit_log(
            "send_email",
            account,
            {
                "to": to,
                "subject": subject[:80],
                "attachments": len(attachments),
            },
        )

        return {
            "id": result.get("id", ""),
            "thread_id": result.get("threadId", ""),
            "account": account,
        }

    except SecurityError:
        raise
    except Exception as e:
        audit_log("send_email", acct_key, {"error": str(e)[:100]}, success=False)
        raise RuntimeError(sanitize_error_message(e)) from None


def create_draft(
    to: str,
    subject: str,
    body: str,
    cc: str | None = None,
    bcc: str | None = None,
    attachment_paths: list[str] | None = None,
    forward_attachments: list[tuple[str, str]] | None = None,
    account: str | None = None,
) -> dict:
    """Create a draft email with optional attachments."""
    # Validate
    validate_email(to)
    subject = validate_subject(subject)
    body = validate_body(body)
    if cc:
        validate_email_list(cc)
    if bcc:
        validate_email_list(bcc)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "draft")

    try:
        service = get_gmail_service(account)

        attachments: list[tuple[str, str, bytes]] = []
        attachment_sizes: list[int] = []

        if attachment_paths:
            for file_path in attachment_paths:
                fname, mime, data = _load_file_attachment(file_path)
                attachments.append((fname, mime, data))
                attachment_sizes.append(len(data))

        if forward_attachments:
            for msg_id, att_id in forward_attachments:
                fname, mime, data = _load_email_attachment(msg_id, att_id)
                attachments.append((fname, mime, data))
                attachment_sizes.append(len(data))

        if attachment_sizes:
            validate_total_attachment_size(attachment_sizes)

        message = _create_message_with_attachments(
            to=to,
            subject=subject,
            body=body,
            cc=cc,
            bcc=bcc,
            attachments=attachments if attachments else None,
        )

        result = (
            service.users()
            .drafts()
            .create(userId="me", body={"message": message})
            .execute()
        )

        audit_log("create_draft", acct_key, {"to": to, "subject": subject[:80]})

        return {
            "id": result.get("id", ""),
            "message_id": result.get("message", {}).get("id", ""),
        }

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------


def list_labels(account: str | None = None) -> list[Label]:
    """List all Gmail labels."""
    try:
        service = get_gmail_service(account)
        response = service.users().labels().list(userId="me").execute()

        return [
            Label(
                id=label.get("id", ""),
                name=label.get("name", ""),
                type=label.get("type", "user"),
            )
            for label in response.get("labels", [])
        ]
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def modify_labels(
    message_id: str,
    add_label_ids: list[str] | None = None,
    remove_label_ids: list[str] | None = None,
    account: str | None = None,
) -> None:
    """Modify labels on a message."""
    message_id = validate_message_id(message_id)

    if add_label_ids:
        add_label_ids = [validate_label_id(lid) for lid in add_label_ids]
    if remove_label_ids:
        remove_label_ids = [validate_label_id(lid) for lid in remove_label_ids]

    acct_key = account or "default"
    rate_limiter.check(acct_key, "modify")

    try:
        service = get_gmail_service(account)

        body: dict = {}
        if add_label_ids:
            body["addLabelIds"] = add_label_ids
        if remove_label_ids:
            body["removeLabelIds"] = remove_label_ids

        service.users().messages().modify(
            userId="me", id=message_id, body=body
        ).execute()

        audit_log(
            "modify_labels",
            acct_key,
            {
                "message_id": message_id,
                "add": add_label_ids,
                "remove": remove_label_ids,
            },
        )

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def mark_as_read(message_id: str) -> None:
    """Mark email as read."""
    modify_labels(message_id, remove_label_ids=["UNREAD"])


def mark_as_unread(message_id: str) -> None:
    """Mark email as unread."""
    modify_labels(message_id, add_label_ids=["UNREAD"])


def archive_email(message_id: str) -> None:
    """Archive email (remove from inbox)."""
    modify_labels(message_id, remove_label_ids=["INBOX"])


# ---------------------------------------------------------------------------
# Reply & Forward (RFC 5322 compliant)
# ---------------------------------------------------------------------------


def _build_reply_recipients(
    original: EmailDetail,
    reply_all: bool,
    my_email: str,
) -> tuple[str, str | None]:
    """Build recipient list for reply."""
    to = original.from_addr

    if not reply_all:
        return to, None

    all_recipients: set[str] = set()

    for addr_field in [original.to_addr, original.cc_addr]:
        if addr_field:
            for addr in addr_field.split(","):
                email = _extract_email_address(addr.strip())
                if email.lower() != my_email.lower():
                    all_recipients.add(addr.strip())

    cc = ", ".join(all_recipients) if all_recipients else None
    return to, cc


def _build_references(original: EmailDetail) -> str:
    """Build References header per RFC 5322."""
    refs: list[str] = []
    if original.references:
        refs.append(original.references.strip())
    if original.message_id:
        refs.append(original.message_id.strip())
    return " ".join(refs)


def _quote_body(original: EmailDetail) -> str:
    """Format original email for quoting in reply."""
    quoted_lines = [f"> {line}" for line in original.body.split("\n")]
    quoted_text = "\n".join(quoted_lines)

    return (
        f"\n\n"
        f"---\n"
        f"On {original.date}, {original.from_addr} wrote:\n"
        f"{quoted_text}"
    )


def download_attachment(
    message_id: str,
    attachment_id: str,
    account: str | None = None,
) -> bytes:
    """Download attachment data from a message."""
    message_id = validate_message_id(message_id)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "download")

    try:
        service = get_gmail_service(account)

        result = (
            service.users()
            .messages()
            .attachments()
            .get(userId="me", messageId=message_id, id=attachment_id)
            .execute()
        )

        data = result.get("data", "")
        decoded = base64.urlsafe_b64decode(data)

        # Validate downloaded attachment size
        validate_attachment_size(len(decoded))

        audit_log(
            "download_attachment",
            acct_key,
            {"message_id": message_id, "size": len(decoded)},
        )

        return decoded

    except SecurityError:
        raise
    except Exception as e:
        raise RuntimeError(sanitize_error_message(e)) from None


def _create_message_with_attachments(
    to: str,
    subject: str,
    body: str,
    from_addr: str | None = None,
    cc: str | None = None,
    bcc: str | None = None,
    in_reply_to: str | None = None,
    references: str | None = None,
    attachments: list[tuple[str, str, bytes]] | None = None,
) -> dict:
    """Create email message with optional attachments."""
    message: MIMEMultipart | MIMEText
    if attachments:
        message = MIMEMultipart()
        message.attach(MIMEText(body, "plain"))

        for filename, mime_type, data in attachments:
            if "/" in mime_type:
                maintype, subtype = mime_type.split("/", 1)
            else:
                maintype, subtype = "application", "octet-stream"
            part = MIMEBase(maintype, subtype)
            part.set_payload(data)
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition", "attachment", filename=filename
            )
            message.attach(part)
    else:
        message = MIMEText(body, "plain")

    if from_addr:
        message["from"] = _encode_address(from_addr)
    message["to"] = _encode_address_list(to)
    message["subject"] = subject

    if cc:
        message["cc"] = _encode_address_list(cc)
    if bcc:
        message["bcc"] = _encode_address_list(bcc)
    if in_reply_to:
        message["In-Reply-To"] = in_reply_to
    if references:
        message["References"] = references

    raw = base64.urlsafe_b64encode(message.as_bytes()).decode("utf-8")
    return {"raw": raw}


def reply_to_email(
    message_id: str,
    body: str,
    reply_all: bool = False,
    quote_original: bool = True,
    account: str | None = None,
) -> dict:
    """
    Reply to an email, properly threading the conversation.

    Follows RFC 5322 for In-Reply-To and References headers.
    """
    # Validate
    message_id = validate_message_id(message_id)
    body = validate_body(body)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "reply")

    try:
        # Get original message
        original = get_email(message_id)

        # Auto-detect account
        if account is None:
            account = detect_account_from_email(original)
            if account is None:
                raise ValueError(
                    f"Could not detect which account received this email. "
                    f"To: {original.to_addr}, Cc: {original.cc_addr}. "
                    f"Please specify account parameter explicitly."
                )

        account_param = None if account == "default" else account

        service = get_gmail_service(account_param)
        my_email = _get_my_email(account_param)

        to, cc = _build_reply_recipients(original, reply_all, my_email)

        # Subject
        subject = original.subject
        if not subject.lower().startswith("re:"):
            subject = f"Re: {subject}"

        full_body = body
        if quote_original:
            full_body += _quote_body(original)

        # RFC 5322 threading headers
        in_reply_to = original.message_id
        references = _build_references(original)

        message = _create_message_with_attachments(
            to=to,
            subject=subject,
            body=full_body,
            from_addr=my_email,
            cc=cc,
            in_reply_to=in_reply_to,
            references=references,
        )

        # Ensure threading on sender's side
        message["threadId"] = original.thread_id

        result = (
            service.users()
            .messages()
            .send(userId="me", body=message)
            .execute()
        )

        audit_log(
            "reply_to_email",
            my_email,
            {
                "original_id": message_id,
                "reply_all": reply_all,
                "to": to,
            },
        )

        return {
            "id": result.get("id", ""),
            "thread_id": result.get("threadId", ""),
            "account": my_email,
        }

    except SecurityError:
        raise
    except Exception as e:
        audit_log(
            "reply_to_email", acct_key, {"error": str(e)[:100]}, success=False
        )
        raise RuntimeError(sanitize_error_message(e)) from None


def forward_email(
    message_id: str,
    to: str,
    body: str = "",
    include_attachments: bool = True,
    account: str | None = None,
) -> dict:
    """
    Forward an email to another recipient.

    Validates recipient, rate-limits, and audit-logs.
    """
    # Validate
    message_id = validate_message_id(message_id)
    validate_email(to)
    body = validate_body(body)

    acct_key = account or "default"
    rate_limiter.check(acct_key, "forward")

    try:
        service = get_gmail_service(account)

        actual_account = get_account_email(account)
        if account is not None and actual_account.lower() != account.lower():
            raise ValueError(
                f"Account mismatch: requested '{account}' but loaded "
                f"credentials are for '{actual_account}'. Re-authenticate."
            )
        account = actual_account

        original = get_email(message_id)

        subject = original.subject
        if not subject.lower().startswith("fwd:"):
            subject = f"Fwd: {subject}"

        forward_header = (
            f"\n\n"
            f"---------- Forwarded message ----------\n"
            f"From: {original.from_addr}\n"
            f"Date: {original.date}\n"
            f"Subject: {original.subject}\n"
            f"To: {original.to_addr}\n"
        )
        if original.cc_addr:
            forward_header += f"Cc: {original.cc_addr}\n"
        forward_header += f"\n{original.body}"

        full_body = body + forward_header

        # Download & validate attachments
        attachments_data: list[tuple[str, str, bytes]] = []
        attachment_sizes: list[int] = []

        if include_attachments and original.attachments:
            for att in original.attachments:
                validate_mime_type(att.mime_type)
                data = download_attachment(message_id, att.id, account)
                attachments_data.append(
                    (sanitize_filename(att.filename), att.mime_type, data)
                )
                attachment_sizes.append(len(data))

            if attachment_sizes:
                validate_total_attachment_size(attachment_sizes)

        message = _create_message_with_attachments(
            to=to,
            subject=subject,
            body=full_body,
            from_addr=account,
            attachments=attachments_data if attachments_data else None,
        )

        result = (
            service.users()
            .messages()
            .send(userId="me", body=message)
            .execute()
        )

        audit_log(
            "forward_email",
            account,
            {
                "original_id": message_id,
                "to": to,
                "attachments": len(attachments_data),
            },
        )

        return {
            "id": result.get("id", ""),
            "thread_id": result.get("threadId", ""),
            "account": account,
        }

    except SecurityError:
        raise
    except Exception as e:
        audit_log(
            "forward_email", acct_key, {"error": str(e)[:100]}, success=False
        )
        raise RuntimeError(sanitize_error_message(e)) from None
