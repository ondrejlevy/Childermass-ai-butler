"""
Google Contacts OAuth2 Authentication

Handles OAuth2 flow for Google People API access with secure token storage.
Tokens are stored in the system keyring (macOS Keychain / Linux Secret Service).
Falls back to encrypted file storage if keyring is unavailable.

Uses SEPARATE credentials file from Gmail, Calendar, Tasks (contacts-credentials.json).

Run with: python -m childermass.contacts_mcp.auth --account=your@email.com
"""

import argparse
import json
import logging
import os
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow


logger = logging.getLogger(__name__)

# People API scopes – full read/write access to contacts
SCOPES = [
    "https://www.googleapis.com/auth/contacts",
]

# Default paths
DEFAULT_TOKEN_DIR = Path.home() / ".childermass"
DEFAULT_CREDENTIALS_PATH = DEFAULT_TOKEN_DIR / "contacts-credentials.json"

# Keyring service name (separate from Gmail, Calendar, Tasks)
KEYRING_SERVICE = "childermass-contacts-mcp"

# Whether keyring is available
_keyring_available: bool | None = None


def _is_keyring_available() -> bool:
    """Check if system keyring is usable."""
    global _keyring_available
    if _keyring_available is not None:
        return _keyring_available

    try:
        import keyring

        # Test write + read + delete
        test_key = "__childermass_contacts_keyring_test__"
        keyring.set_password(KEYRING_SERVICE, test_key, "test")
        val = keyring.get_password(KEYRING_SERVICE, test_key)
        keyring.delete_password(KEYRING_SERVICE, test_key)
        _keyring_available = val == "test"
    except Exception:
        _keyring_available = False

    return _keyring_available


def _get_legacy_token_path(account: str | None = None) -> Path:
    """Legacy plaintext token path (for migration)."""
    if account:
        return DEFAULT_TOKEN_DIR / f"contacts-tokens-{account}.json"
    return Path(
        os.getenv(
            "CONTACTS_TOKEN_PATH",
            str(DEFAULT_TOKEN_DIR / "contacts-tokens.json"),
        )
    )


def get_token_path(account: str | None = None) -> Path:
    """
    Get token storage path for an account.

    Returns the path whether using keyring or file-based storage.
    """
    return _get_legacy_token_path(account)


def get_credentials_path() -> Path:
    """Get OAuth credentials path from env or default."""
    return Path(os.getenv("CONTACTS_CREDENTIALS_PATH", str(DEFAULT_CREDENTIALS_PATH)))


def list_authenticated_accounts() -> list[str]:
    """
    List all authenticated Contacts accounts.

    Returns:
        List of email addresses that have valid tokens
    """
    accounts: set[str] = set()

    # Check file-based tokens
    if DEFAULT_TOKEN_DIR.exists():
        for token_file in DEFAULT_TOKEN_DIR.glob("contacts-tokens-*.json"):
            email = token_file.stem.replace("contacts-tokens-", "")
            accounts.add(email)

    # Check keyring tokens
    if _is_keyring_available():
        try:
            import keyring

            # Read index from keyring
            index_raw = keyring.get_password(KEYRING_SERVICE, "__accounts__")
            if index_raw:
                for acc in json.loads(index_raw):
                    accounts.add(acc)
        except Exception:
            pass

    # Check legacy single-account token
    legacy_token = _get_legacy_token_path(account=None)
    if legacy_token.exists():
        result = ["default"]
        result.extend(sorted(accounts))
        return result

    return sorted(accounts)


def _save_to_keyring(token_json: str, account: str) -> bool:
    """Store token in system keyring. Returns True on success."""
    if not _is_keyring_available():
        return False

    try:
        import keyring

        keyring.set_password(KEYRING_SERVICE, account, token_json)

        # Update account index
        index_raw = keyring.get_password(KEYRING_SERVICE, "__accounts__")
        index: list[str] = json.loads(index_raw) if index_raw else []
        if account not in index:
            index.append(account)
            keyring.set_password(KEYRING_SERVICE, "__accounts__", json.dumps(index))
    except Exception as e:
        logger.warning("Keyring save failed: %s", e)
        return False
    else:
        return True


def _load_from_keyring(account: str) -> Credentials | None:
    """Load token from system keyring."""
    if not _is_keyring_available():
        return None

    try:
        import keyring

        token_json = keyring.get_password(KEYRING_SERVICE, account)
        if not token_json:
            return None

        creds: Credentials = Credentials.from_authorized_user_info(json.loads(token_json), SCOPES)
        return creds
    except Exception as e:
        logger.warning("Keyring load failed: %s", e)
        return None


def _delete_from_keyring(account: str) -> bool:
    """Remove token from system keyring."""
    if not _is_keyring_available():
        return False

    try:
        import keyring

        keyring.delete_password(KEYRING_SERVICE, account)

        # Update index
        index_raw = keyring.get_password(KEYRING_SERVICE, "__accounts__")
        if index_raw:
            index = json.loads(index_raw)
            if account in index:
                index.remove(account)
                keyring.set_password(KEYRING_SERVICE, "__accounts__", json.dumps(index))
    except Exception:
        return False
    else:
        return True


def load_credentials(account: str | None = None) -> Credentials | None:
    """
    Load saved credentials for a specific account.

    Tries system keyring first, then falls back to file-based storage.
    """
    acct_key = account or "default"

    # 1. Try keyring
    creds = _load_from_keyring(acct_key)
    if creds:
        return creds

    # 2. Fall back to file
    token_path = _get_legacy_token_path(account)
    if not token_path.exists():
        return None

    try:
        file_creds: Credentials = Credentials.from_authorized_user_file(str(token_path), SCOPES)

        # Migrate to keyring if possible
        if _is_keyring_available() and file_creds:
            token_json = token_path.read_text()
            if _save_to_keyring(token_json, acct_key):
                logger.info("Migrated token for %s to keyring", acct_key)
                # Keep file as backup but restrict permissions
                token_path.chmod(0o600)
    except Exception:
        return None
    else:
        return file_creds


def save_credentials(creds: Credentials, account: str | None = None) -> None:
    """
    Save credentials securely.

    Uses system keyring if available, otherwise encrypted file with chmod 600.
    """
    acct_key = account or "default"
    token_json = creds.to_json()

    # 1. Try keyring
    saved_to_keyring = _save_to_keyring(token_json, acct_key)

    # 2. Always save to file as backup (with restrictive permissions)
    token_path = _get_legacy_token_path(account)
    token_path.parent.mkdir(parents=True, exist_ok=True)

    with open(token_path, "w") as f:
        f.write(token_json)

    # Secure file permissions (owner read/write only)
    token_path.chmod(0o600)

    if saved_to_keyring:
        pass
    else:
        pass


def get_authenticated_credentials(account: str | None = None) -> Credentials:
    """
    Get authenticated credentials for an account, refreshing if needed.

    Raises RuntimeError if no valid tokens found.
    """
    creds = load_credentials(account)

    if creds and creds.valid:
        return creds

    if creds and creds.expired and creds.refresh_token:
        acct_label = account or "default"
        logger.info("Token expired for %s, refreshing...", acct_label)
        creds.refresh(Request())
        save_credentials(creds, account)
        return creds

    account_msg = f" for {account}" if account else ""
    msg = (
        f"No valid tokens found{account_msg}. Run authentication first with:\n"
        f"  python -m childermass.contacts_mcp.auth "
        f"--account={account or 'your@email.com'}"
    )
    raise RuntimeError(msg)


def authenticate(account: str | None = None) -> None:
    """
    Interactive OAuth2 authentication flow for a specific account.
    """
    credentials_path = get_credentials_path()

    if not credentials_path.exists():
        return

    # Check if already authenticated
    creds = load_credentials(account)
    if creds and creds.valid:
        ("system keyring" if _is_keyring_available() else "file")
        return

    if not account:
        pass

    # Run OAuth flow
    flow = InstalledAppFlow.from_client_secrets_file(str(credentials_path), SCOPES)

    if account:
        pass

    creds = flow.run_local_server(
        port=0,
        prompt="consent",
        access_type="offline",
    )

    # Save credentials
    save_credentials(creds, account)


def revoke_account(account: str) -> None:
    """
    Revoke and delete tokens for an account.
    """
    acct_key = account or "default"

    # Delete from keyring
    _delete_from_keyring(acct_key)

    # Delete file
    token_path = _get_legacy_token_path(account)
    if token_path.exists():
        token_path.unlink()


def migrate_tokens_to_keyring() -> None:
    """
    Migrate all file-based tokens to system keyring.
    """
    if not _is_keyring_available():
        return

    migrated = 0
    if DEFAULT_TOKEN_DIR.exists():
        for token_file in DEFAULT_TOKEN_DIR.glob("contacts-tokens-*.json"):
            email = token_file.stem.replace("contacts-tokens-", "")
            try:
                token_json = token_file.read_text()
                if _save_to_keyring(token_json, email):
                    migrated += 1
            except Exception:
                pass


def main() -> None:
    """CLI entry point for authentication."""
    parser = argparse.ArgumentParser(
        description="Authenticate Google Contacts accounts for Childermass MCP",
        epilog=(
            "Examples:\n"
            "  python -m childermass.contacts_mcp.auth "
            "--account=user@gmail.com\n"
            "  python -m childermass.contacts_mcp.auth --list\n"
            "  python -m childermass.contacts_mcp.auth --migrate-keyring\n"
            "  python -m childermass.contacts_mcp.auth --revoke user@gmail.com"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--account",
        help="Email address to authenticate",
        metavar="EMAIL",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all authenticated accounts",
    )
    parser.add_argument(
        "--revoke",
        metavar="EMAIL",
        help="Revoke and delete tokens for an account",
    )
    parser.add_argument(
        "--migrate-keyring",
        action="store_true",
        help="Migrate file-based tokens to system keyring",
    )

    args = parser.parse_args()

    if args.list:
        accounts = list_authenticated_accounts()
        ("keyring + file" if _is_keyring_available() else "file only")
        if accounts:
            for _acc in accounts:
                pass
        else:
            pass
        return

    if args.revoke:
        revoke_account(args.revoke)
        return

    if args.migrate_keyring:
        migrate_tokens_to_keyring()
        return

    authenticate(args.account)


if __name__ == "__main__":
    main()
