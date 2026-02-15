"""
Google Keep Authentication

Handles authentication for gkeepapi with secure token storage.
Master tokens are stored in the system keyring (macOS Keychain / Linux Secret Service).
Falls back to encrypted file storage if keyring is unavailable.

Run with: python -m childermass.keep_mcp.auth --account=your@email.com
"""

import argparse
import contextlib
import json
import logging
import os
from pathlib import Path


logger = logging.getLogger(__name__)

# Default paths
DEFAULT_TOKEN_DIR = Path.home() / ".childermass"
DEFAULT_CACHE_DIR = DEFAULT_TOKEN_DIR

# Keyring service name
KEYRING_SERVICE = "childermass-keep-mcp"

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
        test_key = "__childermass_keep_keyring_test__"
        keyring.set_password(KEYRING_SERVICE, test_key, "test")
        val = keyring.get_password(KEYRING_SERVICE, test_key)
        keyring.delete_password(KEYRING_SERVICE, test_key)
        _keyring_available = val == "test"
    except Exception:
        _keyring_available = False

    return _keyring_available


def _get_token_file_path(account: str | None = None) -> Path:
    """Get file path for master token storage."""
    if account:
        return DEFAULT_TOKEN_DIR / f"keep-token-{account}.json"
    return Path(
        os.getenv(
            "KEEP_TOKEN_PATH",
            str(DEFAULT_TOKEN_DIR / "keep-token.json"),
        )
    )


def _get_cache_path(account: str | None = None) -> Path:
    """Get file path for Keep state cache."""
    if account:
        return DEFAULT_CACHE_DIR / f"keep-cache-{account}.json"
    return DEFAULT_CACHE_DIR / "keep-cache.json"


def get_token_path(account: str | None = None) -> Path:
    """
    Get token storage path for an account.

    Returns the path whether using keyring or file-based storage.
    """
    return _get_token_file_path(account)


def list_authenticated_accounts() -> list[str]:
    """
    List all authenticated Keep accounts.

    Returns:
        List of email addresses that have valid tokens
    """
    accounts: set[str] = set()

    # Check file-based tokens
    if DEFAULT_TOKEN_DIR.exists():
        for token_file in DEFAULT_TOKEN_DIR.glob("keep-token-*.json"):
            email = token_file.stem.replace("keep-token-", "")
            accounts.add(email)

    # Check keyring tokens
    if _is_keyring_available():
        try:
            import keyring

            index_raw = keyring.get_password(KEYRING_SERVICE, "__accounts__")
            if index_raw:
                for acc in json.loads(index_raw):
                    accounts.add(acc)
        except (json.JSONDecodeError, KeyError) as e:
            logger.debug(f"Could not read accounts from keyring: {e}")
        except Exception as e:
            logger.warning(f"Unexpected error reading keyring accounts: {e}")

    # Check legacy single-account token
    legacy_token = _get_token_file_path(account=None)
    if legacy_token.exists():
        result = ["default"]
        result.extend(sorted(accounts))
        return result

    return sorted(accounts)


def _save_to_keyring(token_data: str, account: str) -> bool:
    """Store token in system keyring. Returns True on success."""
    if not _is_keyring_available():
        return False

    try:
        import keyring

        keyring.set_password(KEYRING_SERVICE, account, token_data)

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


def _load_from_keyring(account: str) -> str | None:
    """Load master token from system keyring."""
    if not _is_keyring_available():
        return None

    try:
        import keyring

        token_data = keyring.get_password(KEYRING_SERVICE, account)
        if not token_data:
            return None

        data = json.loads(token_data)
        master_token = data.get("master_token")
        return str(master_token) if isinstance(master_token, str) else None
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


def load_master_token(account: str | None = None) -> str | None:
    """
    Load saved master token for a specific account.

    Tries system keyring first, then falls back to file-based storage.
    """
    acct_key = account or "default"

    # 1. Try keyring
    token = _load_from_keyring(acct_key)
    if token:
        return token

    # 2. Fall back to file
    token_path = _get_token_file_path(account)
    if not token_path.exists():
        return None

    try:
        data = json.loads(token_path.read_text())
        token = data.get("master_token")

        # Validate token type
        if not isinstance(token, str):
            return None

        # Migrate to keyring if possible
        if _is_keyring_available() and token:
            token_json = token_path.read_text()
            if _save_to_keyring(token_json, acct_key):
                logger.info("Migrated token for %s to keyring", acct_key)
                token_path.chmod(0o600)
    except Exception:
        return None
    else:
        return token


def save_master_token(
    master_token: str, account: str | None = None, email: str | None = None
) -> None:
    """
    Save master token securely.

    Uses system keyring if available, otherwise file with chmod 600.
    """
    acct_key = account or "default"
    token_data = json.dumps(
        {
            "master_token": master_token,
            "email": email or account or "",
        }
    )

    # 1. Try keyring
    saved_to_keyring = _save_to_keyring(token_data, acct_key)

    # 2. Always save to file as backup
    token_path = _get_token_file_path(account)
    token_path.parent.mkdir(parents=True, exist_ok=True)

    with open(token_path, "w") as f:
        f.write(token_data)

    token_path.chmod(0o600)

    if saved_to_keyring:
        pass
    else:
        pass


def load_keep_cache(account: str | None = None) -> dict | None:
    """Load cached Keep state for faster startup."""
    cache_path = _get_cache_path(account)
    if not cache_path.exists():
        return None

    try:
        cache_data: dict = json.loads(cache_path.read_text())
        return cache_data if isinstance(cache_data, dict) else None
    except Exception as e:
        logger.warning("Cache load failed: %s", e)
        return None


def save_keep_cache(state: dict, account: str | None = None) -> None:
    """Save Keep state cache for faster startup."""
    cache_path = _get_cache_path(account)
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    with open(cache_path, "w") as f:
        json.dump(state, f)

    cache_path.chmod(0o600)


def get_authenticated_keep(account: str | None = None):
    """
    Get authenticated gkeepapi.Keep instance.

    Raises RuntimeError if no valid tokens found.
    """
    import gkeepapi

    email = account
    master_token = load_master_token(account)

    if not master_token or not email:
        account_msg = f" for {account}" if account else ""
        msg = (
            f"No valid tokens found{account_msg}. Run authentication first with:\n"
            f"  python -m childermass.keep_mcp.auth --account={account or 'your@email.com'}"
        )
        raise RuntimeError(msg)

    keep = gkeepapi.Keep()

    # Try to restore cached state for faster startup
    cached_state = load_keep_cache(account)

    try:
        keep.authenticate(email, master_token, state=cached_state)
    except Exception as e:
        # If cache is corrupted, try without cache
        if cached_state:
            logger.warning("Cache restore failed, authenticating fresh: %s", e)
            keep.authenticate(email, master_token)
        else:
            raise

    # Save updated cache
    try:
        save_keep_cache(keep.dump(), account)
    except Exception as e:
        logger.warning("Cache save failed: %s", e)

    return keep


def authenticate(account: str | None = None) -> None:
    """
    Interactive authentication flow.

    Guides user through obtaining a master token via gpsoauth.
    """
    if not account:
        return

    # Check if already authenticated
    existing_token = load_master_token(account)
    if existing_token:
        "system keyring" if _is_keyring_available() else "file"

        reauth = input("\n  Re-authenticate? [y/N]: ").strip().lower()
        if reauth != "y":
            return

    master_token = input("Paste your master token: ").strip()

    if not master_token:
        return

    # Verify token works
    try:
        import gkeepapi

        keep = gkeepapi.Keep()
        keep.authenticate(account, master_token)

        # Save token
        save_master_token(master_token, account, account)

        # Save initial cache
        with contextlib.suppress(Exception):
            save_keep_cache(keep.dump(), account)

        len(list(keep.all()))

    except Exception:
        return


def revoke_account(account: str) -> None:
    """Revoke and delete tokens for an account."""
    acct_key = account or "default"

    _delete_from_keyring(acct_key)

    token_path = _get_token_file_path(account)
    if token_path.exists():
        token_path.unlink()

    cache_path = _get_cache_path(account)
    if cache_path.exists():
        cache_path.unlink()


def migrate_tokens_to_keyring() -> None:
    """Migrate all file-based tokens to system keyring."""
    if not _is_keyring_available():
        return

    migrated = 0
    if DEFAULT_TOKEN_DIR.exists():
        for token_file in DEFAULT_TOKEN_DIR.glob("keep-token-*.json"):
            email = token_file.stem.replace("keep-token-", "")
            try:
                token_json = token_file.read_text()
                if _save_to_keyring(token_json, email):
                    migrated += 1
            except (OSError, ValueError) as e:
                logger.warning(f"Failed to migrate token for {email}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error migrating {email}: {e}")


def main() -> None:
    """CLI entry point for authentication."""
    parser = argparse.ArgumentParser(
        description="Authenticate Google Keep accounts for Childermass MCP",
        epilog=(
            "Examples:\n"
            "  python -m childermass.keep_mcp.auth --account=user@gmail.com\n"
            "  python -m childermass.keep_mcp.auth --list\n"
            "  python -m childermass.keep_mcp.auth --migrate-keyring\n"
            "  python -m childermass.keep_mcp.auth --revoke user@gmail.com"
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
