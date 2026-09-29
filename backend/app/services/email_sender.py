from dotenv import load_dotenv

load_dotenv()

import base64
import hashlib
import html
import imaplib
import json
import os
import re
import secrets
import smtplib
import socket
import sqlite3
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
from typing import Any


MAX_CONFIGURED_ACCOUNTS = 20
OAUTH_STATE_TTL_SECONDS = 600
OAUTH_HTTP_TIMEOUT_SECONDS = 30

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "mailboxes.db"

_active_account_id: str | None = None
_attached_account_ids: set[str] = set()

# OAuth authorization state is deliberately kept server-side.
# The state is short-lived and single-use.
_oauth_pending: dict[str, dict[str, Any]] = {}


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _account_id_for_email(
    email: str,
    index: int | None = None,
) -> str:
    normalized = email.strip().lower()

    if index is not None:
        return f"account-{index}"

    safe = re.sub(
        r"[^a-z0-9]+",
        "-",
        normalized,
    ).strip("-")

    return f"account-{safe}"


def _account_id_for_connection(
    email: str,
    smtp_host: str,
    smtp_port: int,
) -> str:
    identity = (
        f"{email.strip().lower()}|"
        f"{smtp_host.strip().lower()}|"
        f"{int(smtp_port)}"
    )

    digest = hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()[:20]

    return f"mailbox-{digest}"


def _provider_from_host(host: str) -> str:
    normalized = host.lower()

    if "gmail" in normalized:
        return "Gmail"

    if (
        "outlook" in normalized
        or "office365" in normalized
        or "microsoft" in normalized
    ):
        return "Microsoft"

    if "yahoo" in normalized:
        return "Yahoo"

    return "Custom SMTP"


def _normalize_provider(
    provider: Any,
) -> str:
    normalized = _clean(provider).lower()

    if normalized in {
        "google",
        "gmail",
    }:
        return "Gmail"

    if normalized in {
        "microsoft",
        "outlook",
        "office365",
        "microsoft 365",
    }:
        return "Microsoft"

    if normalized in {
        "custom",
        "custom smtp",
        "smtp",
        "",
    }:
        return "Custom SMTP"

    return _clean(provider)


def _normalize_security_mode(
    value: Any,
    smtp_port: int,
) -> str:
    normalized = _clean(value).lower()

    aliases = {
        "starttls": "starttls",
        "start_tls": "starttls",
        "tls": "tls",
        "ssl": "tls",
        "implicit_tls": "tls",
        "none": "none",
        "plain": "none",
        "": "",
    }

    mode = aliases.get(
        normalized,
        "",
    )

    if mode:
        return mode

    if smtp_port == 465:
        return "tls"

    if smtp_port in {
        25,
        587,
    }:
        return "starttls"

    return "starttls"


def _parse_port(value: Any) -> int:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return 587

    if port < 1 or port > 65535:
        return 587

    return port


_database_ready = False


def _ensure_database() -> None:
    global _database_ready

    # Schema creation/migration only needs to run once per process.
    # Running it on every lookup caused needless writes and
    # "database is locked" errors under concurrent requests.
    if _database_ready and DATABASE_PATH.exists():
        return

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS mailbox_accounts (
                account_id TEXT PRIMARY KEY,
                sender_email TEXT NOT NULL UNIQUE,
                username TEXT,
                password TEXT NOT NULL DEFAULT '',
                smtp_host TEXT NOT NULL,
                smtp_port INTEGER NOT NULL,
                smtp_tls INTEGER NOT NULL DEFAULT 1,
                security_mode TEXT NOT NULL DEFAULT 'starttls',
                provider TEXT NOT NULL,
                auth_type TEXT NOT NULL DEFAULT 'smtp_password',
                access_token TEXT,
                refresh_token TEXT,
                token_expires_at REAL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(mailbox_accounts)"
            ).fetchall()
        }

        migrations = {
            "username": """
                ALTER TABLE mailbox_accounts
                ADD COLUMN username TEXT
            """,
            "security_mode": """
                ALTER TABLE mailbox_accounts
                ADD COLUMN security_mode TEXT
            """,
            "auth_type": """
                ALTER TABLE mailbox_accounts
                ADD COLUMN auth_type TEXT
                DEFAULT 'smtp_password'
            """,
            "access_token": """
                ALTER TABLE mailbox_accounts
                ADD COLUMN access_token TEXT
            """,
            "refresh_token": """
                ALTER TABLE mailbox_accounts
                ADD COLUMN refresh_token TEXT
            """,
            "token_expires_at": """
                ALTER TABLE mailbox_accounts
                ADD COLUMN token_expires_at REAL
            """,
        }

        for column_name, statement in migrations.items():
            if column_name not in columns:
                connection.execute(statement)

        connection.execute(
            """
            UPDATE mailbox_accounts
            SET username = sender_email
            WHERE username IS NULL
               OR TRIM(username) = ''
            """
        )

        connection.execute(
            """
            UPDATE mailbox_accounts
            SET security_mode =
                CASE
                    WHEN smtp_port = 465 THEN 'tls'
                    WHEN smtp_tls = 1 THEN 'starttls'
                    ELSE 'none'
                END
            WHERE security_mode IS NULL
               OR TRIM(security_mode) = ''
            """
        )

        connection.execute(
            """
            UPDATE mailbox_accounts
            SET auth_type = 'smtp_password'
            WHERE auth_type IS NULL
               OR TRIM(auth_type) = ''
            """
        )

        # Attach/connect state and pending OAuth sessions used to live
        # only in memory, so every backend reload silently disconnected
        # the mailbox and broke in-flight OAuth logins.
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS mailbox_state (
                account_id TEXT PRIMARY KEY,
                attached INTEGER NOT NULL DEFAULT 0,
                active INTEGER NOT NULL DEFAULT 0
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS oauth_pending (
                state TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )

        connection.commit()

    _database_ready = True


def _persist_mailbox_state() -> None:
    _ensure_database()

    with sqlite3.connect(
        DATABASE_PATH
    ) as connection:
        connection.execute(
            "DELETE FROM mailbox_state"
        )

        connection.executemany(
            """
            INSERT INTO mailbox_state (
                account_id,
                attached,
                active
            )
            VALUES (?, 1, ?)
            """,
            [
                (
                    account_id,
                    1
                    if account_id == _active_account_id
                    else 0,
                )
                for account_id in _attached_account_ids
            ],
        )

        connection.commit()


def _restore_mailbox_state() -> None:
    global _active_account_id

    try:
        _ensure_database()

        with sqlite3.connect(
            DATABASE_PATH
        ) as connection:
            rows = connection.execute(
                """
                SELECT account_id, attached, active
                FROM mailbox_state
                """
            ).fetchall()

    except sqlite3.Error:
        return

    for account_id, attached, active in rows:
        if attached:
            _attached_account_ids.add(
                account_id
            )

        if active:
            _active_account_id = account_id


def _store_oauth_state(
    state: str,
    payload: dict[str, Any],
) -> None:
    _oauth_pending[state] = payload

    try:
        _ensure_database()

        with sqlite3.connect(
            DATABASE_PATH
        ) as connection:
            connection.execute(
                """
                DELETE FROM oauth_pending
                WHERE created_at < ?
                """,
                (
                    time.time()
                    - OAUTH_STATE_TTL_SECONDS,
                ),
            )

            connection.execute(
                """
                INSERT OR REPLACE INTO oauth_pending (
                    state,
                    payload,
                    created_at
                )
                VALUES (?, ?, ?)
                """,
                (
                    state,
                    json.dumps(payload),
                    float(
                        payload.get(
                            "created_at",
                            time.time(),
                        )
                    ),
                ),
            )

            connection.commit()

    except sqlite3.Error:
        pass


def _pop_oauth_state(
    state: str,
) -> dict[str, Any] | None:
    pending = _oauth_pending.pop(
        state,
        None,
    )

    try:
        _ensure_database()

        with sqlite3.connect(
            DATABASE_PATH
        ) as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM oauth_pending
                WHERE state = ?
                """,
                (state,),
            ).fetchone()

            connection.execute(
                """
                DELETE FROM oauth_pending
                WHERE state = ?
                """,
                (state,),
            )

            connection.commit()

        if pending is None and row:
            pending = json.loads(row[0])

    except (sqlite3.Error, json.JSONDecodeError):
        pass

    return pending


def _database_account(
    row: sqlite3.Row,
) -> dict[str, Any]:
    smtp_port = int(
        row["smtp_port"]
    )

    security_mode = _normalize_security_mode(
        row["security_mode"],
        smtp_port,
    )

    auth_type = _clean(
        row["auth_type"]
    ).lower()

    if auth_type not in {
        "oauth",
        "smtp_password",
    }:
        auth_type = "smtp_password"

    sender_email = _clean(row["sender_email"])
    username = _clean(row["username"])

    # Gmail-style providers require the full email address as the
    # login name; fall back to the sender email when only a bare
    # mailbox name was saved.
    if username and "@" not in username and "@" in sender_email:
        username = sender_email

    return {
        "account_id": row["account_id"],
        "sender_email": sender_email,
        "username": username or sender_email,
        "password": row["password"] or "",
        "smtp_host": row["smtp_host"],
        "smtp_port": smtp_port,
        "smtp_tls": (
            security_mode == "starttls"
        ),
        "security_mode": security_mode,
        "provider": row["provider"],
        "auth_type": auth_type,
        "access_token": row["access_token"],
        "refresh_token": row["refresh_token"],
        "token_expires_at": (
            float(row["token_expires_at"])
            if row["token_expires_at"] is not None
            else None
        ),
    }


def _load_persistent_accounts() -> list[dict[str, Any]]:
    _ensure_database()

    with sqlite3.connect(
        DATABASE_PATH
    ) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                account_id,
                sender_email,
                username,
                password,
                smtp_host,
                smtp_port,
                smtp_tls,
                security_mode,
                provider,
                auth_type,
                access_token,
                refresh_token,
                token_expires_at
            FROM mailbox_accounts
            ORDER BY created_at ASC
            """
        ).fetchall()

    return [
        _database_account(row)
        for row in rows
    ]


def _save_persistent_account(
    account: dict[str, Any],
) -> None:
    _ensure_database()

    with sqlite3.connect(
        DATABASE_PATH
    ) as connection:
        connection.execute(
            """
            INSERT INTO mailbox_accounts (
                account_id,
                sender_email,
                username,
                password,
                smtp_host,
                smtp_port,
                smtp_tls,
                security_mode,
                provider,
                auth_type,
                access_token,
                refresh_token,
                token_expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                account["account_id"],
                account["sender_email"],
                account["username"],
                account.get("password", ""),
                account["smtp_host"],
                account["smtp_port"],
                1
                if account["smtp_tls"]
                else 0,
                account["security_mode"],
                account["provider"],
                account.get(
                    "auth_type",
                    "smtp_password",
                ),
                account.get("access_token"),
                account.get("refresh_token"),
                account.get("token_expires_at"),
            ),
        )

        connection.commit()


def _update_oauth_account(
    account: dict[str, Any],
) -> None:
    _ensure_database()

    with sqlite3.connect(
        DATABASE_PATH
    ) as connection:
        connection.execute(
            """
            UPDATE mailbox_accounts
            SET
                sender_email = ?,
                username = ?,
                password = '',
                smtp_host = ?,
                smtp_port = ?,
                smtp_tls = ?,
                security_mode = ?,
                provider = ?,
                auth_type = 'oauth',
                access_token = ?,
                refresh_token = ?,
                token_expires_at = ?
            WHERE account_id = ?
            """,
            (
                account["sender_email"],
                account["username"],
                account["smtp_host"],
                account["smtp_port"],
                1
                if account["smtp_tls"]
                else 0,
                account["security_mode"],
                account["provider"],
                account["access_token"],
                account["refresh_token"],
                account["token_expires_at"],
                account["account_id"],
            ),
        )

        connection.commit()


def _public_account(
    config: dict[str, Any],
) -> dict[str, Any]:
    auth_type = config.get(
        "auth_type",
        "smtp_password",
    )

    return {
        "account_id": config["account_id"],
        "sender_email": config["sender_email"],
        "username": config.get(
            "username",
            config["sender_email"],
        ),
        "provider": config["provider"],
        "connection_type": (
            "oauth"
            if auth_type == "oauth"
            else "smtp"
        ),
        "authentication": (
            "oauth"
            if auth_type == "oauth"
            else "credential"
        ),
        "smtp": {
            "host": config["smtp_host"],
            "port": config["smtp_port"],
            "tls": config.get(
                "smtp_tls",
                config.get(
                    "security_mode"
                ) == "starttls",
            ),
            "security_mode": config.get(
                "security_mode",
                "starttls",
            ),
        },
        "attached": (
            config["account_id"]
            in _attached_account_ids
        ),
        "connected": (
            config["account_id"]
            == _active_account_id
        ),
    }


def _load_account_configs() -> list[dict[str, Any]]:
    accounts: list[dict[str, Any]] = []

    seen_accounts: set[
        tuple[str, str, int]
    ] = set()

    for index in range(
        1,
        MAX_CONFIGURED_ACCOUNTS + 1,
    ):
        email = _clean(
            os.getenv(
                f"SECUREMAILSCOPE_ACCOUNT_{index}_EMAIL"
            )
        )

        password = _clean(
            os.getenv(
                f"SECUREMAILSCOPE_ACCOUNT_{index}_PASSWORD"
            )
        )

        if not email or not password:
            continue

        username = _clean(
            os.getenv(
                f"SECUREMAILSCOPE_ACCOUNT_{index}_USERNAME"
            )
        ) or email

        host = _clean(
            os.getenv(
                f"SECUREMAILSCOPE_ACCOUNT_{index}_SMTP_HOST"
            )
        ) or "smtp.gmail.com"

        port = _parse_port(
            os.getenv(
                f"SECUREMAILSCOPE_ACCOUNT_{index}_SMTP_PORT"
            )
        )

        security_mode = _normalize_security_mode(
            os.getenv(
                f"SECUREMAILSCOPE_ACCOUNT_{index}_SECURITY"
            ),
            port,
        )

        provider = _normalize_provider(
            os.getenv(
                f"SECUREMAILSCOPE_ACCOUNT_{index}_PROVIDER"
            )
        )

        if provider == "Custom SMTP":
            provider = _provider_from_host(host)

        identity = (
            email.lower(),
            host.lower(),
            port,
        )

        if identity in seen_accounts:
            continue

        seen_accounts.add(identity)

        accounts.append(
            {
                "account_id": _account_id_for_email(
                    email,
                    index,
                ),
                "sender_email": email,
                "username": username,
                "password": password,
                "smtp_host": host,
                "smtp_port": port,
                "smtp_tls": (
                    security_mode == "starttls"
                ),
                "security_mode": security_mode,
                "provider": provider,
                "auth_type": "smtp_password",
                "access_token": None,
                "refresh_token": None,
                "token_expires_at": None,
            }
        )

    legacy_email = _clean(
        os.getenv(
            "SECUREMAILSCOPE_SENDER_EMAIL"
        )
    )

    legacy_password = _clean(
        os.getenv(
            "SECUREMAILSCOPE_SMTP_PASSWORD"
        )
    )

    if legacy_email and legacy_password:
        legacy_host = _clean(
            os.getenv(
                "SECUREMAILSCOPE_SMTP_HOST"
            )
        ) or "smtp.gmail.com"

        legacy_port = _parse_port(
            os.getenv(
                "SECUREMAILSCOPE_SMTP_PORT"
            )
        )

        identity = (
            legacy_email.lower(),
            legacy_host.lower(),
            legacy_port,
        )

        if identity not in seen_accounts:
            security_mode = _normalize_security_mode(
                os.getenv(
                    "SECUREMAILSCOPE_SMTP_SECURITY"
                ),
                legacy_port,
            )

            accounts.append(
                {
                    "account_id": _account_id_for_email(
                        legacy_email
                    ),
                    "sender_email": legacy_email,
                    "username": legacy_email,
                    "password": legacy_password,
                    "smtp_host": legacy_host,
                    "smtp_port": legacy_port,
                    "smtp_tls": (
                        security_mode == "starttls"
                    ),
                    "security_mode": security_mode,
                    "provider": _provider_from_host(
                        legacy_host
                    ),
                    "auth_type": "smtp_password",
                    "access_token": None,
                    "refresh_token": None,
                    "token_expires_at": None,
                }
            )

    return accounts


def _all_account_configs() -> list[dict[str, Any]]:
    configured = _load_account_configs()

    configured_ids = {
        account["account_id"]
        for account in configured
    }

    for account in _load_persistent_accounts():
        if account["account_id"] not in configured_ids:
            configured.append(account)

    return configured


def _find_any_account(
    account_id: str,
) -> dict[str, Any] | None:
    for account in _all_account_configs():
        if account["account_id"] == account_id:
            return account

    return None


def _find_configured_account(
    account_id: str,
) -> dict[str, Any] | None:
    return _find_any_account(account_id)


def list_all_mailboxes() -> list[dict[str, Any]]:
    return [
        _public_account(account)
        for account in _all_account_configs()
    ]


def list_attached_mailboxes() -> list[dict[str, Any]]:
    return [
        _public_account(account)
        for account in _all_account_configs()
        if account["account_id"]
        in _attached_account_ids
    ]


def list_available_mailboxes() -> list[dict[str, Any]]:
    return [
        _public_account(account)
        for account in _all_account_configs()
        if account["account_id"]
        not in _attached_account_ids
    ]


def add_mailbox(
    *,
    sender_email: str,
    username: str | None = None,
    password: str,
    smtp_host: str,
    smtp_port: int,
    security_mode: str | None = None,
    provider: str | None = None,
) -> dict[str, Any]:
    sender_email = _clean(sender_email)
    username = _clean(username) or sender_email
    password = _clean(password)
    smtp_host = _clean(smtp_host)
    provider = _normalize_provider(provider)

    if not sender_email:
        return {
            "status": "invalid",
            "message": "Email address is required.",
        }

    if not username:
        return {
            "status": "invalid",
            "message": "Username is required.",
        }

    if not password:
        return {
            "status": "invalid",
            "message": (
                "Password / credential is required "
                "for custom SMTP accounts."
            ),
        }

    if not smtp_host:
        return {
            "status": "invalid",
            "message": "SMTP host is required.",
        }

    smtp_port = _parse_port(smtp_port)

    security_mode = _normalize_security_mode(
        security_mode,
        smtp_port,
    )

    if security_mode not in {
        "starttls",
        "tls",
        "none",
    }:
        return {
            "status": "invalid",
            "message": (
                "Security mode must be STARTTLS, TLS, or None."
            ),
        }

    if provider == "Custom SMTP":
        provider = _provider_from_host(
            smtp_host
        )

    # Provider SMTP (smtp.gmail.com, smtp.office365.com, ...) is allowed
    # with a provider App Password. Blocking it here made it impossible
    # to add any Gmail mailbox unless OAuth client credentials were
    # configured, which left the app unable to send at all. If the
    # credential is an ordinary password instead of an App Password the
    # SMTP authentication step fails with a specific error message.
    if provider == "Gmail":
        guidance = (
            " Gmail requires an App Password: enable 2-Step "
            "Verification, then create one under Google Account → "
            "Security → App passwords."
        )
    elif provider == "Microsoft":
        guidance = (
            " Microsoft requires SMTP AUTH to be enabled for the "
            "mailbox and an App Password where basic auth is "
            "restricted."
        )
    else:
        guidance = ""

    account_id = _account_id_for_connection(
        sender_email,
        smtp_host,
        smtp_port,
    )

    existing = _find_any_account(
        account_id
    )

    if existing:
        return {
            "status": "exists",
            "account": _public_account(
                existing
            ),
            "message": (
                "A mailbox with this SMTP connection "
                "already exists."
            ),
        }

    account = {
        "account_id": account_id,
        "sender_email": sender_email,
        "username": username,
        "password": password,
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "smtp_tls": (
            security_mode == "starttls"
        ),
        "security_mode": security_mode,
        "provider": provider,
        "auth_type": "smtp_password",
        "access_token": None,
        "refresh_token": None,
        "token_expires_at": None,
    }

    try:
        _save_persistent_account(
            account
        )

    except sqlite3.IntegrityError:
        existing = _find_any_account(
            account_id
        )

        if existing:
            return {
                "status": "exists",
                "account": _public_account(
                    existing
                ),
                "message": (
                    "A mailbox with this SMTP connection "
                    "already exists."
                ),
            }

        return {
            "status": "error",
            "message": (
                "Unable to save mailbox account."
            ),
        }

    return {
        "status": "success",
        "account": _public_account(
            account
        ),
        "message": (
            "Mailbox account saved successfully. "
            "Attach it when you are ready."
        ) + guidance,
    }


def remove_mailbox(
    account_id: str,
) -> dict[str, Any]:
    global _active_account_id

    account_id = _clean(account_id)

    if not account_id:
        return {
            "status": "invalid",
            "message": "Account ID is required.",
        }

    account = _find_any_account(
        account_id
    )

    if account is None:
        return {
            "status": "not_found",
            "message": "Mailbox account was not found.",
        }

    environment_account_ids = {
        item["account_id"]
        for item in _load_account_configs()
    }

    if account_id in environment_account_ids:
        return {
            "status": "not_removable",
            "message": (
                "This mailbox is configured by the server "
                "environment and cannot be removed from the UI."
            ),
        }

    _attached_account_ids.discard(
        account_id
    )

    if _active_account_id == account_id:
        _active_account_id = None

    _persist_mailbox_state()

    with sqlite3.connect(
        DATABASE_PATH
    ) as connection:
        cursor = connection.execute(
            """
            DELETE FROM mailbox_accounts
            WHERE account_id = ?
            """,
            (account_id,),
        )

        connection.commit()

    if cursor.rowcount == 0:
        return {
            "status": "not_found",
            "message": "Saved mailbox account was not found.",
        }

    return {
        "status": "success",
        "account_id": account_id,
        "message": (
            "Mailbox account permanently removed."
        ),
    }


def attach_mailbox(
    account_id: str,
) -> dict[str, Any]:
    account_id = _clean(account_id)

    if not account_id:
        return {
            "status": "invalid",
            "message": "Account ID is required.",
        }

    account = _find_configured_account(
        account_id
    )

    if account is None:
        return {
            "status": "not_found",
            "message": "Mailbox account was not found.",
        }

    _attached_account_ids.add(
        account["account_id"]
    )

    _persist_mailbox_state()

    return {
        "status": "success",
        "account": _public_account(
            account
        ),
    }


def detach_mailbox(
    account_id: str,
) -> dict[str, Any]:
    global _active_account_id

    account_id = _clean(account_id)

    if not account_id:
        return {
            "status": "invalid",
            "message": "Account ID is required.",
        }

    if account_id not in _attached_account_ids:
        return {
            "status": "not_attached",
            "message": (
                "Mailbox account is not attached."
            ),
        }

    _attached_account_ids.discard(
        account_id
    )

    if _active_account_id == account_id:
        _active_account_id = None

    _persist_mailbox_state()

    return {
        "status": "success",
        "account_id": account_id,
        "message": (
            "Mailbox detached. "
            "The saved account remains available."
        ),
    }


def connect_mailbox(
    account_id: str,
) -> dict[str, Any]:
    global _active_account_id

    account_id = _clean(account_id)

    if not account_id:
        return {
            "status": "invalid",
            "message": "Account ID is required.",
        }

    if account_id not in _attached_account_ids:
        return {
            "status": "not_attached",
            "message": (
                "Attach this mailbox before connecting it."
            ),
        }

    account = _find_any_account(
        account_id
    )

    if account is None:
        _attached_account_ids.discard(
            account_id
        )

        if _active_account_id == account_id:
            _active_account_id = None

        _persist_mailbox_state()

        return {
            "status": "not_found",
            "message": "Mailbox account was not found.",
        }

    _active_account_id = account[
        "account_id"
    ]

    _persist_mailbox_state()

    return {
        "status": "success",
        "account": _public_account(
            account
        ),
    }


def disconnect_mailbox() -> dict[str, Any]:
    global _active_account_id

    _active_account_id = None

    _persist_mailbox_state()

    return {
        "status": "success",
        "account": {
            "connected": False,
            "account_id": None,
            "sender_email": "",
            "username": "",
            "provider": None,
            "smtp": None,
        },
    }


def get_connected_mailbox() -> dict[str, Any]:
    if not _active_account_id:
        return {
            "connected": False,
            "account_id": None,
            "sender_email": "",
            "username": "",
            "provider": None,
            "smtp": None,
        }

    account = _find_any_account(
        _active_account_id
    )

    if account is None:
        return {
            "connected": False,
            "account_id": None,
            "sender_email": "",
            "username": "",
            "provider": None,
            "smtp": None,
        }

    if (
        account["account_id"]
        not in _attached_account_ids
    ):
        return {
            "connected": False,
            "account_id": None,
            "sender_email": "",
            "username": "",
            "provider": None,
            "smtp": None,
        }

    return _public_account(account)


def _get_active_account_config() -> (
    dict[str, Any] | None
):
    if not _active_account_id:
        return None

    if (
        _active_account_id
        not in _attached_account_ids
    ):
        return None

    return _find_any_account(
        _active_account_id
    )


def _smtp_client(
    host: str,
    port: int,
    security_mode: str,
):
    context = ssl.create_default_context()

    if security_mode == "tls":
        return smtplib.SMTP_SSL(
            host,
            port,
            timeout=30,
            context=context,
        )

    return smtplib.SMTP(
        host,
        port,
        timeout=30,
    )


# ---------------------------------------------------------------------------
# OAuth helpers
# ---------------------------------------------------------------------------


def _oauth_redirect_uri(
    provider: str,
) -> str:
    configured = _clean(
        os.getenv(
            "SECUREMAILSCOPE_OAUTH_REDIRECT_URI"
        )
    )

    if configured:
        return configured.rstrip("/") + (
            f"/{provider.lower()}/callback"
        )

    return (
        "http://127.0.0.1:8000"
        f"/api/mailbox/oauth/{provider.lower()}/callback"
    )


def _oauth_client_id(
    provider: str,
) -> str:
    if provider == "Gmail":
        return _clean(
            os.getenv(
                "SECUREMAILSCOPE_GOOGLE_CLIENT_ID"
            )
        )

    return _clean(
        os.getenv(
            "SECUREMAILSCOPE_MICROSOFT_CLIENT_ID"
        )
    )


def _oauth_client_secret(
    provider: str,
) -> str:
    if provider == "Gmail":
        return _clean(
            os.getenv(
                "SECUREMAILSCOPE_GOOGLE_CLIENT_SECRET"
            )
        )

    return _clean(
        os.getenv(
            "SECUREMAILSCOPE_MICROSOFT_CLIENT_SECRET"
        )
    )


def _oauth_ready(
    provider: str,
) -> bool:
    return bool(
        _oauth_client_id(provider)
        and _oauth_client_secret(provider)
    )


def oauth_configuration(
    provider: str,
) -> dict[str, Any]:
    provider = _normalize_provider(
        provider
    )

    if provider not in {
        "Gmail",
        "Microsoft",
    }:
        return {
            "configured": False,
            "provider": provider,
            "message": (
                "OAuth is currently available for "
                "Gmail and Microsoft accounts."
            ),
        }

    return {
        "configured": _oauth_ready(provider),
        "provider": provider,
        "message": (
            "OAuth is configured."
            if _oauth_ready(provider)
            else (
                "OAuth client credentials are not configured "
                "on the server."
            )
        ),
    }


def _http_post_form(
    url: str,
    data: dict[str, str],
) -> dict[str, Any]:
    encoded = urllib.parse.urlencode(
        data
    ).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=encoded,
        headers={
            "Content-Type": (
                "application/x-www-form-urlencoded"
            ),
            "Accept": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=OAUTH_HTTP_TIMEOUT_SECONDS,
        ) as response:
            raw = response.read().decode(
                "utf-8"
            )

    except urllib.error.HTTPError as exc:
        # Providers return the real reason (redirect_uri_mismatch,
        # invalid_grant, invalid_client, ...) in the JSON error body.
        try:
            raw = exc.read().decode("utf-8")
        except Exception:
            raise RuntimeError(
                f"OAuth token request failed: HTTP {exc.code}"
            ) from exc

        if not raw.strip().startswith("{"):
            raise RuntimeError(
                f"OAuth token request failed: HTTP {exc.code}"
            ) from exc

    except Exception as exc:
        raise RuntimeError(
            f"OAuth token request failed: {exc}"
        ) from exc

    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "OAuth provider returned an invalid token response."
        ) from exc

    if not isinstance(result, dict):
        raise RuntimeError(
            "OAuth provider returned an invalid token response."
        )

    if "error" in result:
        description = _clean(
            result.get(
                "error_description"
            )
        )

        if not description:
            description = _clean(
                result.get("error")
            )

        raise RuntimeError(
            description
            or "OAuth token exchange failed."
        )

    return result


def _http_get_json(
    url: str,
    access_token: str,
) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": (
                f"Bearer {access_token}"
            ),
            "Accept": "application/json",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=OAUTH_HTTP_TIMEOUT_SECONDS,
        ) as response:
            raw = response.read().decode(
                "utf-8"
            )
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode(
                "utf-8",
                errors="replace",
            )[:500]
        except Exception:
            detail = ""

        raise RuntimeError(
            f"OAuth profile request failed with HTTP "
            f"{exc.code}: {detail or exc.reason}"
        ) from exc
    except Exception as exc:
        raise RuntimeError(
            f"OAuth profile request failed: {exc}"
        ) from exc

    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "OAuth provider returned invalid profile data."
        ) from exc

    if not isinstance(result, dict):
        raise RuntimeError(
            "OAuth provider returned invalid profile data."
        )

    return result


def _decode_jwt_payload(
    token: str,
) -> dict[str, Any]:
    try:
        parts = token.split(".")

        if len(parts) != 3:
            return {}

        payload = parts[1]

        padding = "=" * (
            (-len(payload)) % 4
        )

        decoded = base64.urlsafe_b64decode(
            payload + padding
        )

        result = json.loads(
            decoded.decode("utf-8")
        )

        return (
            result
            if isinstance(result, dict)
            else {}
        )

    except Exception:
        return {}


def _extract_email_from_profile(
    provider: str,
    token_result: dict[str, Any],
) -> str:
    id_token = _clean(
        token_result.get("id_token")
    )

    if provider == "Gmail":
        if id_token:
            payload = _decode_jwt_payload(
                id_token
            )

            email = _clean(
                payload.get("email")
            )

            if email:
                return email.lower()

        access_token = _clean(
            token_result.get("access_token")
        )

        if access_token:
            profile = _http_get_json(
                "https://openidconnect.googleapis.com/v1/userinfo",
                access_token,
            )

            email = _clean(
                profile.get("email")
            )

            if email:
                return email.lower()

    if provider == "Microsoft":
        if id_token:
            payload = _decode_jwt_payload(
                id_token
            )

            email = (
                _clean(
                    payload.get("preferred_username")
                )
                or _clean(
                    payload.get("email")
                )
            )

            if email:
                return email.lower()

    return ""


def begin_oauth(
    provider: str,
) -> dict[str, Any]:
    provider = _normalize_provider(
        provider
    )

    if provider not in {
        "Gmail",
        "Microsoft",
    }:
        return {
            "status": "invalid",
            "message": (
                "OAuth is available only for "
                "Gmail and Microsoft."
            ),
        }

    client_id = _oauth_client_id(
        provider
    )
    client_secret = _oauth_client_secret(
        provider
    )

    if not client_id or not client_secret:
        return {
            "status": "not_configured",
            "provider": provider,
            "message": (
                f"{provider} OAuth is not configured. "
                "Configure the provider OAuth client ID "
                "and client secret on the backend first."
            ),
        }

    state = secrets.token_urlsafe(
        32
    )

    redirect_uri = _oauth_redirect_uri(
        provider
    )

    _store_oauth_state(
        state,
        {
            "provider": provider,
            "created_at": time.time(),
        },
    )

    if provider == "Gmail":
        scope = " ".join(
            [
                "openid",
                "email",
                "profile",
                "https://mail.google.com/",
            ]
        )

        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "access_type": "offline",
            "prompt": "consent",
            "include_granted_scopes": "true",
            "state": state,
        }

        authorization_url = (
            "https://accounts.google.com/o/oauth2/v2/auth?"
            + urllib.parse.urlencode(params)
        )

    else:
        scope = " ".join(
            [
                "openid",
                "profile",
                "email",
                "offline_access",
                "https://outlook.office.com/SMTP.Send",
            ]
        )

        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "response_mode": "query",
            "scope": scope,
            "state": state,
        }

        authorization_url = (
            "https://login.microsoftonline.com/common/"
            "oauth2/v2.0/authorize?"
            + urllib.parse.urlencode(params)
        )

    return {
        "status": "success",
        "provider": provider,
        "state": state,
        "authorization_url": authorization_url,
    }


def _consume_oauth_state(
    state: str,
    provider: str,
) -> dict[str, Any]:
    state = _clean(state)

    pending = _pop_oauth_state(
        state
    )

    if not pending:
        raise ValueError(
            "OAuth state is invalid or has expired."
        )

    created_at = float(
        pending.get(
            "created_at",
            0,
        )
    )

    if (
        time.time() - created_at
        > OAUTH_STATE_TTL_SECONDS
    ):
        raise ValueError(
            "OAuth authorization session has expired."
        )

    expected_provider = _normalize_provider(
        pending.get("provider")
    )

    actual_provider = _normalize_provider(
        provider
    )

    if expected_provider != actual_provider:
        raise ValueError(
            "OAuth provider does not match the authorization session."
        )

    return pending


def handle_oauth_callback(
    provider: str,
    *,
    code: str | None,
    state: str | None,
    error: str | None = None,
    error_description: str | None = None,
) -> dict[str, Any]:
    provider = _normalize_provider(
        provider
    )

    if error:
        if state:
            _pop_oauth_state(
                _clean(state)
            )

        message = _clean(
            error_description
        ) or _clean(error)

        return {
            "status": "oauth_error",
            "provider": provider,
            "message": (
                message
                or "OAuth authorization was denied."
            ),
        }

    if not code or not state:
        return {
            "status": "invalid",
            "provider": provider,
            "message": (
                "OAuth callback is missing the "
                "authorization code or state."
            ),
        }

    try:
        _consume_oauth_state(
            state,
            provider,
        )
    except ValueError as exc:
        return {
            "status": "invalid",
            "provider": provider,
            "message": str(exc),
        }

    client_id = _oauth_client_id(
        provider
    )
    client_secret = _oauth_client_secret(
        provider
    )

    redirect_uri = _oauth_redirect_uri(
        provider
    )

    try:
        if provider == "Gmail":
            token_result = _http_post_form(
                "https://oauth2.googleapis.com/token",
                {
                    "code": code,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "redirect_uri": redirect_uri,
                    "grant_type": (
                        "authorization_code"
                    ),
                },
            )

            smtp_host = "smtp.gmail.com"
            smtp_port = 587
            security_mode = "starttls"

        elif provider == "Microsoft":
            token_result = _http_post_form(
                "https://login.microsoftonline.com/common/"
                "oauth2/v2.0/token",
                {
                    "code": code,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "redirect_uri": redirect_uri,
                    "grant_type": (
                        "authorization_code"
                    ),
                },
            )

            smtp_host = "smtp.office365.com"
            smtp_port = 587
            security_mode = "starttls"

        else:
            return {
                "status": "invalid",
                "provider": provider,
                "message": (
                    "Unsupported OAuth provider."
                ),
            }

        access_token = _clean(
            token_result.get(
                "access_token"
            )
        )

        refresh_token = _clean(
            token_result.get(
                "refresh_token"
            )
        )

        if not access_token:
            return {
                "status": "oauth_error",
                "provider": provider,
                "message": (
                    "OAuth provider did not return an "
                    "access token."
                ),
            }

        sender_email = (
            _extract_email_from_profile(
                provider,
                token_result,
            )
        )

        if not sender_email:
            return {
                "status": "oauth_error",
                "provider": provider,
                "message": (
                    "OAuth succeeded, but the mailbox email "
                    "address could not be determined."
                ),
            }

        expires_in = token_result.get(
            "expires_in",
            3600,
        )

        try:
            expires_in = int(
                expires_in
            )
        except (
            TypeError,
            ValueError,
        ):
            expires_in = 3600

        token_expires_at = (
            time.time()
            + max(
                60,
                expires_in,
            )
        )

        account_id = _account_id_for_connection(
            sender_email,
            smtp_host,
            smtp_port,
        )

        account = {
            "account_id": account_id,
            "sender_email": sender_email,
            "username": sender_email,
            "password": "",
            "smtp_host": smtp_host,
            "smtp_port": smtp_port,
            "smtp_tls": True,
            "security_mode": security_mode,
            "provider": provider,
            "auth_type": "oauth",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_expires_at": token_expires_at,
        }

        existing = _find_any_account(
            account_id
        )

        persistent_ids = {
            item["account_id"]
            for item in _load_persistent_accounts()
        }

        if (
            existing
            and existing["account_id"]
            in persistent_ids
        ):
            # Re-authorization of a saved account. This used to take
            # the INSERT path and fail with a UNIQUE constraint error,
            # so an expired/revoked account could never be reconnected.
            if not account["refresh_token"]:
                account["refresh_token"] = (
                    existing.get("refresh_token")
                    or ""
                )

            _update_oauth_account(
                account
            )
        else:
            try:
                _save_persistent_account(
                    account
                )
            except sqlite3.IntegrityError:
                candidates = [
                    item
                    for item in _load_persistent_accounts()
                    if item["sender_email"].lower()
                    == sender_email.lower()
                ]

                if len(candidates) == 1:
                    existing = candidates[0]

                    account["account_id"] = existing[
                        "account_id"
                    ]

                    if not account["refresh_token"]:
                        account["refresh_token"] = (
                            existing.get("refresh_token")
                            or ""
                        )

                    _update_oauth_account(
                        account
                    )
                else:
                    raise

        stored = _find_any_account(
            account["account_id"]
        )

        return {
            "status": "success",
            "provider": provider,
            "account": _public_account(
                stored or account
            ),
            "message": (
                "OAuth mailbox authorization completed. "
                "The account is saved but not attached or "
                "connected."
            ),
        }

    except Exception as exc:
        return {
            "status": "oauth_error",
            "provider": provider,
            "message": str(exc),
        }


def _refresh_oauth_token(
    account: dict[str, Any],
) -> dict[str, Any]:
    provider = _normalize_provider(
        account["provider"]
    )

    refresh_token = _clean(
        account.get("refresh_token")
    )

    if not refresh_token:
        raise RuntimeError(
            "OAuth refresh token is unavailable. "
            "Reconnect this mailbox."
        )

    client_id = _oauth_client_id(
        provider
    )
    client_secret = _oauth_client_secret(
        provider
    )

    if not client_id or not client_secret:
        raise RuntimeError(
            f"{provider} OAuth is not configured on the server."
        )

    if provider == "Gmail":
        token_result = _http_post_form(
            "https://oauth2.googleapis.com/token",
            {
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
        )

    elif provider == "Microsoft":
        token_result = _http_post_form(
            "https://login.microsoftonline.com/common/"
            "oauth2/v2.0/token",
            {
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
                "scope": (
                    "https://outlook.office.com/SMTP.Send"
                    " offline_access"
                ),
            },
        )

    else:
        raise RuntimeError(
            "Unsupported OAuth provider."
        )

    access_token = _clean(
        token_result.get(
            "access_token"
        )
    )

    if not access_token:
        raise RuntimeError(
            "OAuth token refresh did not return an access token."
        )

    new_refresh_token = _clean(
        token_result.get(
            "refresh_token"
        )
    ) or refresh_token

    expires_in = token_result.get(
        "expires_in",
        3600,
    )

    try:
        expires_in = int(
            expires_in
        )
    except (
        TypeError,
        ValueError,
    ):
        expires_in = 3600

    account["access_token"] = access_token
    account["refresh_token"] = (
        new_refresh_token
    )
    account["token_expires_at"] = (
        time.time()
        + max(
            60,
            expires_in,
        )
    )

    _update_oauth_account(
        account
    )

    return account


def _get_valid_oauth_access_token(
    account: dict[str, Any],
) -> str:
    access_token = _clean(
        account.get("access_token")
    )

    expires_at = account.get(
        "token_expires_at"
    )

    if (
        access_token
        and expires_at
        and time.time()
        < float(expires_at) - 60
    ):
        return access_token

    if access_token and not expires_at:
        return access_token

    refreshed = _refresh_oauth_token(
        account
    )

    return _clean(
        refreshed["access_token"]
    )


def _smtp_auth_xoauth2(
    smtp: smtplib.SMTP,
    username: str,
    access_token: str,
) -> None:
    auth_string = (
        f"user={username}\x01"
        f"auth=Bearer {access_token}\x01"
        "\x01"
    )

    # smtplib calls this without a challenge for the initial
    # response. On failure the server sends a 334 error challenge that
    # must be answered with an empty line so the real authentication
    # error is reported instead of an auth loop.
    def auth_callback(challenge=None):
        return auth_string if challenge is None else ""

    smtp.auth(
        "XOAUTH2",
        auth_callback,
        initial_response_ok=True,
    )


# ---------------------------------------------------------------------------
# Email sending
# ---------------------------------------------------------------------------


def send_connected_email(
    *,
    recipient_email: str,
    subject: str,
    body: str,
    attachments: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    account = _get_active_account_config()

    if account is None:
        return {
            "status": "not_connected",
            "message": (
                "No sending mailbox is connected. "
                "Attach and connect a mailbox before sending."
            ),
        }

    recipient_email = _clean(
        recipient_email
    )
    subject = _clean(subject)

    if not recipient_email:
        return {
            "status": "invalid",
            "message": "Recipient email is required.",
        }

    # Subject and body are optional (the API documents them as such);
    # rejecting them here broke attachment-only and subject-only sends.
    body = body or ""

    message = EmailMessage()

    message["From"] = account[
        "sender_email"
    ]
    message["To"] = recipient_email
    message["Subject"] = subject

    message.set_content(body)

    attachment_metadata: list[
        dict[str, Any]
    ] = []

    for attachment in attachments or []:
        filename = _clean(
            attachment.get("filename")
        )

        content_type = _clean(
            attachment.get("content_type")
        ) or "application/octet-stream"

        payload = attachment.get(
            "content"
        )

        if (
            not filename
            or not isinstance(payload, bytes)
        ):
            continue

        if "/" in content_type:
            maintype, subtype = (
                content_type.split(
                    "/",
                    1,
                )
            )
        else:
            maintype = "application"
            subtype = "octet-stream"

        message.add_attachment(
            payload,
            maintype=maintype,
            subtype=subtype,
            filename=filename,
        )

        attachment_metadata.append(
            {
                "filename": filename,
                "content_type": content_type,
                "size": len(payload),
            }
        )

    smtp_host = account[
        "smtp_host"
    ]

    smtp_port = account[
        "smtp_port"
    ]

    security_mode = _normalize_security_mode(
        account.get("security_mode"),
        smtp_port,
    )

    auth_type = account.get(
        "auth_type",
        "smtp_password",
    )

    # Many campus/office/venue networks block outbound SMTP ports
    # (25/465/587) while HTTPS works. Gmail OAuth accounts can then
    # submit through the Gmail API over HTTPS instead of timing out
    # with WinError 10060. The message (already E2E-encrypted in the
    # browser when applicable) is identical on both paths.
    use_gmail_api = (
        auth_type == "oauth"
        and _normalize_provider(
            account.get("provider")
        ) == "Gmail"
        and not _smtp_port_reachable(
            smtp_host,
            smtp_port,
        )
    )

    gmail_api_result: dict[str, Any] = {}

    try:
        if use_gmail_api:
            gmail_api_result = _gmail_api_send(
                _get_valid_oauth_access_token(
                    account
                ),
                message,
            )

        elif auth_type == "oauth":
            access_token = (
                _get_valid_oauth_access_token(
                    account
                )
            )

            with _smtp_client(
                smtp_host,
                smtp_port,
                security_mode,
            ) as smtp:
                smtp.ehlo()

                if security_mode == "starttls":
                    smtp.starttls(
                        context=ssl.create_default_context()
                    )
                    smtp.ehlo()

                _smtp_auth_xoauth2(
                    smtp,
                    account["username"],
                    access_token,
                )

                smtp.send_message(
                    message
                )

        else:
            with _smtp_client(
                smtp_host,
                smtp_port,
                security_mode,
            ) as smtp:
                smtp.ehlo()

                if security_mode == "starttls":
                    smtp.starttls(
                        context=ssl.create_default_context()
                    )
                    smtp.ehlo()

                if security_mode == "none":
                    pass

                smtp.login(
                    account["username"],
                    account["password"],
                )

                smtp.send_message(
                    message
                )

        return {
            "status": "success",
            "sender": account[
                "sender_email"
            ],
            "recipient": recipient_email,
            "smtp": {
                "host": (
                    "gmail.googleapis.com"
                    if use_gmail_api
                    else smtp_host
                ),
                "port": (
                    443
                    if use_gmail_api
                    else smtp_port
                ),
                "security_mode": (
                    "https"
                    if use_gmail_api
                    else security_mode
                ),
                "tls": (
                    use_gmail_api
                    or security_mode
                    in {
                        "starttls",
                        "tls",
                    }
                ),
                "authentication": (
                    "oauth"
                    if auth_type == "oauth"
                    else "credential"
                ),
                "submission_channel": (
                    "gmail_api_https"
                    if use_gmail_api
                    else "smtp"
                ),
                "provider_message_id": gmail_api_result.get(
                    "id"
                ),
                "submission_verified": True,
            },
            "attachments": attachment_metadata,
        }

    except smtplib.SMTPAuthenticationError:
        if (
            _normalize_provider(
                account.get("provider")
            )
            == "Gmail"
        ):
            auth_message = (
                "Gmail rejected the credential. Google no longer "
                "accepts ordinary account passwords for SMTP. Enable "
                "2-Step Verification, create an App Password (Google "
                "Account → Security → App passwords), save it as this "
                "mailbox's credential, and connect again."
            )
        else:
            auth_message = (
                "Mailbox authentication failed. "
                "For Google or Microsoft accounts, reconnect "
                "the OAuth authorization. For custom SMTP, "
                "verify the configured credential."
            )

        return {
            "status": "authentication_error",
            "message": auth_message,
        }

    except smtplib.SMTPException as exc:
        return {
            "status": "smtp_error",
            "message": str(exc),
        }

    except OSError as exc:
        return {
            "status": "connection_error",
            "message": (
                f"Could not reach the mail server "
                f"{smtp_host}:{smtp_port} ({exc}). The current "
                "network may block outbound SMTP ports; try another "
                "network or a Gmail OAuth account (sent over HTTPS)."
            ),
        }

    except Exception as exc:
        return {
            "status": "error",
            "message": str(exc),
        }


def _smtp_port_reachable(
    host: str,
    port: int,
    timeout: float = 5.0,
) -> bool:
    try:
        with socket.create_connection(
            (host, int(port)),
            timeout=timeout,
        ):
            return True
    except OSError:
        return False


def _gmail_api_send(
    access_token: str,
    message: EmailMessage,
) -> dict[str, Any]:
    """
    Submits a fully built RFC 5322 message through the Gmail API
    (users.messages.send) over HTTPS. Covered by the existing
    https://mail.google.com/ OAuth scope.
    """

    raw = base64.urlsafe_b64encode(
        message.as_bytes()
    ).decode("ascii")

    request = urllib.request.Request(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
        data=json.dumps(
            {"raw": raw}
        ).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=OAUTH_HTTP_TIMEOUT_SECONDS,
        ) as response:
            result = json.loads(
                response.read().decode("utf-8")
            )

    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode(
                "utf-8",
                errors="replace",
            )[:500]
        except Exception:
            detail = ""

        if exc.code in {401, 403}:
            raise smtplib.SMTPAuthenticationError(
                exc.code,
                detail or "Gmail API rejected the OAuth token.",
            ) from exc

        raise RuntimeError(
            f"Gmail API send failed with HTTP {exc.code}: "
            f"{detail or exc.reason}"
        ) from exc

    return result if isinstance(result, dict) else {}


# ---------------------------------------------------------------------------
# Gmail mailbox retrieval
# ---------------------------------------------------------------------------


def _gmail_api_get_json(
    url: str,
    access_token: str,
) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=OAUTH_HTTP_TIMEOUT_SECONDS,
        ) as response:
            raw = response.read().decode(
                "utf-8"
            )

    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode(
                "utf-8"
            )
        except Exception:
            detail = ""

        raise RuntimeError(
            f"Gmail API request failed with HTTP {exc.code}: "
            f"{detail or exc.reason}"
        ) from exc

    except Exception as exc:
        raise RuntimeError(
            f"Gmail API request failed: {exc}"
        ) from exc

    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Gmail API returned invalid JSON."
        ) from exc

    if not isinstance(result, dict):
        raise RuntimeError(
            "Gmail API returned an invalid response."
        )

    return result


def _gmail_api_get_raw_message(
    message_id: str,
    access_token: str,
) -> bytes:
    url = (
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/"
        f"{urllib.parse.quote(message_id, safe='')}"
        "?format=raw"
    )

    result = _gmail_api_get_json(
        url,
        access_token,
    )

    raw_value = result.get("raw")

    if not isinstance(
        raw_value,
        str,
    ):
        raise RuntimeError(
            "Gmail API did not return the raw message."
        )

    try:
        return base64.urlsafe_b64decode(
            raw_value
            + "=" * (
                (-len(raw_value)) % 4
            )
        )
    except Exception as exc:
        raise RuntimeError(
            "Unable to decode the Gmail message."
        ) from exc


def _header_value(
    message,
    name: str,
) -> str:
    value = message.get(
        name,
        "",
    )

    if value is None:
        return ""

    return _clean(value)


def _extract_message_addresses(
    value: str,
) -> list[str]:
    if not value:
        return []

    return [
        address
        for _, address in getaddresses([value])
        if address
    ]


def _message_received_at(
    message,
) -> str:
    date_value = _header_value(
        message,
        "Date",
    )

    if date_value:
        try:
            return parsedate_to_datetime(
                date_value
            ).isoformat()
        except Exception:
            pass

    internal_date = _header_value(
        message,
        "X-Gmail-Internal-Date",
    )

    if internal_date:
        return internal_date

    return ""


def _decode_message_part(
    part,
) -> str:
    try:
        payload = part.get_payload(
            decode=True
        )

        if payload is None:
            return ""

        charset = part.get_content_charset()

        if charset:
            try:
                return payload.decode(
                    charset,
                    errors="replace",
                )
            except (
                LookupError,
                UnicodeDecodeError,
            ):
                pass

        return payload.decode(
            "utf-8",
            errors="replace",
        )

    except Exception:
        return ""


def _extract_mailbox_content(
    message,
) -> tuple[
    str,
    str,
    list[dict[str, Any]],
]:
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict[str, Any]] = []

    if message.is_multipart():
        parts = message.walk()
    else:
        parts = [message]

    for part in parts:
        if part.is_multipart():
            continue

        content_disposition = (
            part.get_content_disposition()
        )

        filename = _clean(
            part.get_filename()
        )

        content_type = (
            _clean(
                part.get_content_type()
            )
            or "application/octet-stream"
        )

        if (
            content_disposition == "attachment"
            or filename
        ):
            payload = part.get_payload(
                decode=True
            )

            attachments.append(
                {
                    "filename": (
                        filename
                        or "Attachment"
                    ),
                    "content_type": content_type,
                    "size": (
                        len(payload)
                        if isinstance(
                            payload,
                            bytes,
                        )
                        else 0
                    ),
                }
            )

            continue

        content = _decode_message_part(
            part
        )

        if not content:
            continue

        if content_type == "text/plain":
            plain_parts.append(content)

        elif content_type == "text/html":
            html_parts.append(content)

    body = "\n\n".join(
        item
        for item in plain_parts
        if item.strip()
    ).strip()

    if not body and html_parts:
        # Drop non-visible blocks first, otherwise CSS/JS text leaks
        # into the body and preview.
        visible_html = re.sub(
            r"(?is)<(script|style|head)\b.*?</\1>",
            " ",
            "\n".join(html_parts),
        )

        body = re.sub(
            r"<[^>]+>",
            " ",
            visible_html,
        )

        body = re.sub(
            r"\s+",
            " ",
            html.unescape(body),
        ).strip()

    return (
        body,
        "\n".join(
            html_parts
        ).strip(),
        attachments,
    )


E2E_ENVELOPE_PATTERN = re.compile(
    r'\{[^{}]*"protocol"\s*:\s*"SecureMailScope-E2E"[^{}]*\}'
)


def detect_e2e_envelope(
    body: str,
) -> dict[str, Any] | None:
    """
    Detects a SecureMailScope E2E envelope in a message body and
    returns its public metadata only.

    The backend never holds the recipient private key, so it cannot
    and does not decrypt. The envelope stays opaque and is decrypted
    in the recipient's browser (app or extension).
    """

    if not body or "SecureMailScope-E2E" not in body:
        return None

    # Second candidate tolerates leftover quoted-printable soft breaks
    # and hard-wrapped lines.
    unwrapped = re.sub(r"=\r?\n", "", body)
    unwrapped = re.sub(r"(?i)=3D", "=", unwrapped)
    unwrapped = re.sub(r"\r?\n", "", unwrapped)

    envelope = None

    for text in (body, unwrapped):
        match = E2E_ENVELOPE_PATTERN.search(text)

        if not match:
            continue

        try:
            envelope = json.loads(match.group(0))
            break
        except json.JSONDecodeError:
            continue

    if not isinstance(envelope, dict):
        return None

    return {
        "detected": True,
        "protocol": envelope.get("protocol"),
        "version": envelope.get("version"),
        "content_encryption": envelope.get(
            "content_encryption"
        ),
        "key_encryption": envelope.get(
            "key_encryption"
        ),
        "recipient": envelope.get("recipient"),
        "recipient_key_id": envelope.get(
            "recipient_key_id"
        ),
        "recipient_key_fingerprint": envelope.get(
            "recipient_key_fingerprint"
        ),
    }


def _normalize_gmail_message(
    raw_eml: bytes,
    *,
    message_id: str,
    thread_id: str = "",
) -> dict[str, Any]:
    try:
        parsed = BytesParser(
            policy=policy.default
        ).parsebytes(raw_eml)

    except Exception as exc:
        raise RuntimeError(
            "Unable to parse the Gmail message."
        ) from exc

    sender_header = _header_value(
        parsed,
        "From",
    )

    recipient_header = _header_value(
        parsed,
        "To",
    )

    cc_header = _header_value(
        parsed,
        "Cc",
    )

    recipients = (
        _extract_message_addresses(
            recipient_header
        )
        + _extract_message_addresses(
            cc_header
        )
    )

    body, html_body, attachments = (
        _extract_mailbox_content(
            parsed
        )
    )

    subject = _header_value(
        parsed,
        "Subject",
    )

    preview_source = body or html_body

    preview = re.sub(
        r"\s+",
        " ",
        preview_source,
    ).strip()

    if len(preview) > 180:
        preview = (
            preview[:177]
            + "..."
        )

    e2e = detect_e2e_envelope(body)

    if e2e:
        preview = (
            "End-to-end encrypted SecureMailScope message. "
            "Open to decrypt locally."
        )

    # Repeated headers (Received, Authentication-Results, DKIM-Signature,
    # ARC-*) are kept as lists. Joining them into one comma-separated
    # string made hop reconstruction see a single hop and broke
    # authentication parsing.
    header_lists: dict[str, list[str]] = {}
    canonical_names: dict[str, str] = {}

    for key, value in parsed.items():
        name = canonical_names.setdefault(
            key.lower(),
            "Received"
            if key.lower() == "received"
            else key,
        )

        header_lists.setdefault(
            name,
            [],
        ).append(str(value))

    headers: dict[str, Any] = {
        name: (
            values
            if len(values) > 1
            or name == "Received"
            else values[0]
        )
        for name, values in header_lists.items()
    }

    return {
        "id": message_id,
        "message_id": _header_value(
            parsed,
            "Message-ID",
        ),
        "thread_id": thread_id,
        "sender": sender_header,
        "recipients": recipients,
        "subject": subject,
        "preview": preview,
        "body": body,
        "html_body": html_body,
        "received_at": _message_received_at(
            parsed
        ),
        "provider": "Gmail",
        "attachments": attachments,
        "e2e": e2e,
        "headers": headers,
        "raw_eml": raw_eml.decode(
            "utf-8",
            errors="replace",
        ),
    }


def _gmail_list_messages(
    account: dict[str, Any],
    limit: int,
) -> list[dict[str, Any]]:
    if _normalize_provider(
        account.get("provider")
    ) != "Gmail":
        raise RuntimeError(
            "Mailbox retrieval is currently available "
            "only for Gmail OAuth accounts."
        )

    if account.get("auth_type") != "oauth":
        raise RuntimeError(
            "Gmail inbox retrieval requires an OAuth-connected account."
        )

    try:
        limit = int(limit)
    except (
        TypeError,
        ValueError,
    ):
        limit = 20

    limit = max(
        1,
        min(limit, 50),
    )

    access_token = _get_valid_oauth_access_token(
        account
    )

    params = urllib.parse.urlencode(
        {
            "maxResults": limit,
            "labelIds": "INBOX",
        }
    )

    url = (
        "https://gmail.googleapis.com/gmail/v1/users/me/messages?"
        + params
    )

    result = _gmail_api_get_json(
        url,
        access_token,
    )

    message_refs = result.get(
        "messages",
        [],
    )

    if not isinstance(
        message_refs,
        list,
    ):
        return []

    references = [
        reference
        for reference in message_refs
        if isinstance(reference, dict)
        and _clean(reference.get("id"))
    ]

    def load_item(reference):
        try:
            return _gmail_list_item(
                reference,
                access_token,
            )
        except Exception:
            # One malformed/unavailable message must not prevent
            # the rest of the inbox from loading.
            return None

    # The list view only needs headers + snippet. Fetching metadata in
    # parallel replaces N sequential full raw downloads (which included
    # every attachment). The full raw message is fetched on open.
    with ThreadPoolExecutor(
        max_workers=8
    ) as pool:
        results = list(
            pool.map(
                load_item,
                references,
            )
        )

    return [
        item
        for item in results
        if item
    ]


def _gmail_list_item(
    reference: dict[str, Any],
    access_token: str,
) -> dict[str, Any]:
    message_id = _clean(
        reference.get("id")
    )

    query = urllib.parse.urlencode(
        [("format", "metadata")]
        + [
            ("metadataHeaders", name)
            for name in (
                "From",
                "To",
                "Cc",
                "Subject",
                "Date",
            )
        ]
    )

    data = _gmail_api_get_json(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/"
        f"{urllib.parse.quote(message_id, safe='')}?{query}",
        access_token,
    )

    header_map = {
        str(item.get("name", "")).lower(): str(
            item.get("value", "")
        )
        for item in (
            data.get("payload", {}).get(
                "headers",
                [],
            )
        )
        if isinstance(item, dict)
    }

    snippet = html.unescape(
        _clean(data.get("snippet"))
    )

    subject = header_map.get(
        "subject",
        "",
    )

    is_e2e = (
        "SecureMailScope-E2E" in snippet
        or "SECUREMAILSCOPE E2E" in snippet
        or subject.startswith(
            "[SecureMailScope E2E]"
        )
    )

    try:
        received_at = datetime.fromtimestamp(
            int(data.get("internalDate", 0))
            / 1000,
            timezone.utc,
        ).isoformat()
    except (TypeError, ValueError):
        received_at = ""

    return {
        "id": message_id,
        "thread_id": _clean(
            data.get("threadId")
            or reference.get("threadId")
        ),
        "sender": header_map.get(
            "from",
            "",
        ),
        "recipients": (
            _extract_message_addresses(
                header_map.get("to", "")
            )
            + _extract_message_addresses(
                header_map.get("cc", "")
            )
        ),
        "subject": subject,
        "preview": (
            "End-to-end encrypted SecureMailScope message. "
            "Open to decrypt locally."
            if is_e2e
            else snippet
        ),
        "received_at": received_at,
        "labels": data.get(
            "labelIds",
            [],
        ),
        "provider": "Gmail",
        "e2e": (
            {"detected": True}
            if is_e2e
            else None
        ),
    }


def _gmail_get_message(
    account: dict[str, Any],
    message_id: str,
) -> dict[str, Any]:
    if _normalize_provider(
        account.get("provider")
    ) != "Gmail":
        raise RuntimeError(
            "Mailbox retrieval is currently available "
            "only for Gmail OAuth accounts."
        )

    if account.get("auth_type") != "oauth":
        raise RuntimeError(
            "Gmail inbox retrieval requires an OAuth-connected account."
        )

    message_id = _clean(
        message_id
    )

    if not message_id:
        raise ValueError(
            "Message ID is required."
        )

    access_token = _get_valid_oauth_access_token(
        account
    )

    raw_eml = _gmail_api_get_raw_message(
        message_id,
        access_token,
    )

    return _normalize_gmail_message(
        raw_eml,
        message_id=message_id,
    )


# ---------------------------------------------------------------------------
# IMAP retrieval for saved-credential (App Password) mailboxes
# ---------------------------------------------------------------------------


def _imap_host_for_account(
    account: dict[str, Any],
) -> str:
    smtp_host = _clean(
        account.get("smtp_host")
    ).lower()

    if not smtp_host:
        return ""

    if (
        "gmail" in smtp_host
        or "googlemail" in smtp_host
    ):
        return "imap.gmail.com"

    if (
        "outlook" in smtp_host
        or "office365" in smtp_host
        or "hotmail" in smtp_host
        or "live" in smtp_host
    ):
        return "outlook.office365.com"

    if smtp_host.startswith(
        "smtp."
    ):
        return "imap." + smtp_host[5:]

    return ""


def _imap_connection(
    account: dict[str, Any],
) -> imaplib.IMAP4_SSL:
    host = _imap_host_for_account(
        account
    )

    if not host:
        raise RuntimeError(
            "The IMAP server for this mailbox "
            "could not be determined from its "
            "SMTP host."
        )

    username = _clean(
        account.get("username")
        or account.get("sender_email")
    )

    password = _clean(
        account.get("password")
    )

    if not username or not password:
        raise RuntimeError(
            "This mailbox has no saved IMAP "
            "credentials."
        )

    try:
        connection = imaplib.IMAP4_SSL(
            host,
            993,
            timeout=15,
        )

        connection.login(
            username,
            password,
        )

    except imaplib.IMAP4.error as exc:
        raise RuntimeError(
            "The mail provider rejected the IMAP "
            f"login for {username}. Confirm IMAP is "
            "enabled for the account and that the "
            "saved password is an App Password."
        ) from exc

    except OSError as exc:
        raise RuntimeError(
            "Unable to reach the mail provider "
            f"IMAP server {host}."
        ) from exc

    return connection


def _imap_fetch_raw(
    connection: imaplib.IMAP4_SSL,
    uid: str,
) -> bytes:
    status, data = connection.uid(
        "FETCH",
        uid,
        "(RFC822)",
    )

    if status != "OK":
        raise RuntimeError(
            "The mail provider refused to return "
            "the message."
        )

    for part in data:
        if isinstance(
            part,
            tuple,
        ):
            return part[1]

    raise RuntimeError(
        "The mail provider returned an empty "
        "message."
    )


def _imap_list_messages(
    account: dict[str, Any],
    limit: int,
) -> list[dict[str, Any]]:
    try:
        limit = int(limit)

    except (
        TypeError,
        ValueError,
    ):
        limit = 20

    limit = max(
        1,
        min(limit, 50),
    )

    connection = _imap_connection(
        account
    )

    try:
        connection.select(
            "INBOX",
            readonly=True,
        )

        status, data = connection.uid(
            "SEARCH",
            None,
            "ALL",
        )

        if status != "OK":
            raise RuntimeError(
                "The mail provider refused the "
                "inbox search."
            )

        uids = [
            uid.decode(
                "ascii",
                errors="ignore",
            )
            for uid in (data[0] or b"").split()
        ]

        items: list[dict[str, Any]] = []

        for uid in reversed(
            uids[-limit:]
        ):
            try:
                raw_eml = _imap_fetch_raw(
                    connection,
                    uid,
                )

                message = _normalize_gmail_message(
                    raw_eml,
                    message_id=uid,
                )

            except Exception:
                # One malformed message must not
                # break the whole inbox.
                continue

            items.append(
                {
                    "id": message.get(
                        "id",
                        uid,
                    ),
                    "thread_id": message.get(
                        "thread_id",
                        "",
                    ),
                    "sender": message.get(
                        "sender",
                        "",
                    ),
                    "recipients": message.get(
                        "recipients",
                        [],
                    ),
                    "subject": message.get(
                        "subject",
                        "",
                    ),
                    "preview": message.get(
                        "preview",
                        "",
                    ),
                    "received_at": message.get(
                        "received_at",
                        "",
                    ),
                    "labels": [],
                    "provider": message.get(
                        "provider",
                        "Gmail",
                    ),
                    "e2e": message.get(
                        "e2e"
                    ),
                }
            )

        return items

    finally:
        try:
            connection.logout()

        except Exception:
            pass


def _imap_get_message(
    account: dict[str, Any],
    message_id: str,
) -> dict[str, Any]:
    message_id = _clean(
        message_id
    )

    if not message_id:
        raise ValueError(
            "Message ID is required."
        )

    connection = _imap_connection(
        account
    )

    try:
        connection.select(
            "INBOX",
            readonly=True,
        )

        raw_eml = _imap_fetch_raw(
            connection,
            message_id,
        )

    finally:
        try:
            connection.logout()

        except Exception:
            pass

    return _normalize_gmail_message(
        raw_eml,
        message_id=message_id,
    )


def list_mailbox_messages(
    account_id: str,
    limit: int = 20,
) -> list[dict[str, Any]]:
    account_id = _clean(
        account_id
    )

    if not account_id:
        raise ValueError(
            "Account ID is required."
        )

    account = _find_any_account(
        account_id
    )

    if account is None:
        raise ValueError(
            "Mailbox account was not found."
        )

    provider = _normalize_provider(
        account.get("provider")
    )

    if provider == "Gmail":
        if account.get("auth_type") == "oauth":
            return _gmail_list_messages(
                account,
                limit,
            )

        # Saved-credential (App Password) mailboxes
        # read their inbox over IMAP.
        return _imap_list_messages(
            account,
            limit,
        )

    raise RuntimeError(
        "Inbox retrieval is not currently available "
        f"for the {provider} mailbox provider."
    )


def get_mailbox_message(
    account_id: str,
    message_id: str,
) -> dict[str, Any]:
    account_id = _clean(
        account_id
    )

    if not account_id:
        raise ValueError(
            "Account ID is required."
        )

    account = _find_any_account(
        account_id
    )

    if account is None:
        raise ValueError(
            "Mailbox account was not found."
        )

    provider = _normalize_provider(
        account.get("provider")
    )

    if provider == "Gmail":
        if account.get("auth_type") == "oauth":
            return _gmail_get_message(
                account,
                message_id,
            )

        return _imap_get_message(
            account,
            message_id,
        )

    raise RuntimeError(
        "Inbox retrieval is not currently available "
        f"for the {provider} mailbox provider."
    )

# Restore attach/connect state saved before the last restart/reload.
_restore_mailbox_state()
