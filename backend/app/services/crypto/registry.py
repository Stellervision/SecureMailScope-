import base64
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa


BASE_DIR = Path(__file__).resolve().parents[3]
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "crypto_keys.db"


SUPPORTED_ALGORITHM = "RSA-OAEP-256"
MIN_RSA_BITS = 2048


def _clean_email(value: Any) -> str:
    return str(value or "").strip().lower()


def _validate_email(email: str) -> bool:
    if not email or "@" not in email:
        return False

    local_part, domain = email.rsplit("@", 1)

    return bool(
        local_part
        and domain
        and "." in domain
        and not domain.startswith(".")
        and not domain.endswith(".")
    )


def _base64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("Invalid base64url value.")

    padding = "=" * (-len(value) % 4)

    try:
        return base64.urlsafe_b64decode(
            value + padding
        )
    except Exception as exc:
        raise ValueError(
            "Invalid base64url encoding."
        ) from exc


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(
        value
    ).rstrip(b"=").decode("ascii")


def _normalize_public_key(
    public_key: Any,
) -> dict[str, Any]:
    if not isinstance(public_key, dict):
        raise ValueError(
            "Public key must be a JSON object."
        )

    key_type = str(
        public_key.get("kty", "")
    ).strip()

    algorithm = str(
        public_key.get("alg", "")
    ).strip()

    key_use = str(
        public_key.get("use", "")
    ).strip()

    if key_type != "RSA":
        raise ValueError(
            "Only RSA public keys are supported."
        )

    if algorithm != SUPPORTED_ALGORITHM:
        raise ValueError(
            f"Unsupported key algorithm. "
            f"Expected {SUPPORTED_ALGORITHM}."
        )

    if key_use and key_use != "enc":
        raise ValueError(
            "The public key must be intended for encryption."
        )

    modulus = public_key.get("n")
    exponent = public_key.get("e")

    if not isinstance(modulus, str) or not modulus:
        raise ValueError(
            "RSA public key is missing modulus."
        )

    if not isinstance(exponent, str) or not exponent:
        raise ValueError(
            "RSA public key is missing exponent."
        )

    modulus_bytes = _base64url_decode(modulus)
    exponent_bytes = _base64url_decode(exponent)

    if len(modulus_bytes) < MIN_RSA_BITS // 8:
        raise ValueError(
            "RSA public key must be at least 2048 bits."
        )

    modulus_int = int.from_bytes(
        modulus_bytes,
        "big",
    )

    exponent_int = int.from_bytes(
        exponent_bytes,
        "big",
    )

    try:
        public_numbers = rsa.RSAPublicNumbers(
            exponent_int,
            modulus_int,
        )

        public_key_object = (
            public_numbers.public_key()
        )

    except Exception as exc:
        raise ValueError(
            "The supplied RSA public key is invalid."
        ) from exc

    key_size = public_key_object.key_size

    if key_size < MIN_RSA_BITS:
        raise ValueError(
            "RSA public key must be at least 2048 bits."
        )

    normalized = {
        "kty": "RSA",
        "n": _base64url_encode(
            modulus_bytes
        ),
        "e": _base64url_encode(
            exponent_bytes
        ),
        "alg": SUPPORTED_ALGORITHM,
        "use": "enc",
    }

    return normalized


def _canonical_public_key(
    public_key: dict[str, Any],
) -> str:
    return json.dumps(
        public_key,
        sort_keys=True,
        separators=(",", ":"),
    )


def _fingerprint(
    public_key: dict[str, Any],
) -> str:
    canonical = _canonical_public_key(
        public_key
    )

    digest = hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()

    return " ".join(
        digest[index:index + 4]
        for index in range(
            0,
            len(digest),
            4,
        )
    )


def _key_id(
    public_key: dict[str, Any],
) -> str:
    digest = hashlib.sha256(
        _canonical_public_key(
            public_key
        ).encode("utf-8")
    ).hexdigest()

    return f"smsk-{digest[:24]}"


def _utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def initialize_registry() -> None:
    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with sqlite3.connect(
        DATABASE_PATH
    ) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS crypto_public_keys (
                email TEXT PRIMARY KEY,
                key_id TEXT NOT NULL UNIQUE,
                fingerprint TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                public_key_jwk TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

        # Retired keys are kept so key rotation stays auditable.
        # Only public keys are stored; private keys never reach
        # the backend.
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS crypto_key_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                key_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                public_key_jwk TEXT NOT NULL,
                created_at TEXT NOT NULL,
                retired_at TEXT NOT NULL
            )
            """
        )

        # "mailbox" = key published by a mailbox authenticated on this
        # instance. "contact_card" = public key card imported for an
        # external recipient (e.g. someone running SecureMailScope on
        # another machine).
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(crypto_public_keys)"
            ).fetchall()
        }

        if "source" not in columns:
            connection.execute(
                """
                ALTER TABLE crypto_public_keys
                ADD COLUMN source TEXT NOT NULL DEFAULT 'mailbox'
                """
            )

        connection.commit()


def _load_key(
    email: str,
) -> dict[str, Any] | None:
    initialize_registry()

    with sqlite3.connect(
        DATABASE_PATH
    ) as connection:
        connection.row_factory = sqlite3.Row

        row = connection.execute(
            """
            SELECT
                email,
                key_id,
                fingerprint,
                algorithm,
                public_key_jwk,
                created_at,
                updated_at,
                source
            FROM crypto_public_keys
            WHERE email = ?
            """,
            (email,),
        ).fetchone()

    if row is None:
        return None

    try:
        public_key = json.loads(
            row["public_key_jwk"]
        )
    except json.JSONDecodeError:
        public_key = {}

    return {
        "email": row["email"],
        "key_id": row["key_id"],
        "fingerprint": row["fingerprint"],
        "algorithm": row["algorithm"],
        "public_key": public_key,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "source": row["source"] or "mailbox",
    }


def _load_key_by_id(
    key_id: str,
) -> dict[str, Any] | None:
    initialize_registry()

    with sqlite3.connect(
        DATABASE_PATH
    ) as connection:
        connection.row_factory = sqlite3.Row

        row = connection.execute(
            """
            SELECT
                email,
                key_id,
                fingerprint,
                algorithm,
                public_key_jwk,
                created_at,
                updated_at,
                source
            FROM crypto_public_keys
            WHERE key_id = ?
            """,
            (key_id,),
        ).fetchone()

    if row is None:
        return None

    try:
        public_key = json.loads(
            row["public_key_jwk"]
        )
    except json.JSONDecodeError:
        public_key = {}

    return {
        "email": row["email"],
        "key_id": row["key_id"],
        "fingerprint": row["fingerprint"],
        "algorithm": row["algorithm"],
        "public_key": public_key,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "source": row["source"] or "mailbox",
    }


def register_public_key(
    *,
    email: str,
    public_key: dict[str, Any],
) -> dict[str, Any]:
    email = _clean_email(email)

    if not _validate_email(email):
        return {
            "status": "invalid",
            "message": "Invalid email address.",
        }

    try:
        normalized_key = _normalize_public_key(
            public_key
        )
    except ValueError as exc:
        return {
            "status": "invalid",
            "message": str(exc),
        }

    key_id = _key_id(
        normalized_key
    )

    fingerprint = _fingerprint(
        normalized_key
    )

    now = _utc_now()

    initialize_registry()

    existing = _load_key(email)

    if existing is not None:
        if (
            existing["fingerprint"]
            == fingerprint
        ):
            return {
                "status": "success",
                "created": False,
                "unchanged": True,
                "message": (
                    "The registered public key "
                    "is already current."
                ),
                "key": existing,
            }

        return {
            "status": "conflict",
            "created": False,
            "message": (
                "A different public key is already "
                "registered for this email address. "
                "Key replacement requires an explicit "
                "rotation flow."
            ),
            "existing_key": {
                "email": existing["email"],
                "key_id": existing["key_id"],
                "fingerprint": existing[
                    "fingerprint"
                ],
                "algorithm": existing[
                    "algorithm"
                ],
                "created_at": existing[
                    "created_at"
                ],
                "updated_at": existing[
                    "updated_at"
                ],
            },
        }

    try:
        with sqlite3.connect(
            DATABASE_PATH
        ) as connection:
            connection.execute(
                """
                INSERT INTO crypto_public_keys (
                    email,
                    key_id,
                    fingerprint,
                    algorithm,
                    public_key_jwk,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    email,
                    key_id,
                    fingerprint,
                    SUPPORTED_ALGORITHM,
                    json.dumps(
                        normalized_key,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    now,
                    now,
                ),
            )

            connection.commit()

    except sqlite3.IntegrityError as exc:
        if "crypto_public_keys.key_id" not in str(exc):
            raise

        conflicting_key = _load_key_by_id(
            key_id
        )

        if conflicting_key is None:
            raise

        if (
            conflicting_key["email"]
            == email
            and conflicting_key["fingerprint"]
            == fingerprint
        ):
            return {
                "status": "success",
                "created": False,
                "unchanged": True,
                "message": (
                    "The registered public key "
                    "is already current."
                ),
                "key": conflicting_key,
            }

        return {
            "status": "conflict",
            "created": False,
            "message": (
                "This public encryption key is already "
                "registered to another email address. "
                "The key was not registered again."
            ),
            "existing_key": {
                "email": conflicting_key[
                    "email"
                ],
                "key_id": conflicting_key[
                    "key_id"
                ],
                "fingerprint": conflicting_key[
                    "fingerprint"
                ],
                "algorithm": conflicting_key[
                    "algorithm"
                ],
                "created_at": conflicting_key[
                    "created_at"
                ],
                "updated_at": conflicting_key[
                    "updated_at"
                ],
            },
        }

    return {
        "status": "success",
        "created": True,
        "unchanged": False,
        "message": (
            "Public encryption key registered."
        ),
        "key": {
            "email": email,
            "key_id": key_id,
            "fingerprint": fingerprint,
            "algorithm": SUPPORTED_ALGORITHM,
            "public_key": normalized_key,
            "created_at": now,
            "updated_at": now,
        },
    }


def get_public_key(
    email: str,
) -> dict[str, Any] | None:
    email = _clean_email(email)

    if not _validate_email(email):
        return None

    return _load_key(email)


def rotate_public_key(
    *,
    email: str,
    public_key: dict[str, Any],
) -> dict[str, Any]:
    """
    Explicit key-rotation flow.

    Used when the browser that owns the mailbox no longer holds the
    private key matching the registered public key (new device,
    cleared browser storage, lost key). Without rotation, senders keep
    encrypting to the stale key and the recipient can never decrypt.

    The previous public key is moved to crypto_key_history.
    """

    email = _clean_email(email)

    if not _validate_email(email):
        return {
            "status": "invalid",
            "message": "Invalid email address.",
        }

    try:
        normalized_key = _normalize_public_key(
            public_key
        )
    except ValueError as exc:
        return {
            "status": "invalid",
            "message": str(exc),
        }

    existing = _load_key(email)

    if existing is None:
        return register_public_key(
            email=email,
            public_key=normalized_key,
        )

    key_id = _key_id(
        normalized_key
    )

    fingerprint = _fingerprint(
        normalized_key
    )

    if existing["fingerprint"] == fingerprint:
        return {
            "status": "success",
            "created": False,
            "unchanged": True,
            "rotated": False,
            "message": (
                "The registered public key "
                "is already current."
            ),
            "key": existing,
        }

    conflicting_key = _load_key_by_id(
        key_id
    )

    if (
        conflicting_key is not None
        and conflicting_key["email"] != email
    ):
        return {
            "status": "conflict",
            "message": (
                "This public encryption key is already "
                "registered to another email address."
            ),
        }

    now = _utc_now()

    with sqlite3.connect(
        DATABASE_PATH
    ) as connection:
        connection.execute(
            """
            INSERT INTO crypto_key_history (
                email,
                key_id,
                fingerprint,
                algorithm,
                public_key_jwk,
                created_at,
                retired_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                existing["email"],
                existing["key_id"],
                existing["fingerprint"],
                existing["algorithm"],
                json.dumps(
                    existing["public_key"],
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                existing["created_at"],
                now,
            ),
        )

        connection.execute(
            """
            UPDATE crypto_public_keys
            SET
                key_id = ?,
                fingerprint = ?,
                algorithm = ?,
                public_key_jwk = ?,
                created_at = ?,
                updated_at = ?,
                source = 'mailbox'
            WHERE email = ?
            """,
            (
                key_id,
                fingerprint,
                SUPPORTED_ALGORITHM,
                json.dumps(
                    normalized_key,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                now,
                now,
                email,
            ),
        )

        connection.commit()

    return {
        "status": "success",
        "created": False,
        "unchanged": False,
        "rotated": True,
        "message": (
            "Public encryption key rotated. Messages "
            "encrypted to the previous key can only be "
            "decrypted by a device that still holds the "
            "previous private key."
        ),
        "previous_key_id": existing["key_id"],
        "key": _load_key(email),
    }


def import_contact_key(
    *,
    email: str,
    public_key: dict[str, Any],
    replace: bool = False,
) -> dict[str, Any]:
    """
    Imports a recipient's public key card so messages can be encrypted
    to someone whose mailbox is not authenticated on this instance.

    Only public keys are involved. Trust is established out of band by
    comparing the fingerprint with the recipient.
    """

    email = _clean_email(email)

    if not _validate_email(email):
        return {
            "status": "invalid",
            "message": "Invalid email address.",
        }

    existing = _load_key(email)

    if existing is not None:
        try:
            fingerprint = _fingerprint(
                _normalize_public_key(
                    public_key
                )
            )
        except ValueError as exc:
            return {
                "status": "invalid",
                "message": str(exc),
            }

        if (
            existing["fingerprint"] != fingerprint
            and not replace
        ):
            return {
                "status": "conflict",
                "message": (
                    "A different key is already stored for "
                    "this recipient. Verify the new fingerprint "
                    "with the recipient, then import again with "
                    "replace enabled."
                ),
                "existing_key": {
                    "email": existing["email"],
                    "key_id": existing["key_id"],
                    "fingerprint": existing["fingerprint"],
                },
            }

        result = rotate_public_key(
            email=email,
            public_key=public_key,
        )
    else:
        result = register_public_key(
            email=email,
            public_key=public_key,
        )

    if result.get("status") == "success":
        with sqlite3.connect(
            DATABASE_PATH
        ) as connection:
            connection.execute(
                """
                UPDATE crypto_public_keys
                SET source = 'contact_card'
                WHERE email = ?
                """,
                (email,),
            )

            connection.commit()

        result["key"] = _load_key(email)

    return result


def get_key_history(
    email: str,
) -> list[dict[str, Any]]:
    email = _clean_email(email)

    if not _validate_email(email):
        return []

    initialize_registry()

    with sqlite3.connect(
        DATABASE_PATH
    ) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                key_id,
                fingerprint,
                algorithm,
                created_at,
                retired_at
            FROM crypto_key_history
            WHERE email = ?
            ORDER BY id DESC
            """,
            (email,),
        ).fetchall()

    return [dict(row) for row in rows]


def assess_recipient_key(
    email: str,
) -> dict[str, Any]:
    email = _clean_email(email)

    if not _validate_email(email):
        return {
            "status": "invalid",
            "recipient": email,
            "available": False,
            "message": "Invalid email address.",
        }

    key = _load_key(email)

    if key is None:
        return {
            "status": "success",
            "recipient": email,
            "available": False,
            "trusted": False,
            "algorithm": None,
            "key_id": None,
            "fingerprint": None,
            "message": (
                "No SecureMailScope encryption key is "
                "registered for this recipient."
            ),
        }

    return {
        "status": "success",
        "recipient": email,
        "available": True,
        "trusted": False,
        "trust_model": (
            "imported_contact_card"
            if key.get("source") == "contact_card"
            else "self_asserted_registry"
        ),
        "algorithm": key["algorithm"],
        "key_id": key["key_id"],
        "fingerprint": key["fingerprint"],
        "created_at": key["created_at"],
        "updated_at": key["updated_at"],
        # Included so the sender can encrypt without a second
        # round-trip to /api/crypto/keys.
        "key": key,
        "message": (
            "An encryption key is available. "
            "Its fingerprint should be verified before "
            "treating the recipient identity as trusted."
        ),
    }