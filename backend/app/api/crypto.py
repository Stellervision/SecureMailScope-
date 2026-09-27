from fastapi import APIRouter, HTTPException

from app.services.crypto import (
    assess_recipient_key,
    get_key_history,
    get_public_key,
    import_contact_key,
    register_public_key,
    rotate_public_key,
)
from app.services.email_sender import (
    list_all_mailboxes,
)


router = APIRouter(
    prefix="/api/crypto",
    tags=["End-to-End Cryptography"],
)


def _require_owned_mailbox(
    email: str,
) -> None:
    """
    A public key may only be published for a mailbox that has been
    authenticated in this SecureMailScope instance (OAuth or SMTP
    credential). Otherwise anyone could publish their own key for
    someone else's address and silently read messages meant for them.
    """

    email = str(email or "").strip().lower()

    owned = {
        str(
            account.get("sender_email", "")
        ).strip().lower()
        for account in list_all_mailboxes()
    }

    if email not in owned:
        raise HTTPException(
            status_code=403,
            detail=(
                "Encryption keys can only be published for "
                "a mailbox that is authenticated in "
                "SecureMailScope."
            ),
        )


def _raise_for_status(
    result: dict,
    default_message: str,
) -> None:
    if result.get("status") == "invalid":
        raise HTTPException(
            status_code=400,
            detail=result.get(
                "message",
                default_message,
            ),
        )

    if result.get("status") == "conflict":
        raise HTTPException(
            status_code=409,
            detail={
                "message": result.get(
                    "message",
                    default_message,
                ),
                "existing_key": result.get(
                    "existing_key"
                ),
            },
        )


@router.post("/keys/register")
def register_recipient_public_key(
    request: dict,
):
    email = request.get(
        "email",
        "",
    )

    public_key = request.get(
        "public_key"
    )

    _require_owned_mailbox(email)

    result = register_public_key(
        email=str(email),
        public_key=public_key,
    )

    _raise_for_status(
        result,
        "Invalid public key registration.",
    )

    return result


@router.post("/keys/rotate")
def rotate_recipient_public_key(
    request: dict,
):
    email = request.get(
        "email",
        "",
    )

    public_key = request.get(
        "public_key"
    )

    _require_owned_mailbox(email)

    result = rotate_public_key(
        email=str(email),
        public_key=public_key,
    )

    _raise_for_status(
        result,
        "Unable to rotate the public key.",
    )

    return result


@router.post("/keys/import-contact")
def import_recipient_contact_key(
    request: dict,
):
    """
    Imports a recipient's public key card (public key only) so this
    instance can encrypt to a recipient whose mailbox is connected to a
    different SecureMailScope instance, e.g. on another laptop.
    """

    email = str(
        request.get("email", "")
    ).strip().lower()

    owned = {
        str(
            account.get("sender_email", "")
        ).strip().lower()
        for account in list_all_mailboxes()
    }

    if email in owned:
        raise HTTPException(
            status_code=409,
            detail=(
                "This mailbox is authenticated here. Its key is "
                "managed by the End-to-end identity panel, not "
                "by contact cards."
            ),
        )

    result = import_contact_key(
        email=email,
        public_key=request.get(
            "public_key"
        ),
        replace=bool(
            request.get(
                "replace",
                False,
            )
        ),
    )

    _raise_for_status(
        result,
        "Unable to import the contact key.",
    )

    return result


@router.get("/keys")
def get_recipient_public_key(
    email: str,
):
    result = get_public_key(
        email
    )

    if result is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "No SecureMailScope encryption key "
                "is registered for this recipient."
            ),
        )

    return {
        "status": "success",
        "key": result,
    }


@router.get("/keys/history")
def get_recipient_key_history(
    email: str,
):
    return {
        "status": "success",
        "email": str(email or "").strip().lower(),
        "history": get_key_history(email),
    }


@router.post("/assess-recipient")
def assess_recipient_encryption_key(
    request: dict,
):
    email = request.get(
        "email",
        "",
    )

    result = assess_recipient_key(
        str(email)
    )

    if result.get("status") == "invalid":
        raise HTTPException(
            status_code=400,
            detail=result.get(
                "message",
                "Invalid recipient email address.",
            ),
        )

    return result
