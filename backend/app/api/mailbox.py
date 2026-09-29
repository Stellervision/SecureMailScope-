import html
import json

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.services.email_sender import (
    add_mailbox,
    attach_mailbox,
    begin_oauth,
    connect_mailbox,
    detach_mailbox,
    disconnect_mailbox,
    get_connected_mailbox,
    handle_oauth_callback,
    list_all_mailboxes,
    list_attached_mailboxes,
    list_available_mailboxes,
    oauth_configuration,
    remove_mailbox,
)
from app.services.mail.mock import MockMailProvider
from app.services.mail.message_analyzer import (
    analyze_mailbox_message,
)


router = APIRouter(
    prefix="/api/mailbox",
    tags=["Mailbox"],
)


mail_provider = MockMailProvider()


class MailboxAccountRequest(BaseModel):
    account_id: str = Field(
        min_length=1
    )


class MailboxAddRequest(BaseModel):
    sender_email: str = Field(
        min_length=3
    )

    username: str = Field(
        min_length=1
    )

    password: str = Field(
        min_length=1
    )

    smtp_host: str = Field(
        min_length=1
    )

    smtp_port: int = Field(
        default=587,
        ge=1,
        le=65535,
    )

    security_mode: str = Field(
        default="starttls"
    )

    provider: str | None = None


# ---------------------------------------------------------------------------
# Mailbox listing
# ---------------------------------------------------------------------------


@router.get("/accounts")
def get_attached_accounts():
    """
    Returns ONLY mailboxes explicitly attached by the user.
    """

    accounts = list_attached_mailboxes()

    return {
        "status": "success",
        "count": len(accounts),
        "accounts": accounts,
    }


@router.get("/available-accounts")
def get_available_accounts():
    """
    Returns stored/configured accounts that are not attached.
    """

    accounts = list_available_mailboxes()

    return {
        "status": "success",
        "count": len(accounts),
        "accounts": accounts,
    }


@router.get("/configured-accounts")
def get_configured_accounts():
    """
    Returns all saved/configured mailbox metadata.

    Credentials and OAuth tokens are never returned.
    """

    accounts = list_all_mailboxes()

    return {
        "status": "success",
        "count": len(accounts),
        "accounts": accounts,
    }


# ---------------------------------------------------------------------------
# Generic/custom SMTP mailbox creation
# ---------------------------------------------------------------------------


@router.post("/accounts")
def create_account(
    request: MailboxAddRequest,
):
    """
    Saves a generic SMTP mailbox.

    Saving does NOT attach or connect it.

    Provider mailboxes (Gmail, Microsoft) may also be saved with a
    provider App Password; OAuth remains available as the alternative
    sign-in for those providers.
    """

    result = add_mailbox(
        sender_email=request.sender_email,
        username=request.username,
        password=request.password,
        smtp_host=request.smtp_host,
        smtp_port=request.smtp_port,
        security_mode=request.security_mode,
        provider=request.provider,
    )

    if result["status"] == "invalid":
        raise HTTPException(
            status_code=400,
            detail=result["message"],
        )

    if result["status"] == "exists":
        raise HTTPException(
            status_code=409,
            detail=result["message"],
        )

    if result["status"] != "success":
        raise HTTPException(
            status_code=500,
            detail=result.get(
                "message",
                "Unable to save mailbox account.",
            ),
        )

    return result


@router.delete("/accounts/{account_id}")
def delete_account(
    account_id: str,
):
    """
    Permanently removes a saved mailbox.

    This also clears its attached/active state.
    """

    result = remove_mailbox(
        account_id
    )

    if result["status"] == "invalid":
        raise HTTPException(
            status_code=400,
            detail=result["message"],
        )

    if result["status"] == "not_found":
        raise HTTPException(
            status_code=404,
            detail=result["message"],
        )

    if result["status"] == "not_removable":
        raise HTTPException(
            status_code=409,
            detail=result["message"],
        )

    if result["status"] != "success":
        raise HTTPException(
            status_code=500,
            detail=result.get(
                "message",
                "Unable to remove mailbox account.",
            ),
        )

    return result


# ---------------------------------------------------------------------------
# OAuth
# ---------------------------------------------------------------------------


@router.get("/oauth/{provider}/configuration")
def get_oauth_configuration(
    provider: str,
):
    """
    Returns whether provider OAuth is configured on the backend.

    Supported providers:
        - Gmail
        - Microsoft
    """

    provider_value = provider.strip().lower()

    if provider_value in {
        "google",
        "gmail",
    }:
        provider_value = "Gmail"

    elif provider_value in {
        "microsoft",
        "outlook",
        "office365",
    }:
        provider_value = "Microsoft"

    else:
        raise HTTPException(
            status_code=400,
            detail=(
                "Supported OAuth providers are "
                "Google and Microsoft."
            ),
        )

    return oauth_configuration(
        provider_value
    )


@router.get("/oauth/{provider}/start")
def start_oauth(
    provider: str,
):
    """
    Starts provider OAuth.

    The frontend should open the returned authorization URL
    in a popup/window.

    Completing OAuth does NOT attach or connect the mailbox.
    """

    provider_value = provider.strip().lower()

    if provider_value in {
        "google",
        "gmail",
    }:
        provider_value = "Gmail"

    elif provider_value in {
        "microsoft",
        "outlook",
        "office365",
    }:
        provider_value = "Microsoft"

    else:
        raise HTTPException(
            status_code=400,
            detail=(
                "Supported OAuth providers are "
                "Google and Microsoft."
            ),
        )

    result = begin_oauth(
        provider_value
    )

    if result["status"] == "not_configured":
        raise HTTPException(
            status_code=503,
            detail=result["message"],
        )

    if result["status"] == "invalid":
        raise HTTPException(
            status_code=400,
            detail=result["message"],
        )

    return result


@router.get(
    "/oauth/{provider}/callback",
    response_class=HTMLResponse,
)
def oauth_callback(
    provider: str,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
):
    """
    Handles the OAuth provider callback.

    The account is persisted server-side, but is deliberately NOT
    attached or connected automatically.

    A small callback page notifies the originating frontend window
    and then closes the OAuth popup.
    """

    provider_value = provider.strip().lower()

    if provider_value in {
        "google",
        "gmail",
    }:
        provider_value = "Gmail"

    elif provider_value in {
        "microsoft",
        "outlook",
        "office365",
    }:
        provider_value = "Microsoft"

    else:
        provider_value = provider

    result = handle_oauth_callback(
        provider_value,
        code=code,
        state=state,
        error=error,
        error_description=error_description,
    )

    # Never expose tokens or credentials to the browser.
    safe_result = {
        "status": result.get(
            "status",
            "error",
        ),
        "provider": result.get(
            "provider",
            provider_value,
        ),
        "message": result.get(
            "message",
            "",
        ),
    }

    account = result.get(
        "account"
    )

    if isinstance(account, dict):
        safe_result["account"] = account

    title = (
        "Mailbox connected"
        if result.get("status") == "success"
        else "Mailbox authorization"
    )

    return HTMLResponse(
        content=f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >
    <title>{html.escape(title)}</title>
    <style>
        body {{
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #0b1020;
            color: #ffffff;
            font-family:
                Inter,
                system-ui,
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                sans-serif;
        }}

        .card {{
            width: min(420px, calc(100vw - 40px));
            box-sizing: border-box;
            padding: 28px;
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 18px;
            background: rgba(255,255,255,0.06);
            text-align: center;
        }}

        .icon {{
            width: 48px;
            height: 48px;
            margin: 0 auto 16px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            background: rgba(255,255,255,0.10);
            font-size: 24px;
        }}

        h1 {{
            margin: 0 0 10px;
            font-size: 20px;
        }}

        p {{
            margin: 0;
            color: rgba(255,255,255,0.68);
            line-height: 1.5;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">
            {"✓" if result.get("status") == "success" else "!"}
        </div>

        <h1>
            {html.escape(title)}
        </h1>

        <p id="message">
            {html.escape(
                result.get(
                    "message",
                    "OAuth authorization completed.",
                )
            )}
        </p>
    </div>

    <script>
        const result = {json.dumps(safe_result)};

        try {{
            if (window.opener) {{
                window.opener.postMessage(
                    {{
                        type: "securemailscope-oauth-result",
                        result: result
                    }},
                    "http://localhost:5173"
                );

                window.opener.postMessage(
                    {{
                        type: "securemailscope-oauth-result",
                        result: result
                    }},
                    "http://127.0.0.1:5173"
                );
            }}
        }} catch (error) {{
            // The backend result has already been persisted.
        }}

        setTimeout(() => {{
            window.close();
        }}, 900);
    </script>
</body>
</html>
""",
    )


# ---------------------------------------------------------------------------
# Explicit attach/connect workflow
# ---------------------------------------------------------------------------


@router.post("/attach")
def attach_account(
    request: MailboxAccountRequest,
):
    """
    Explicitly attaches a mailbox.

    Attaching does not authenticate against SMTP or OAuth.
    """

    result = attach_mailbox(
        request.account_id
    )

    if result["status"] == "invalid":
        raise HTTPException(
            status_code=400,
            detail=result["message"],
        )

    if result["status"] == "not_found":
        raise HTTPException(
            status_code=404,
            detail=result["message"],
        )

    return result


@router.post("/detach")
def detach_account(
    request: MailboxAccountRequest,
):
    """
    Detaches a mailbox from the workspace.

    The saved mailbox remains available.
    """

    result = detach_mailbox(
        request.account_id
    )

    if result["status"] == "invalid":
        raise HTTPException(
            status_code=400,
            detail=result["message"],
        )

    if result["status"] == "not_attached":
        raise HTTPException(
            status_code=404,
            detail=result["message"],
        )

    return result


@router.post("/connect")
def connect_account(
    request: MailboxAccountRequest,
):
    """
    Makes an already-attached mailbox the active
    sending mailbox.
    """

    result = connect_mailbox(
        request.account_id
    )

    if result["status"] == "invalid":
        raise HTTPException(
            status_code=400,
            detail=result["message"],
        )

    if result["status"] == "not_attached":
        raise HTTPException(
            status_code=409,
            detail=result["message"],
        )

    if result["status"] == "not_found":
        raise HTTPException(
            status_code=404,
            detail=result["message"],
        )

    return result


@router.post("/disconnect")
def disconnect_account():
    """
    Disconnects the active mailbox.

    The mailbox remains saved and attached.
    """

    return disconnect_mailbox()


@router.get("/connection")
def get_connection():
    """
    Returns the currently active mailbox.
    """

    return {
        "status": "success",
        "account": get_connected_mailbox(),
    }


# ---------------------------------------------------------------------------
# Inbox
# ---------------------------------------------------------------------------


@router.get("/inbox")
def get_inbox(
    account_id: str = Query(
        default="",
    ),
    # The Gmail service caps a page at 50 messages.
    limit: int = Query(
        default=20,
        ge=1,
        le=50,
    ),
):
    """
    Returns inbox messages for the requested mailbox.

    The demo mailbox continues to use the mock provider.

    Real provider mailboxes are delegated to the provider mailbox
    retrieval service. That service is responsible for OAuth token
    handling and provider-specific API access.
    """

    if not account_id:
        return {
            "status": "success",
            "account_id": None,
            "count": 0,
            "messages": [],
            "integration": "none",
            "message": (
                "No mailbox is connected."
            ),
        }

    if account_id == "demo-account":
        try:
            messages = mail_provider.list_messages(
                account_id=account_id,
                limit=limit,
            )

            return {
                "status": "success",
                "account_id": account_id,
                "count": len(messages),
                "messages": messages,
                "integration": "mock",
            }

        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=str(exc),
            )

    try:
        from app.services.email_sender import (
            list_mailbox_messages,
        )

        messages = list_mailbox_messages(
            account_id=account_id,
            limit=limit,
        )

        if not isinstance(messages, list):
            raise HTTPException(
                status_code=502,
                detail=(
                    "Mailbox provider returned an invalid "
                    "inbox response."
                ),
            )

        return {
            "status": "success",
            "account_id": account_id,
            "count": len(messages),
            "messages": messages,
            "integration": "provider_api",
        }

    except HTTPException:
        raise

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except RuntimeError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Unable to retrieve mailbox messages: {exc}",
        ) from exc


# ---------------------------------------------------------------------------
# Message
# ---------------------------------------------------------------------------


@router.get("/message/{message_id}")
def get_message(
    message_id: str,
    account_id: str = Query(
        default="",
    ),
):
    """
    Retrieves and analyzes a message from the requested mailbox.

    The demo mailbox continues to use the mock provider.

    Real provider messages are retrieved through the provider mailbox
    retrieval service.

    SecureMailScope E2E envelopes remain opaque to the backend and
    are passed to the frontend for local decryption.
    """

    if not account_id:
        raise HTTPException(
            status_code=409,
            detail="No mailbox is connected.",
        )

    if account_id == "demo-account":
        try:
            message = mail_provider.get_message(
                account_id=account_id,
                message_id=message_id,
            )

            analysis = analyze_mailbox_message(
                message
            )

            return {
                "status": "success",
                "message": message,
                "analysis": analysis,
                "integration": "mock",
            }

        except ValueError as exc:
            raise HTTPException(
                status_code=404,
                detail=str(exc),
            ) from exc

        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=str(exc),
            ) from exc

    try:
        from app.services.email_sender import (
            get_mailbox_message,
        )

        message = get_mailbox_message(
            account_id=account_id,
            message_id=message_id,
        )

        if not isinstance(message, dict):
            raise HTTPException(
                status_code=502,
                detail=(
                    "Mailbox provider returned an invalid message."
                ),
            )

        # get_mailbox_message() returns the normalized message
        # dictionary directly. It does not return a wrapper containing
        # status/message fields.
        if message.get("status") in {
            "not_found",
            "not_supported",
        }:
            status = message.get("status")

            if status == "not_found":
                raise HTTPException(
                    status_code=404,
                    detail=message.get(
                        "message",
                        "Mailbox message was not found.",
                    ),
                )

            raise HTTPException(
                status_code=409,
                detail=message.get(
                    "message",
                    "Message retrieval is not supported for this provider.",
                ),
            )

        analysis = analyze_mailbox_message(
            message
        )

        return {
            "status": "success",
            "message": message,
            "analysis": analysis,
            "integration": "provider_api",
        }

    except HTTPException:
        raise

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except RuntimeError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Unable to retrieve mailbox message: {exc}",
        ) from exc