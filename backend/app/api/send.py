from email.utils import parseaddr

from fastapi import (
    APIRouter,
    File,
    Form,
    HTTPException,
    UploadFile,
)
from fastapi.concurrency import run_in_threadpool

from app.services.domain_assessment import analyze_domain
from app.services.email_sender import (
    get_connected_mailbox,
    send_connected_email,
)
from app.services.security.pre_send import (
    build_pre_send_security_decision,
)
from app.services.security.recommendations import (
    build_domain_recommendations,
)


router = APIRouter(
    prefix="/api/send",
    tags=["Email Sending"],
)


MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024
MAX_TOTAL_ATTACHMENT_SIZE = 10 * 1024 * 1024
MAX_ATTACHMENT_COUNT = 10

# An encrypted envelope carries the attachments inside the ciphertext
# (base64 inside JSON, then base64url), so it is ~1.8x the attachment
# size. It is uploaded as a file part because plain multipart text
# fields are capped at 1 MB by Starlette.
MAX_ENVELOPE_SIZE = 25 * 1024 * 1024


def _extract_email_address(
    email_value: str,
) -> str:
    _, address = parseaddr(email_value)

    return address.strip().lower()


def _extract_domain(
    email_address: str,
) -> str:
    if "@" not in email_address:
        return ""

    return (
        email_address
        .rsplit("@", 1)[1]
        .strip()
        .lower()
        .rstrip(".")
    )


def _validate_email_address(
    email_address: str,
) -> bool:
    if not email_address or "@" not in email_address:
        return False

    local_part, domain = email_address.rsplit(
        "@",
        1,
    )

    return (
        bool(local_part)
        and bool(domain)
        and "." in domain
        and not domain.startswith(".")
        and not domain.endswith(".")
    )


def _extract_domain_result(
    domain_result: dict,
) -> dict:
    if not isinstance(
        domain_result,
        dict,
    ):
        return {}

    nested_result = domain_result.get(
        "result"
    )

    if isinstance(
        nested_result,
        dict,
    ):
        return nested_result

    return domain_result


def _extract_recommendations(
    result: dict,
) -> list[dict]:
    recommendations = result.get(
        "recommendations",
        [],
    )

    return (
        recommendations
        if isinstance(
            recommendations,
            list,
        )
        else []
    )


def _safe_filename(
    filename: str | None,
) -> str:
    if not filename:
        return "attachment"

    filename = filename.replace(
        "\\",
        "/",
    )

    filename = filename.rsplit(
        "/",
        1,
    )[-1].strip()

    if not filename:
        return "attachment"

    if filename in {
        ".",
        "..",
    }:
        return "attachment"

    return filename[:255]


@router.get("/account")
def get_send_account():
    """
    Returns only the mailbox explicitly connected by the user.

    Stored or configured accounts are never automatically selected.
    """

    return {
        "status": "success",
        "account": get_connected_mailbox(),
    }


@router.post("/check-recipient")
def check_recipient_security(
    request: dict,
):
    """
    Performs the live recipient-domain security assessment used
    by the pre-send security workflow.
    """

    recipient_value = request.get(
        "recipient_email",
        "",
    )

    recipient_email = _extract_email_address(
        str(recipient_value)
    )

    if not _validate_email_address(
        recipient_email
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid recipient email address.",
        )

    domain = _extract_domain(
        recipient_email
    )

    if not domain:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unable to determine the "
                "recipient domain."
            ),
        )

    try:
        domain_result = analyze_domain(
            domain
        )

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to assess the recipient "
                f"domain: {exc}"
            ),
        ) from exc

    result = _extract_domain_result(
        domain_result
    )

    if result.get("status") != "success":
        return result

    security = result.get(
        "security",
        {},
    )

    if not isinstance(
        security,
        dict,
    ):
        security = {}

    risk = result.get(
        "risk",
        {},
    )

    if not isinstance(
        risk,
        dict,
    ):
        risk = {}

    pqc = result.get(
        "pqc",
        {},
    )

    if not isinstance(
        pqc,
        dict,
    ):
        pqc = {}

    mta_sts = result.get(
        "mta_sts",
        {},
    )

    if not isinstance(
        mta_sts,
        dict,
    ):
        mta_sts = {}

    recommendations = _extract_recommendations(
        result
    )

    if not recommendations:
        recommendations = (
            build_domain_recommendations(
                domain=domain,
                security=security,
                risk=risk,
                pqc=pqc,
                mta_sts=mta_sts,
            )
        )

    security_for_pre_send = {
        **security,
        "risk": risk,
    }

    pre_send = build_pre_send_security_decision(
        recipient_email=recipient_email,
        domain=domain,
        security=security_for_pre_send,
        recommendations=recommendations,
        mta_sts=mta_sts,
    )

    return {
        "status": "success",
        "recipient": recipient_email,
        "domain": domain,
        # Top-level copies: the frontend and the AI engine read these.
        "risk": risk,
        "pqc": pqc,
        "security": {
            "risk": risk,
            "pqc": pqc,
            "domain_summary": security.get(
                "domain_summary",
                {},
            ),
            "mx_host_assessments": security.get(
                "mx_host_assessments",
                [],
            ),
            "findings": security.get(
                "findings",
                [],
            ),
        },
        "mta_sts": mta_sts,
        "recommendations": recommendations,
        "pre_send": pre_send,
        "assessment_source": result.get(
            "assessment_source",
            "live_domain_assessment",
        ),
    }


@router.post("/email")
async def send_email_endpoint(
    recipient_email: str = Form(...),
    subject: str = Form(default=""),
    body: str = Form(default=""),
    attachments: list[UploadFile] | None = File(
        default=None
    ),
    body_file: UploadFile | None = File(
        default=None
    ),
):
    """
    Sends using the mailbox explicitly connected by the user.

    Only the recipient is mandatory for the message itself.
    Subject, body, and attachments are optional.

    The frontend never supplies SMTP credentials.

    Attachments are read into memory only for the duration of
    the request and are passed to the sender using the field name
    expected by email_sender.py.
    """

    account = get_connected_mailbox()

    if not account["connected"]:
        raise HTTPException(
            status_code=503,
            detail=(
                "No sending mailbox has been selected. "
                "Connect a mailbox before sending."
            ),
        )

    recipient_email = _extract_email_address(
        recipient_email
    )

    if not _validate_email_address(
        recipient_email
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid recipient email address.",
        )

    if body_file is not None:
        body_bytes = await body_file.read(
            MAX_ENVELOPE_SIZE + 1
        )

        if len(body_bytes) > MAX_ENVELOPE_SIZE:
            raise HTTPException(
                status_code=400,
                detail=(
                    "The encrypted message exceeds "
                    "the 25 MB limit."
                ),
            )

        body = body_bytes.decode(
            "utf-8",
            errors="replace",
        )

    subject = subject.strip()
    body = body.strip()

    uploaded_files = attachments or []

    if len(uploaded_files) > MAX_ATTACHMENT_COUNT:
        raise HTTPException(
            status_code=400,
            detail=(
                f"A maximum of {MAX_ATTACHMENT_COUNT} "
                "attachments can be submitted."
            ),
        )

    attachment_payloads = []

    total_size = 0

    for uploaded_file in uploaded_files:
        filename = _safe_filename(
            uploaded_file.filename
        )

        try:
            file_data = await uploaded_file.read()

        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Unable to read attachment "
                    f"'{filename}'."
                ),
            ) from exc

        file_size = len(file_data)

        if file_size <= 0:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Attachment '{filename}' "
                    "is empty."
                ),
            )

        if file_size > MAX_ATTACHMENT_SIZE:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Attachment '{filename}' exceeds "
                    "the 10 MB attachment limit."
                ),
            )

        total_size += file_size

        if total_size > MAX_TOTAL_ATTACHMENT_SIZE:
            raise HTTPException(
                status_code=400,
                detail=(
                    "The total attachment size "
                    "cannot exceed 10 MB."
                ),
            )

        content_type = (
            uploaded_file.content_type
            or "application/octet-stream"
        )

        if "/" not in content_type:
            content_type = (
                "application/octet-stream"
            )

        attachment_payloads.append(
            {
                "filename": filename,
                "content_type": content_type,
                "content": file_data,
            }
        )

    # SMTP submission and OAuth refresh are blocking network calls.
    # Running them in the threadpool keeps the API responsive.
    result = await run_in_threadpool(
        send_connected_email,
        recipient_email=recipient_email,
        subject=subject,
        body=body,
        attachments=attachment_payloads,
    )

    status = result.get(
        "status",
        "error",
    )

    if status == "not_connected":
        raise HTTPException(
            status_code=503,
            detail=result.get(
                "message",
                "No sending mailbox is connected.",
            ),
        )

    if status == "invalid":
        raise HTTPException(
            status_code=400,
            detail=result.get(
                "message",
                "Invalid email request.",
            ),
        )

    if status == "authentication_error":
        raise HTTPException(
            status_code=401,
            detail=result.get(
                "message",
                "Mailbox authentication failed.",
            ),
        )

    if status == "connection_error":
        raise HTTPException(
            status_code=503,
            detail=result.get(
                "message",
                "Unable to connect to the SMTP server.",
            ),
        )

    if status == "smtp_error":
        raise HTTPException(
            status_code=502,
            detail=result.get(
                "message",
                "SMTP submission failed.",
            ),
        )

    if status == "error":
        raise HTTPException(
            status_code=500,
            detail=result.get(
                "message",
                "Unable to send email.",
            ),
        )

    if status != "success":
        raise HTTPException(
            status_code=500,
            detail=result.get(
                "message",
                "Unable to send email.",
            ),
        )

    return {
        "status": "success",
        "message": "Email submitted successfully.",
        "result": {
            "sent": True,
            "sender": result.get(
                "sender",
                account["sender_email"],
            ),
            "recipient": recipient_email,
            "smtp": result.get(
                "smtp"
            ),
            "attachments": result.get(
                "attachments",
                [],
            ),
        },
    }
