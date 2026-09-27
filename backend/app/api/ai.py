from fastapi import APIRouter, HTTPException

from app.services.ai import (
    analyze_security_posture,
)


router = APIRouter(
    prefix="/api/ai",
    tags=["AI Security Intelligence"],
)


@router.post("/assess")
def assess_security_with_ai(
    request: dict,
):
    if not isinstance(
        request,
        dict,
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "A security evidence object "
                "is required."
            ),
        )

    try:
        return analyze_security_posture(
            request
        )

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "AI security assessment failed: "
                f"{exc}"
            ),
        ) from exc