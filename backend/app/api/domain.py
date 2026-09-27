from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.domain_assessment import (
    analyze_domain,
    is_valid_domain,
)
from app.services.security.recommendations import (
    build_domain_recommendations,
)


router = APIRouter(
    prefix="/api/domain",
    tags=["Domain Analysis"],
)


class DomainRequest(BaseModel):
    domain: str


@router.post("/analyze")
def analyze_domain_endpoint(
    request: DomainRequest,
):
    domain = request.domain.strip().lower().rstrip(".")

    if not domain:
        raise HTTPException(
            status_code=400,
            detail="A domain name is required.",
        )

    if not is_valid_domain(domain):
        raise HTTPException(
            status_code=400,
            detail="Invalid domain name.",
        )

    result = analyze_domain(domain)

    if result.get("status") != "success":
        return result

    recommendations = build_domain_recommendations(
        domain=domain,
        security=result["security"],
        risk=result["risk"],
        pqc=result["pqc"],
        mta_sts=result["mta_sts"],
    )

    result["recommendations"] = recommendations

    return result