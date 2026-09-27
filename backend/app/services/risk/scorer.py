SEVERITY_DEDUCTIONS = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
    "info": 0,
    "unknown": 0,
}


def calculate_security_score(summary: dict) -> dict:
    severity_counts = summary.get("severity_counts", {})

    deductions = 0

    for severity, deduction in SEVERITY_DEDUCTIONS.items():
        count = severity_counts.get(severity, 0)
        deductions += count * deduction

    score = max(0, 100 - deductions)

    if score >= 90:
        risk_level = "low"
    elif score >= 70:
        risk_level = "medium"
    elif score >= 40:
        risk_level = "high"
    else:
        risk_level = "critical"

    return {
        "score": score,
        "risk_level": risk_level,
        "deductions": deductions,
    }