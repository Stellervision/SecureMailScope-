import json
import os
import re
import urllib.error
import urllib.request
from typing import Any


AI_SYSTEM_PROMPT = """
You are SecureMailScope's security interpretation engine.

Your job is to interpret ONLY the deterministic security evidence supplied by the application.
Never invent observations, never convert unknown/unavailable into insecure, and never claim end-to-end
security unless message-level cryptographic evidence actually supports it.

Important distinctions:
- observed = directly measured or explicitly asserted by the supplied evidence source
- unknown = the system could not determine the property
- unavailable = the environment or dependency prevented observation
- inferred = a bounded interpretation derived from observed evidence
- self_asserted_registry = a registered key exists but identity/trust has not been independently verified

Transport security (SMTP/STARTTLS/TLS/MTA-STS/DANE) is separate from message-level E2E encryption.
PQC readiness is migration readiness, not proof of quantum safety.
Do not make cryptographic decisions; explain evidence and recommend remediation.

Return concise, evidence-linked JSON only.
""".strip()


def _clean_text(
    value: Any,
    limit: int = 1200,
) -> str:
    if value is None:
        return ""

    text = str(value).strip()

    return text[:limit]


def _normalize_evidence(
    payload: dict[str, Any],
) -> dict[str, Any]:
    """
    Keep security evidence only.

    Message content, attachments, credentials and private keys
    must never be forwarded to the AI provider.
    """

    assessment = (
        payload.get("assessment")
        or payload
    )

    e2e = (
        assessment.get("e2e")
        or {}
    )

    pre_send = (
        assessment.get("pre_send")
        or {}
    )

    security = assessment.get(
        "security"
    )

    if not isinstance(
        security,
        dict,
    ):
        security = {}

    # check-recipient returns risk/pqc both at the top level and under
    # "security". Only one location used to be read for each, so the
    # engine often received empty risk/PQC evidence.
    risk = (
        assessment.get("risk")
        or security.get("risk")
        or {}
    )

    pqc = (
        assessment.get("pqc")
        or security.get("pqc")
        or {}
    )

    # MTA-STS arrives as {"dns": {...}, "policy": {"status", "policy":
    # {"mode", ...}}}. Reading mta_sts["mode"] always returned nothing.
    mta_sts_raw = (
        assessment.get("mta_sts")
        or {}
    )

    mta_sts_policy_result = (
        mta_sts_raw.get("policy")
        if isinstance(
            mta_sts_raw.get("policy"),
            dict,
        )
        else {}
    )

    mta_sts_policy = (
        mta_sts_policy_result.get("policy")
        if isinstance(
            mta_sts_policy_result.get("policy"),
            dict,
        )
        else {}
    )

    mta_sts = {
        "mode": (
            mta_sts_raw.get("mode")
            or mta_sts_policy.get("mode")
        ),
        "status": (
            mta_sts_raw.get("status")
            or mta_sts_policy_result.get("status")
        ),
    }

    return {
        "domain": _clean_text(
            assessment.get("domain"),
            255,
        ),
        "risk": {
            "risk_level": _clean_text(
                risk.get("risk_level"),
                32,
            ),
            "score": risk.get(
                "score"
            ),
            "confidence": _clean_text(
                risk.get("confidence"),
                32,
            ),
            "observability": _clean_text(
                risk.get("observability"),
                32,
            ),
        },
        "mta_sts": {
            "mode": _clean_text(
                mta_sts.get("mode"),
                32,
            ),
            "status": _clean_text(
                mta_sts.get("status"),
                64,
            ),
        },
        "tlsa": assessment.get(
            "tlsa"
        ),
        "pqc": {
            "readiness": _clean_text(
                pqc.get("readiness"),
                32,
            ),
            "explanation": _clean_text(
                pqc.get("explanation")
                or pqc.get("assessment"),
                700,
            ),
        },
        "pre_send": {
            "decision": _clean_text(
                pre_send.get("decision"),
                32,
            ),
            "observations": (
                pre_send.get(
                    "observations"
                )
                or []
            ),
            "unknowns": (
                pre_send.get(
                    "unknowns"
                )
                or []
            ),
            "observability": (
                pre_send.get(
                    "observability"
                )
                or {}
            ),
        },
        "e2e": {
            "status": _clean_text(
                e2e.get("status"),
                32,
            ),
            "available": bool(
                e2e.get("available")
            ),
            "trusted": bool(
                e2e.get("trusted")
            ),
            "trust_model": _clean_text(
                e2e.get("trust_model"),
                64,
            ),
            "algorithm": _clean_text(
                e2e.get("algorithm"),
                64,
            ),
            "key_id": _clean_text(
                e2e.get("key_id"),
                100,
            ),
            "fingerprint": _clean_text(
                e2e.get("fingerprint"),
                200,
            ),
            "message": _clean_text(
                e2e.get("message"),
                500,
            ),
        },
        "recommendations": [
            {
                "title": _clean_text(
                    item.get("title"),
                    180,
                ),
                # Recommendations use priority/action; older callers
                # may send severity/recommendation.
                "severity": _clean_text(
                    item.get("severity")
                    or item.get("priority"),
                    32,
                ),
                "why_it_matters": _clean_text(
                    item.get(
                        "why_it_matters"
                    ),
                    700,
                ),
                "recommendation": _clean_text(
                    item.get(
                        "recommendation"
                    )
                    or item.get("action"),
                    700,
                ),
                "verification": _clean_text(
                    item.get(
                        "verification"
                    ),
                    700,
                ),
            }
            for item in (
                assessment.get(
                    "recommendations"
                )
                or []
            )
            if isinstance(
                item,
                dict,
            )
        ][:10],
    }


def _fallback_analysis(
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """
    Local evidence-correlation fallback.

    This is intentionally conservative. It is not presented as
    an LLM result when no provider is configured.
    """

    findings = []
    interpretations = []
    limitations = []

    e2e = evidence["e2e"]
    risk = evidence["risk"]
    pre_send = evidence["pre_send"]
    pqc = evidence["pqc"]

    if not e2e["available"]:
        findings.append(
            {
                "title": (
                    "Recipient E2E encryption "
                    "key is unavailable"
                ),
                "severity": "high",
                "evidence": [
                    "e2e.available=false",
                ],
                "explanation": (
                    "SecureMailScope cannot encrypt "
                    "a message to this recipient "
                    "without a compatible recipient "
                    "public encryption key."
                ),
                "recommendation": (
                    "Register a compatible "
                    "SecureMailScope recipient "
                    "encryption key before sending "
                    "an end-to-end encrypted message."
                ),
                "verification": (
                    "Run recipient security "
                    "assessment again and confirm "
                    "that a recipient key is available."
                ),
            }
        )

    elif not e2e["trusted"]:
        findings.append(
            {
                "title": (
                    "Recipient encryption key is "
                    "not independently verified"
                ),
                "severity": "medium",
                "evidence": [
                    "e2e.available=true",
                    (
                        "e2e.trust_model="
                        + (
                            e2e["trust_model"]
                            or "unknown"
                        )
                    ),
                ],
                "explanation": (
                    "A usable recipient key is "
                    "registered, but the current "
                    "registry does not independently "
                    "verify that the key belongs to "
                    "the intended human recipient."
                ),
                "recommendation": (
                    "Add an out-of-band or "
                    "provider-backed key verification "
                    "mechanism before treating the "
                    "recipient identity as "
                    "cryptographically verified."
                ),
                "verification": (
                    "Verify the key fingerprint "
                    "through an independent trusted "
                    "channel and compare it with the "
                    "registered fingerprint."
                ),
            }
        )

    else:
        interpretations.append(
            "A compatible recipient encryption "
            "key is available for message-level "
            "encryption."
        )

    if risk["risk_level"] in {
        "high",
        "critical",
    }:
        findings.append(
            {
                "title": (
                    "Transport posture contains "
                    "a high-priority finding"
                ),
                "severity": risk[
                    "risk_level"
                ],
                "evidence": [
                    (
                        "risk.risk_level="
                        + risk["risk_level"]
                    ),
                    (
                        "risk.confidence="
                        + (
                            risk["confidence"]
                            or "unknown"
                        )
                    ),
                ],
                "explanation": (
                    "The deterministic transport "
                    "assessment reported a "
                    "high-priority risk level."
                ),
                "recommendation": (
                    "Review the underlying transport "
                    "findings and remediate only "
                    "conditions supported by "
                    "observed evidence."
                ),
                "verification": (
                    "Repeat the live recipient-domain "
                    "assessment after remediation."
                ),
            }
        )

    elif risk["risk_level"] == "unknown":
        limitations.append(
            "Transport risk remains unknown because "
            "the available environment did not "
            "establish enough live evidence for a "
            "definitive TLS posture."
        )

    elif risk["risk_level"]:
        interpretations.append(
            "The deterministic transport assessment "
            "reports a "
            f"{risk['risk_level']} risk level with "
            f"{risk['confidence'] or 'unknown'} "
            "confidence."
        )

    if pre_send.get("unknowns"):
        limitations.append(
            "Some transport properties could not "
            "be observed from the current "
            "assessment environment; unknown does "
            "not mean insecure."
        )

    if pqc.get("readiness") in {
        "unknown",
        "limited",
    }:
        limitations.append(
            "PQC readiness is an assessment "
            "indicator; TLS 1.3 or forward secrecy "
            "alone does not demonstrate "
            "post-quantum cryptography."
        )

    if (
        evidence["mta_sts"]["mode"]
        == "enforce"
    ):
        interpretations.append(
            "MTA-STS enforcement was observed "
            "for the recipient domain; this "
            "strengthens transport-policy "
            "expectations but does not provide "
            "message-level E2E encryption."
        )

    if not interpretations:
        interpretations.append(
            "The available evidence is insufficient "
            "for a stronger security conclusion."
        )

    if not limitations and not findings:
        limitations.append(
            "No material limitation beyond the "
            "supplied evidence was identified by "
            "the local correlation engine."
        )

    top = findings[:5]

    if top:
        summary = (
            "SecureMailScope correlated "
            f"{len(top)} priority security "
            "finding(s) from deterministic "
            "evidence for "
            f"{evidence['domain'] or 'the recipient domain'}."
        )
    else:
        summary = (
            "SecureMailScope found no additional "
            "priority finding from the supplied "
            "evidence for "
            f"{evidence['domain'] or 'the recipient domain'}, "
            "while preserving observed and "
            "unknown states."
        )

    return {
        "executive_summary": summary,
        "security_interpretation": (
            interpretations[:6]
        ),
        "priority_findings": top,
        "limitations": limitations[:6],
    }


def _extract_response_text(
    data: dict[str, Any],
) -> str:
    output_text = data.get(
        "output_text"
    )

    if (
        isinstance(
            output_text,
            str,
        )
        and output_text.strip()
    ):
        return output_text.strip()

    parts = []

    for item in (
        data.get("output")
        or []
    ):
        for content in (
            item.get("content")
            or []
        ):
            text = content.get(
                "text"
            )

            if isinstance(
                text,
                str,
            ):
                parts.append(text)

    return "\n".join(parts).strip()


def _extract_json(
    text: str,
) -> dict[str, Any]:
    text = text.strip()

    if text.startswith("```"):
        text = re.sub(
            r"^```(?:json)?\s*",
            "",
            text,
            flags=re.I,
        )
        text = re.sub(
            r"\s*```$",
            "",
            text,
        )

    try:
        value = json.loads(text)

        if isinstance(
            value,
            dict,
        ):
            return value

    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")

    if (
        start >= 0
        and end > start
    ):
        value = json.loads(
            text[
                start : end + 1
            ]
        )

        if isinstance(
            value,
            dict,
        ):
            return value

    raise ValueError(
        "AI response did not contain "
        "a valid JSON object."
    )


def _call_llm(
    evidence: dict[str, Any],
) -> dict[str, Any]:
    api_key = os.getenv(
        "SECUREMAILSCOPE_AI_API_KEY",
        "",
    ).strip()

    if not api_key:
        raise RuntimeError(
            "AI API key is not configured."
        )

    base_url = os.getenv(
        "SECUREMAILSCOPE_AI_BASE_URL",
        "https://api.openai.com/v1",
    ).rstrip("/")

    model = os.getenv(
        "SECUREMAILSCOPE_AI_MODEL",
        "gpt-5.6-luna",
    ).strip()

    schema = {
        "type": "object",
        "properties": {
            "executive_summary": {
                "type": "string",
            },
            "security_interpretation": {
                "type": "array",
                "items": {
                    "type": "string",
                },
            },
            "priority_findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                        },
                        "severity": {
                            "type": "string",
                            "enum": [
                                "critical",
                                "high",
                                "medium",
                                "low",
                                "info",
                            ],
                        },
                        "evidence": {
                            "type": "array",
                            "items": {
                                "type": "string",
                            },
                        },
                        "explanation": {
                            "type": "string",
                        },
                        "recommendation": {
                            "type": "string",
                        },
                        "verification": {
                            "type": "string",
                        },
                    },
                    "required": [
                        "title",
                        "severity",
                        "evidence",
                        "explanation",
                        "recommendation",
                        "verification",
                    ],
                    "additionalProperties": False,
                },
            },
            "limitations": {
                "type": "array",
                "items": {
                    "type": "string",
                },
            },
        },
        "required": [
            "executive_summary",
            "security_interpretation",
            "priority_findings",
            "limitations",
        ],
        "additionalProperties": False,
    }

    body = {
        "model": model,
        "input": [
            {
                "role": "system",
                "content": [
                    {
                        "type": "input_text",
                        "text": AI_SYSTEM_PROMPT,
                    }
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": (
                            "Interpret this deterministic "
                            "security evidence. Do not "
                            "infer facts that are not "
                            "present:\n"
                            + json.dumps(
                                evidence,
                                ensure_ascii=False,
                            )
                        ),
                    }
                ],
            },
        ],
        "text": {
            "format": {
                "type": "json_schema",
                "name": (
                    "securemailscope_security_assessment"
                ),
                "strict": True,
                "schema": schema,
            }
        },
    }

    request = urllib.request.Request(
        f"{base_url}/responses",
        data=json.dumps(
            body
        ).encode("utf-8"),
        headers={
            "Authorization": (
                f"Bearer {api_key}"
            ),
            "Content-Type": (
                "application/json"
            ),
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=30,
        ) as response:
            data = json.loads(
                response.read().decode(
                    "utf-8"
                )
            )

    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(
            "utf-8",
            errors="replace",
        )[:1000]

        raise RuntimeError(
            "AI provider returned "
            f"HTTP {exc.code}: {detail}"
        ) from exc

    except urllib.error.URLError as exc:
        raise RuntimeError(
            "AI provider connection failed: "
            f"{exc.reason}"
        ) from exc

    return _extract_json(
        _extract_response_text(data)
    )


def _sanitize_output(
    value: dict[str, Any],
) -> dict[str, Any]:
    result = {
        "executive_summary": _clean_text(
            value.get(
                "executive_summary"
            ),
            1400,
        ),
        "security_interpretation": [
            _clean_text(
                item,
                800,
            )
            for item in (
                value.get(
                    "security_interpretation"
                )
                or []
            )
            if item
        ][:8],
        "priority_findings": [],
        "limitations": [
            _clean_text(
                item,
                800,
            )
            for item in (
                value.get(
                    "limitations"
                )
                or []
            )
            if item
        ][:8],
    }

    allowed = {
        "critical",
        "high",
        "medium",
        "low",
        "info",
    }

    for item in (
        value.get(
            "priority_findings"
        )
        or []
    )[:8]:
        if not isinstance(
            item,
            dict,
        ):
            continue

        severity = str(
            item.get(
                "severity",
                "info",
            )
        ).lower()

        if severity not in allowed:
            severity = "info"

        result[
            "priority_findings"
        ].append(
            {
                "title": _clean_text(
                    item.get("title"),
                    180,
                ),
                "severity": severity,
                "evidence": [
                    _clean_text(
                        evidence,
                        400,
                    )
                    for evidence in (
                        item.get(
                            "evidence"
                        )
                        or []
                    )
                    if evidence
                ][:8],
                "explanation": _clean_text(
                    item.get(
                        "explanation"
                    ),
                    1000,
                ),
                "recommendation": _clean_text(
                    item.get(
                        "recommendation"
                    ),
                    1000,
                ),
                "verification": _clean_text(
                    item.get(
                        "verification"
                    ),
                    1000,
                ),
            }
        )

    return result


def analyze_security_posture(
    payload: dict[str, Any],
) -> dict[str, Any]:
    evidence = _normalize_evidence(
        payload
    )

    fallback = _fallback_analysis(
        evidence
    )

    try:
        result = _sanitize_output(
            _call_llm(evidence)
        )

        mode = "llm"
        provider = "configured"

    except Exception as exc:
        result = fallback
        mode = (
            "deterministic_fallback"
        )

        provider = (
            "not_configured"
            if "not configured"
            in str(exc).lower()
            else "unavailable"
        )

    return {
        "status": "success",
        "engine": (
            "SecureMailScope "
            "AI Correlation Engine"
        ),
        "engine_mode": mode,
        "provider": provider,
        "evidence_scope": (
            "deterministic_security_evidence_only"
        ),
        "privacy": {
            "message_content_sent_to_ai": False,
            "attachments_sent_to_ai": False,
            "credentials_sent_to_ai": False,
        },
        "analysis": result,
    }