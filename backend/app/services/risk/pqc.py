def assess_pqc_readiness(tls_results: list[dict]) -> dict:
    tls_assessments = len(tls_results)
    successful_tls_observations = 0
    tls_13_observations = 0
    legacy_tls_observations = 0
    unobserved_tls_assessments = 0
    forward_secrecy_observations = 0

    for tls_result in tls_results:
        if not isinstance(tls_result, dict):
            unobserved_tls_assessments += 1
            continue

        if tls_result.get("status") != "success":
            unobserved_tls_assessments += 1
            continue

        successful_tls_observations += 1

        tls_version = tls_result.get("tls_version")

        if tls_version == "TLSv1.3":
            tls_13_observations += 1
        elif tls_version:
            legacy_tls_observations += 1
        else:
            unobserved_tls_assessments += 1

        if tls_result.get("forward_secrecy") == "yes":
            forward_secrecy_observations += 1

    if successful_tls_observations == 0:
        readiness = "unknown"
    elif legacy_tls_observations > 0:
        readiness = "limited"
    else:
        readiness = "baseline"

    return {
        "readiness": readiness,
        "tls_assessments": tls_assessments,
        "successful_tls_observations": successful_tls_observations,
        "tls_13_observations": tls_13_observations,
        "legacy_tls_observations": legacy_tls_observations,
        "unobserved_tls_assessments": unobserved_tls_assessments,
        "forward_secrecy_observations": forward_secrecy_observations,
        "assessment": (
            "PQC readiness is a migration indicator based on currently "
            "observable TLS evidence. TLS 1.3 and forward secrecy do not "
            "by themselves demonstrate post-quantum cryptographic protection. "
            "Actual PQC readiness requires evaluating support for appropriate "
            "post-quantum or hybrid cryptographic mechanisms."
        ),
    }