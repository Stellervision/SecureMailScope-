import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    rsa,
)


def _infer_forward_secrecy(
    tls_version: str | None,
    cipher_name: str | None,
) -> str:
    if not tls_version:
        return "unknown"

    if tls_version == "TLSv1.3":
        return "yes"

    if not cipher_name:
        return "unknown"

    cipher_upper = cipher_name.upper()

    if "ECDHE" in cipher_upper or "DHE" in cipher_upper:
        return "yes"

    # Before TLS 1.3, a suite without (EC)DHE uses static RSA key
    # exchange. OpenSSL names these without "RSA" (e.g.
    # AES256-GCM-SHA384), so they were previously reported "unknown".
    if tls_version in {
        "TLSv1.2",
        "TLSv1.1",
        "TLSv1",
        "SSLv3",
    }:
        return "no"

    return "unknown"


def _certificate_details(
    der_certificate: bytes | None,
) -> dict:
    """
    The probe uses an unverified context (so weak servers can still be
    assessed). With CERT_NONE, getpeercert() returns an empty dict, so
    the certificate is parsed from its DER form instead.
    """

    empty = {
        "subject": None,
        "issuer": None,
        "serial_number": None,
        "not_before": None,
        "not_after": None,
        "subject_alternative_names": [],
        "public_key_algorithm": None,
        "public_key_bits": None,
        "signature_algorithm": None,
        "expired": None,
        "days_until_expiry": None,
        "certificate_verified": False,
    }

    if not der_certificate:
        return empty

    try:
        certificate = x509.load_der_x509_certificate(
            der_certificate
        )
    except Exception:
        return empty

    try:
        san_entries = (
            certificate.extensions
            .get_extension_for_class(
                x509.SubjectAlternativeName
            )
            .value
            .get_values_for_type(
                x509.DNSName
            )
        )
    except (
        x509.ExtensionNotFound,
        ValueError,
    ):
        san_entries = []

    public_key = certificate.public_key()

    public_key_bits = getattr(
        public_key,
        "key_size",
        None,
    )

    if isinstance(public_key, rsa.RSAPublicKey):
        public_key_algorithm = "RSA"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key_algorithm = (
            f"ECDSA ({public_key.curve.name})"
        )
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        public_key_algorithm = "Ed25519"
    elif isinstance(public_key, dsa.DSAPublicKey):
        public_key_algorithm = "DSA"
    else:
        public_key_algorithm = type(public_key).__name__

    try:
        signature_algorithm = (
            certificate.signature_algorithm_oid._name
        )
    except Exception:
        signature_algorithm = None

    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc

    now = datetime.now(timezone.utc)

    return {
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serial_number": format(
            certificate.serial_number,
            "X",
        ),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "subject_alternative_names": san_entries,
        "public_key_algorithm": public_key_algorithm,
        "public_key_bits": public_key_bits,
        "signature_algorithm": signature_algorithm,
        "expired": now > not_after,
        "days_until_expiry": (not_after - now).days,
        # Chain and hostname are not validated by the probe.
        "certificate_verified": False,
    }


def analyze_tls_socket(sock: ssl.SSLSocket) -> dict:
    if not isinstance(sock, ssl.SSLSocket):
        return {
            "status": "invalid",
            "error": "The supplied socket is not an SSL/TLS socket.",
        }

    try:
        tls_version = sock.version()
        cipher = sock.cipher()

        cipher_name = cipher[0] if cipher else None
        cipher_bits = cipher[2] if cipher else None

        certificate = _certificate_details(
            sock.getpeercert(
                binary_form=True
            )
        )

        return {
            "status": "success",
            "tls_version": tls_version,
            "cipher": {
                "name": cipher_name,
                "bits": cipher_bits,
            },
            "certificate": certificate,
            "forward_secrecy": _infer_forward_secrecy(
                tls_version,
                cipher_name,
            ),
            "evidence_source": "live_probe",
            "error": None,
        }

    except Exception as exc:
        return {
            "status": "error",
            "error": str(exc),
            "evidence_source": "live_probe",
        }