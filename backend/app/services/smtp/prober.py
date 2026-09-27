import smtplib
import ssl

from app.services.tls.analyzer import analyze_tls_socket


def probe_smtp_starttls(
    hostname: str,
    port: int = 25,
    timeout: int = 3,
) -> dict:
    hostname = hostname.strip().lower().rstrip(".")

    if not hostname:
        return {
            "hostname": hostname,
            "port": port,
            "status": "invalid",
            "smtp_reachable": False,
            "starttls_supported": None,
            "tls": None,
            "evidence_source": "live_probe",
            "error": "A hostname is required.",
        }

    smtp = None

    try:
        # A fixed EHLO name avoids socket.getfqdn(), which can take
        # several seconds per probe on Windows.
        smtp = smtplib.SMTP(
            host=hostname,
            port=port,
            timeout=timeout,
            local_hostname="securemailscope.local",
        )

        smtp_code, smtp_message = smtp.ehlo()

        ehlo_message = smtp_message.decode(
            "utf-8",
            errors="replace",
        )

        if smtp_code >= 400:
            return {
                "hostname": hostname,
                "port": port,
                "status": "smtp_error",
                "smtp_reachable": True,
                "starttls_supported": False,
                "tls": None,
                "ehlo_code": smtp_code,
                "ehlo_message": ehlo_message,
                "evidence_source": "live_probe",
                "error": "SMTP EHLO command failed.",
            }

        starttls_supported = smtp.has_extn("starttls")

        if not starttls_supported:
            return {
                "hostname": hostname,
                "port": port,
                "status": "success",
                "smtp_reachable": True,
                "starttls_supported": False,
                "tls": None,
                "ehlo_code": smtp_code,
                "ehlo_message": ehlo_message,
                "evidence_source": "live_probe",
                "error": None,
            }

        tls_context = ssl._create_unverified_context()

        # The host is reachable and advertised STARTTLS. A failure here
        # is a real transport weakness, not "host unreachable".
        try:
            smtp.starttls(context=tls_context)

        except (
            smtplib.SMTPException,
            OSError,
        ) as exc:
            return {
                "hostname": hostname,
                "port": port,
                "status": "tls_error",
                "smtp_reachable": True,
                "starttls_supported": True,
                "tls": {
                    "status": "error",
                    "error": str(exc),
                    "evidence_source": "live_probe",
                },
                "ehlo_code": smtp_code,
                "ehlo_message": ehlo_message,
                "evidence_source": "live_probe",
                "error": (
                    "STARTTLS was advertised but the TLS "
                    f"negotiation failed: {exc}"
                ),
            }

        tls_analysis = analyze_tls_socket(smtp.sock)

        # A failing post-TLS EHLO must not discard the TLS evidence
        # that was already collected.
        try:
            smtp.ehlo()
        except (
            smtplib.SMTPException,
            OSError,
        ):
            pass

        return {
            "hostname": hostname,
            "port": port,
            "status": "success",
            "smtp_reachable": True,
            "starttls_supported": True,
            "tls": tls_analysis,
            "ehlo_code": smtp_code,
            "ehlo_message": ehlo_message,
            "evidence_source": "live_probe",
            "error": None,
        }

    except TimeoutError:
        return {
            "hostname": hostname,
            "port": port,
            "status": "unavailable",
            "smtp_reachable": False,
            "starttls_supported": None,
            "tls": None,
            "evidence_source": "live_probe",
            "error": (
                "The SMTP connection timed out. "
                "Port 25 may be blocked or unreachable "
                "from the assessment environment."
            ),
        }

    # smtplib.SMTPException is a subclass of OSError, so it must be
    # handled first or this branch is unreachable.
    except smtplib.SMTPException as exc:
        return {
            "hostname": hostname,
            "port": port,
            "status": "smtp_error",
            "smtp_reachable": False,
            "starttls_supported": None,
            "tls": None,
            "evidence_source": "live_probe",
            "error": str(exc),
        }

    except OSError as exc:
        return {
            "hostname": hostname,
            "port": port,
            "status": "unavailable",
            "smtp_reachable": False,
            "starttls_supported": None,
            "tls": None,
            "evidence_source": "live_probe",
            "error": (
                "SMTP service was unreachable from the "
                f"assessment environment: {exc}"
            ),
        }

    except Exception as exc:
        return {
            "hostname": hostname,
            "port": port,
            "status": "error",
            "smtp_reachable": False,
            "starttls_supported": None,
            "tls": None,
            "evidence_source": "live_probe",
            "error": str(exc),
        }

    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except Exception:
                smtp.close()