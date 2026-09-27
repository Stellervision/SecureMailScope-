import Metric from "../security/Metric";
import SecurityRow from "../security/SecurityRow";

function SecurityPanel({
  assessment,
  loading,
  formatDecision,
}) {
  return (
    <div className="card security-card">
      <div className="card-header">
        <div>
          <span className="section-label">
            SECURITY CENTER
          </span>

          <h3>
            Recipient posture
          </h3>
        </div>

        {assessment &&
          !assessment.error && (
            <span className="live-badge">
              LIVE
            </span>
          )}
      </div>

      {loading && (
        <div className="empty-state">
          <div className="shield">
            ⌁
          </div>

          <h4>
            Assessing destination
          </h4>

          <p>
            Inspecting observable DNS,
            mail transport and
            cryptographic signals.
          </p>
        </div>
      )}

      {!loading &&
        !assessment && (
          <div className="empty-state">
            <div className="shield">
              ⌁
            </div>

            <h4>
              Waiting for assessment
            </h4>

            <p>
              Enter a recipient and
              check its domain to see
              observable security
              controls.
            </p>
          </div>
        )}

      {!loading &&
        assessment?.error && (
          <div className="error-box">
            {assessment.error}
          </div>
        )}

      {!loading &&
        assessment &&
        !assessment.error && (
          <AssessmentContent
            assessment={assessment}
            formatDecision={formatDecision}
          />
        )}
    </div>
  );
}

function AssessmentContent({
  assessment,
  formatDecision,
}) {
  const risk =
    assessment.risk;

  const pqc =
    assessment.pqc;

  const observability =
    risk?.observability;

  return (
    <>
      <div className="risk-panel">
        <div>
          <span>
            Risk posture
          </span>

          <strong>
            {risk?.risk_level ||
              "Unknown"}
          </strong>
        </div>

        <div className="risk-score">
          {risk?.score ?? "—"}
        </div>
      </div>

      <div className="metrics">
        <Metric
          label="Confidence"
          value={
            risk?.confidence ||
            "Unknown"
          }
        />

        <Metric
          label="Observability"
          value={
            risk?.observability ||
            "Unknown"
          }
        />

        <Metric
          label="PQC readiness"
          value={
            pqc?.readiness ||
            "Unknown"
          }
        />
      </div>

      <div className="decision">
        <span>
          Pre-send decision
        </span>

        <strong>
          {formatDecision(
            assessment.pre_send
              ?.decision
          )}
        </strong>
      </div>

      <div className="controls">
        <SecurityRow
          label="MTA-STS"
          value={
            assessment.mta_sts
              ?.mode === "enforce"
              ? "Enforce observed"
              : "Observed"
          }
          positive
        />

        <SecurityRow
          label="SMTP transport"
          value={
            observability?.smtp_unreachable_hosts >
              0 ||
            observability?.smtp_unobserved_hosts >
              0
              ? "Not observable"
              : "Observed"
          }
        />

        <SecurityRow
          label="STARTTLS"
          value={
            observability?.starttls_unobserved_hosts >
              0
              ? "Not observable"
              : "Observed"
          }
        />

        <SecurityRow
          label="TLS handshake"
          value={
            observability?.tls_unobserved_hosts >
              0
              ? "Not observable"
              : "Observed"
          }
        />
      </div>

      {assessment.pre_send
        ?.unknowns?.length > 0 && (
        <div className="unknown-box">
          <strong>
            What could not be verified
          </strong>

          <p>
            Some transport properties
            could not be observed from
            the current assessment
            environment.
          </p>
        </div>
      )}

      {assessment.recommendations
        ?.length > 0 && (
        <div className="recommendation">
          <span>
            RECOMMENDATION
          </span>

          <strong>
            {
              assessment
                .recommendations[0]
                .title
            }
          </strong>

          <p>
            {
              assessment
                .recommendations[0]
                .why_it_matters
            }
          </p>
        </div>
      )}
    </>
  );
}

export default SecurityPanel;