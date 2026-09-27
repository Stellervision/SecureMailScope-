function MessageView({
  message,
  onBack,
  formatDate,
}) {
  const analysis =
    message?.analysis;

  const security =
    analysis?.security;

  const authentication =
    security?.authentication;

  const summary =
    security?.summary;

  const risk =
    analysis?.risk;

  const hndl =
    analysis?.hndl;

  return (
    <main className="message-view">
      <button
        type="button"
        className="back-button"
        onClick={onBack}
      >
        Back to inbox
      </button>

      <div className="message-header">
        <div className="message-eyebrow">
          MESSAGE
        </div>

        <h2>
          {message?.subject ||
            "Untitled message"}
        </h2>

        <div className="message-meta">
          <div>
            <strong>
              From
            </strong>

            <span>
              {message?.sender ||
                "Unknown"}
            </span>
          </div>

          <div>
            <strong>
              To
            </strong>

            <span>
              {message?.recipients
                ?.length
                ? message.recipients.join(
                    ", "
                  )
                : "Unknown"}
            </span>
          </div>

          <div>
            <strong>
              Received
            </strong>

            <span>
              {message?.received_at
                ? formatDate(
                    message.received_at
                  )
                : "Unknown"}
            </span>
          </div>
        </div>
      </div>

      <div className="message-body">
        {message?.body ||
          "No message body available."}
      </div>

      {message?.attachments?.length >
        0 && (
        <section className="security-panel">
          <div className="message-eyebrow">
            ATTACHMENTS
          </div>

          <h3>
            {
              message.attachments
                .length
            }{" "}
            file
            {message.attachments
              .length ===
            1
              ? ""
              : "s"}{" "}
            attached
          </h3>

          <div className="security-findings">
            {message.attachments.map(
              (
                attachment,
                index
              ) => (
                <div
                  className="security-finding"
                  key={index}
                >
                  <strong>
                    {
                      attachment.filename ||
                      "Attachment"
                    }
                  </strong>

                  <span>
                    {
                      attachment.content_type ||
                      "application/octet-stream"
                    }
                  </span>
                </div>
              )
            )}
          </div>
        </section>
      )}

      <section className="security-panel">
        <div className="message-eyebrow">
          SECURITY ANALYSIS
        </div>

        <h3>
          Observable security posture
        </h3>

        <div className="security-grid">
          <div className="security-card">
            <strong>
              Risk
            </strong>

            <span>
              {risk?.risk_level ||
                "unknown"}
            </span>

            <small>
              Score:{" "}
              {risk?.score ??
                "unknown"}
            </small>
          </div>

          <div className="security-card">
            <strong>
              Authentication
            </strong>

            <span>
              {authentication
                ?.summary?.spf
                ?.status ||
                "unobserved"}
            </span>

            <small>
              SPF observation
            </small>
          </div>

          <div className="security-card">
            <strong>
              Transport
            </strong>

            <span>
              {summary?.status ||
                "unknown"}
            </span>

            <small>
              Based on observed headers
            </small>
          </div>

          <div className="security-card">
            <strong>
              HNDL
            </strong>

            <span>
              {hndl?.level ||
                hndl?.status ||
                "unknown"}
            </span>

            <small>
              Exposure indicator
            </small>
          </div>
        </div>

        <div className="security-findings">
          <h4>
            Findings
          </h4>

          {summary?.findings
            ?.length ? (
            summary.findings.map(
              (
                finding,
                index
              ) => (
                <div
                  className="security-finding"
                  key={index}
                >
                  <strong>
                    {
                      finding.severity ||
                      "unknown"
                    }
                  </strong>

                  <span>
                    {
                      finding.finding
                    }
                  </span>
                </div>
              )
            )
          ) : (
            <p>
              No additional security
              findings were observed
              from the available message
              evidence.
            </p>
          )}
        </div>

        <div className="security-source">
          Evidence source:{" "}
          {analysis?.evidence_source ||
            "unknown"}
        </div>
      </section>
    </main>
  );
}

export default MessageView;