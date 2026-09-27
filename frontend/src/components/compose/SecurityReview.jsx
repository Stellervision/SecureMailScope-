import { useEffect, useState } from "react";

import { API_BASE } from "../../services/config";

function SecurityReview({
  assessment,
  mailAccount,
  mailAccountLoading,
  recipient,
  subject,
  body,
  attachments,
  sendEmail,
  sendLoading,
  sendResult,
  formatDecision,
  formatAuthenticationLabel,
  formatFileSize,
}) {
  const [aiAssessment, setAiAssessment] =
    useState(null);

  const [aiLoading, setAiLoading] =
    useState(false);

  const [aiError, setAiError] =
    useState(null);

  const decision =
    assessment.pre_send?.decision;

  const unknowns =
    assessment.pre_send?.unknowns || [];

  const observations =
    assessment.pre_send?.observations || [];

  const risk =
    assessment.risk ||
    assessment.security?.risk;

  const e2e =
    assessment.e2e;

  const recommendation =
    assessment.recommendations?.[0];

  /*
   * Recipient is the only message-content field
   * required before submission.
   *
   * Subject, body, and attachments are all optional.
   */
  const messageReady =
    Boolean(recipient?.trim());

  const accountReady =
    Boolean(mailAccount?.connected);

  /*
   * E2E is the preferred SecureMailScope path,
   * but it is not a prerequisite for submission.
   *
   * If no recipient key exists, sendEmail() will
   * explicitly ask the user whether to continue
   * with a standard non-E2E email.
   */
  const e2eReady =
    Boolean(e2e?.available);

  const readyToSend =
    messageReady &&
    accountReady &&
    !sendLoading;

  /*
   * AI receives only deterministic security evidence.
   *
   * Deliberately excluded:
   * - subject
   * - message body
   * - attachments
   * - mailbox credentials
   * - private keys
   * - OAuth tokens
   */
  useEffect(() => {
    let cancelled = false;

    const assessWithAI = async () => {
      if (!assessment || assessment.error) {
        setAiAssessment(null);
        setAiError(null);
        return;
      }

      setAiLoading(true);
      setAiError(null);

      const e2e =
        assessment.e2e;

      const mtaStsPolicy =
        assessment.mta_sts?.policy;

      const evidence = {
        domain:
          assessment.domain ||
          assessment.recipient?.split("@")[1] ||
          null,

        risk:
          assessment.risk ||
          assessment.security?.risk ||
          null,

        // Flattened to the keys the AI engine reads.
        mta_sts: assessment.mta_sts
          ? {
              ...assessment.mta_sts,
              mode:
                mtaStsPolicy?.policy
                  ?.mode || null,
              status:
                mtaStsPolicy?.status ||
                null,
            }
          : null,

        pqc:
          assessment.pqc ||
          assessment.security?.pqc ||
          null,

        pre_send:
          assessment.pre_send || null,

        e2e: e2e
          ? {
              available:
                Boolean(e2e.available),

              trusted:
                Boolean(e2e.trusted),

              trust_model:
                e2e.trust_model ||
                null,

              algorithm:
                e2e.algorithm ||
                e2e.key_encryption ||
                "RSA-OAEP-256",

              key_id:
                e2e.key_id ||
                null,

              fingerprint:
                e2e.fingerprint ||
                null,
            }
          : null,

        recommendations:
          assessment.recommendations ||
          [],
      };

      try {
        const response =
          await fetch(
            `${API_BASE}/api/ai/assess`,
            {
              method: "POST",
              headers: {
                "Content-Type":
                  "application/json",
              },
              body: JSON.stringify(
                evidence
              ),
            }
          );

        const data =
          await response.json();

        if (!response.ok) {
          throw new Error(
            data.detail ||
              data.message ||
              "AI security assessment failed."
          );
        }

        if (!cancelled) {
          setAiAssessment(data);
        }
      } catch (error) {
        if (!cancelled) {
          setAiAssessment(null);
          setAiError(
            error?.message ||
              "AI security assessment is unavailable."
          );
        }
      } finally {
        if (!cancelled) {
          setAiLoading(false);
        }
      }
    };

    assessWithAI();

    return () => {
      cancelled = true;
    };
    // Only re-run when a new assessment arrives. Depending on the
    // recipient text re-posted to the AI endpoint on every keystroke.
  }, [assessment]);

  const aiAnalysis =
    aiAssessment?.analysis;

  const priorityFindings =
    aiAnalysis?.priority_findings ||
    [];

  const aiInterpretation =
    aiAnalysis?.security_interpretation ||
    [];

  const aiLimitations =
    aiAnalysis?.limitations ||
    [];

  return (
    <section
      className="card"
      style={{
        marginTop: "14px",
      }}
    >
      <div className="card-header">
        <div>
          <span className="section-label">
            SECURITY REVIEW
          </span>

          <h3>
            Review before sending
          </h3>
        </div>

        <span className="draft">
          {formatDecision(decision)}
        </span>
      </div>

      <div className="security-findings">
        <h4>
          Destination
        </h4>

        <div className="security-row">
          <span>
            Recipient
          </span>

          <span className="neutral">
            {recipient || "Not provided"}
          </span>
        </div>

        <div className="security-row">
          <span>
            Domain
          </span>

          <span className="neutral">
            {assessment.domain ||
              recipient?.split("@")[1] ||
              "Unknown"}
          </span>
        </div>

        <div className="security-row">
          <span>
            Risk
          </span>

          <span className="neutral">
            {risk?.risk_level ||
              "Unknown"}
          </span>
        </div>

        <div className="security-row">
          <span>
            Confidence
          </span>

          <span className="neutral">
            {risk?.confidence ||
              "Unknown"}
          </span>
        </div>

        <div className="security-row">
          <span>
            Observability
          </span>

          <span className="neutral">
            {risk?.observability ||
              "Unknown"}
          </span>
        </div>
      </div>

      <div className="security-findings">
        <h4>
          End-to-end encryption
        </h4>

        <div className="security-row">
          <span>
            Recipient key
          </span>

          <span
            className={
              e2e?.available
                ? "positive"
                : "neutral"
            }
          >
            {e2e?.available
              ? "Available"
              : "Unavailable"}
          </span>
        </div>

        {e2e?.available ? (
          <>
            <div className="security-row">
              <span>
                Content encryption
              </span>

              <span className="positive">
                AES-256-GCM
              </span>
            </div>

            <div className="security-row">
              <span>
                Key encryption
              </span>

              <span className="positive">
                RSA-OAEP-256
              </span>
            </div>

            <div className="security-row">
              <span>
                Key ID
              </span>

              <span
                className="neutral"
                style={{
                  overflowWrap:
                    "anywhere",
                  textAlign:
                    "right",
                }}
              >
                {e2e.key_id ||
                  "Available"}
              </span>
            </div>

            {e2e.fingerprint && (
              <div className="security-row">
                <span>
                  Key fingerprint
                </span>

                <span
                  className="neutral"
                  style={{
                    overflowWrap:
                      "anywhere",
                    textAlign:
                      "right",
                  }}
                >
                  {e2e.fingerprint}
                </span>
              </div>
            )}

            <div className="security-row">
              <span>
                Trust
              </span>

              <span
                className={
                  e2e.trusted
                    ? "positive"
                    : "neutral"
                }
              >
                {e2e.trusted
                  ? "Verified"
                  : "Self-asserted / unverified"}
              </span>
            </div>

            <p className="security-source">
              The message content and
              attachments can be encrypted
              in the browser before entering
              SMTP infrastructure. Transport
              security is assessed separately.
            </p>
          </>
        ) : (
          <div className="unknown-box">
            <strong>
              End-to-end encryption is not
              available for this recipient
            </strong>

            <p>
              A compatible SecureMailScope
              recipient encryption key is
              required for E2E encryption.
              If you continue, SecureMailScope
              will explicitly ask whether you
              want to send this message as a
              standard non-E2E email.
            </p>
          </div>
        )}
      </div>

      {observations.length > 0 && (
        <div className="security-findings">
          <h4>
            Verified observations
          </h4>

          {observations.map(
            (
              observation,
              index
            ) => (
              <div
                className="security-finding"
                key={index}
              >
                <strong>
                  Observed
                </strong>

                <span>
                  {typeof observation ===
                  "string"
                    ? observation
                    : observation?.message ||
                      observation?.description ||
                      JSON.stringify(
                        observation
                      )}
                </span>
              </div>
            )
          )}
        </div>
      )}

      {unknowns.length > 0 && (
        <div className="unknown-box">
          <strong>
            Transport verification is incomplete
          </strong>

          <p>
            {unknowns.map(
              (
                unknown,
                index
              ) => (
                <span
                  key={index}
                  style={{
                    display: "block",
                    marginTop:
                      index === 0
                        ? "6px"
                        : "4px",
                  }}
                >
                  {typeof unknown ===
                  "string"
                    ? unknown
                    : unknown?.message ||
                      unknown?.description ||
                      JSON.stringify(
                        unknown
                      )}
                </span>
              )
            )}
          </p>
        </div>
      )}

      {recommendation && (
        <div className="recommendation">
          <span>
            RECOMMENDATION
          </span>

          <strong>
            {recommendation.title}
          </strong>

          <p>
            {recommendation.why_it_matters}
          </p>
        </div>
      )}

      <div className="security-findings">
        <h4>
          AI Security Intelligence
        </h4>

        <div className="security-row">
          <span>
            Analysis engine
          </span>

          <span className="neutral">
            {aiLoading
              ? "Analyzing evidence..."
              : aiAssessment?.engine ||
                "SecureMailScope AI"}
          </span>
        </div>

        {!aiLoading &&
          aiAssessment?.engine_mode && (
            <div className="security-row">
              <span>
                Mode
              </span>

              <span className="neutral">
                {aiAssessment.engine_mode ===
                "llm"
                  ? "AI model"
                  : "Deterministic fallback"}
              </span>
            </div>
          )}

        {aiLoading && (
          <p className="security-source">
            Correlating deterministic
            cryptographic and transport
            evidence. Message content is
            not provided to the AI layer.
          </p>
        )}

        {!aiLoading &&
          aiAnalysis
            ?.executive_summary && (
            <div
              className="security-finding"
              style={{
                marginTop: "10px",
              }}
            >
              <strong>
                AI interpretation
              </strong>

              <span>
                {
                  aiAnalysis.executive_summary
                }
              </span>
            </div>
          )}

        {!aiLoading &&
          aiInterpretation.length >
            0 && (
            <div
              style={{
                marginTop: "12px",
              }}
            >
              <strong>
                Security interpretation
              </strong>

              {aiInterpretation.map(
                (
                  interpretation,
                  index
                ) => (
                  <div
                    className="security-finding"
                    key={index}
                    style={{
                      marginTop: "8px",
                    }}
                  >
                    <strong>
                      {index + 1}
                    </strong>

                    <span>
                      {interpretation}
                    </span>
                  </div>
                )
              )}
            </div>
          )}

        {!aiLoading &&
          priorityFindings.length >
            0 && (
            <div
              style={{
                marginTop: "14px",
              }}
            >
              <strong>
                Priority findings
              </strong>

              {priorityFindings.map(
                (
                  finding,
                  index
                ) => (
                  <div
                    className="security-finding"
                    key={index}
                    style={{
                      marginTop: "10px",
                      display: "block",
                    }}
                  >
                    <div
                      className="security-row"
                    >
                      <strong>
                        {finding.title ||
                          "Security finding"}
                      </strong>

                      <span className="neutral">
                        {finding.severity ||
                          "Unknown"}
                      </span>
                    </div>

                    {finding.evidence
                      ?.length > 0 && (
                      <div
                        style={{
                          marginTop:
                            "8px",
                        }}
                      >
                        <strong>
                          Evidence
                        </strong>

                        {finding.evidence.map(
                          (
                            evidence,
                            evidenceIndex
                          ) => (
                            <span
                              key={
                                evidenceIndex
                              }
                              style={{
                                display:
                                  "block",
                                marginTop:
                                  "4px",
                              }}
                            >
                              {evidence}
                            </span>
                          )
                        )}
                      </div>
                    )}

                    {finding.explanation && (
                      <p>
                        <strong>
                          Explanation:
                        </strong>{" "}
                        {
                          finding.explanation
                        }
                      </p>
                    )}

                    {finding.recommendation && (
                      <p>
                        <strong>
                          Remediation:
                        </strong>{" "}
                        {
                          finding.recommendation
                        }
                      </p>
                    )}

                    {finding.verification && (
                      <p>
                        <strong>
                          Verification:
                        </strong>{" "}
                        {
                          finding.verification
                        }
                      </p>
                    )}
                  </div>
                )
              )}
            </div>
          )}

        {!aiLoading &&
          aiLimitations.length >
            0 && (
            <div
              className="unknown-box"
              style={{
                marginTop: "12px",
              }}
            >
              <strong>
                AI assessment limitations
              </strong>

              <p>
                {aiLimitations.map(
                  (
                    limitation,
                    index
                  ) => (
                    <span
                      key={index}
                      style={{
                        display:
                          "block",
                        marginTop:
                          index === 0
                            ? "6px"
                            : "4px",
                      }}
                    >
                      {limitation}
                    </span>
                  )
                )}
              </p>
            </div>
          )}

        {!aiLoading &&
          aiError && (
            <div
              className="unknown-box"
              style={{
                marginTop: "12px",
              }}
            >
              <strong>
                AI interpretation unavailable
              </strong>

              <p>
                {aiError}
              </p>

              <p className="security-source">
                The deterministic security
                evidence above remains the
                source of truth. AI does not
                control cryptographic
                decisions.
              </p>
            </div>
          )}

        {!aiLoading &&
          !aiError &&
          aiAssessment && (
            <p
              className="security-source"
              style={{
                marginTop: "12px",
              }}
            >
              AI analysis uses deterministic
              security evidence only. Message
              content, attachments,
              credentials, and private keys
              are not sent to the AI layer.
            </p>
          )}
      </div>

      <div className="security-findings">
        <h4>
          Sending account
        </h4>

        {mailAccountLoading ? (
          <>
            <div className="security-row">
              <span>
                Account
              </span>

              <span className="neutral">
                Checking connection...
              </span>
            </div>

            <p className="security-source">
              Checking the selected
              mailbox before
              submission.
            </p>
          </>
        ) : accountReady ? (
          <>
            <div className="security-row">
              <span>
                Sender
              </span>

              <span className="neutral">
                {mailAccount.sender_email}
              </span>
            </div>

            <div className="security-row">
              <span>
                Provider
              </span>

              <span className="neutral">
                {mailAccount.provider ||
                  "Mail provider"}
              </span>
            </div>

            <div className="security-row">
              <span>
                Authentication
              </span>

              <span className="neutral">
                {formatAuthenticationLabel(
                  mailAccount
                )}
              </span>
            </div>

            <div className="security-row">
              <span>
                Status
              </span>

              <span className="positive">
                Connected
              </span>
            </div>

            <div className="security-row">
              <span>
                Transport
              </span>

              <span className="neutral">
                {mailAccount.smtp?.security_mode
                  ? mailAccount.smtp.security_mode.toUpperCase()
                  : "Configured"}
              </span>
            </div>

            <p className="security-source">
              The explicitly selected
              mailbox is used for
              submission. Credentials
              remain outside the
              compose workflow.
            </p>
          </>
        ) : (
          <div className="unknown-box">
            <strong>
              No sending mailbox selected
            </strong>

            <p>
              Attach and connect a
              mailbox above before
              submitting.
            </p>
          </div>
        )}
      </div>

      <div className="security-findings">
        <h4>
          Message review
        </h4>

        <div className="security-row">
          <span>
            Recipient
          </span>

          <span
            className={
              recipient?.trim()
                ? "positive"
                : "neutral"
            }
          >
            {recipient?.trim()
              ? "Ready"
              : "Required"}
          </span>
        </div>

        <div className="security-row">
          <span>
            Subject
          </span>

          <span
            className={
              subject.trim()
                ? "positive"
                : "neutral"
            }
          >
            {subject.trim()
              ? "Provided"
              : "Optional"}
          </span>
        </div>

        <div className="security-row">
          <span>
            Message
          </span>

          <span
            className={
              body.trim()
                ? "positive"
                : "neutral"
            }
          >
            {body.trim()
              ? "Provided"
              : "Optional"}
          </span>
        </div>

        <div className="security-row">
          <span>
            Attachments
          </span>

          <span
            className={
              attachments.length > 0
                ? "positive"
                : "neutral"
            }
          >
            {attachments.length > 0
              ? `${attachments.length} attached`
              : "Optional"}
          </span>
        </div>
      </div>

      {attachments.length > 0 && (
        <div className="security-findings">
          <h4>
            Files pending encryption
          </h4>

          {attachments.map(
            (
              file,
              index
            ) => (
              <div
                className="security-row"
                key={`${file.name}-${file.size}-${index}`}
              >
                <span
                  style={{
                    minWidth: 0,
                    overflow: "hidden",
                    textOverflow:
                      "ellipsis",
                    whiteSpace:
                      "nowrap",
                    paddingRight:
                      "10px",
                  }}
                >
                  {file.name}
                </span>

                <span className="neutral">
                  {formatFileSize(
                    file.size
                  )}
                </span>
              </div>
            )
          )}

          <p className="security-source">
            These files are included
            inside the encrypted
            SecureMailScope envelope.
            They are not submitted as
            plaintext MIME attachments
            when E2E encryption is
            available.
          </p>
        </div>
      )}

      {!messageReady && (
        <div className="unknown-box">
          <strong>
            Recipient required before sending
          </strong>

          <p>
            Enter at least one recipient
            address in the composer above.
            Subject, message content, and
            attachments are optional.
          </p>
        </div>
      )}

      {!accountReady &&
        !mailAccountLoading && (
          <div className="unknown-box">
            <strong>
              Sending account required
            </strong>

            <p>
              Attach and connect a
              mailbox before
              submitting the message.
            </p>
          </div>
        )}

      {!e2eReady && messageReady && (
        <div className="unknown-box">
          <strong>
            E2E encryption unavailable for this recipient
          </strong>

          <p>
            No compatible SecureMailScope
            recipient public key is
            currently available. E2E
            remains the preferred path.
            If you press Confirm &amp; Send,
            SecureMailScope will ask
            whether you want to continue
            with a standard non-E2E email.
          </p>
        </div>
      )}

      {e2eReady && messageReady && (
        <p
          className="security-source"
          style={{
            marginTop: "14px",
          }}
        >
          SecureMailScope will use
          end-to-end encryption for this
          recipient. Subject, message
          content, and attachments are
          encrypted in the browser before
          SMTP submission.
        </p>
      )}

      <button
        className="assess-button"
        onClick={sendEmail}
        disabled={!readyToSend}
        style={{
          width: "100%",
          marginTop: "18px",
        }}
      >
        {sendLoading
          ? "Submitting securely..."
          : "Confirm & Send"}
      </button>

      {sendResult && (
        <div
          className={
            sendResult.type ===
            "success"
              ? "recommendation"
              : "error-box"
          }
          style={{
            marginTop: "14px",
          }}
        >
          {sendResult.type ===
          "success" ? (
            <>
              <span>
                SUBMISSION SUCCESSFUL
              </span>

              <strong>
                {sendResult.message}
              </strong>

              <p>
                {sendResult.e2e?.enabled
                  ? "The SMTP provider accepted the encrypted SecureMailScope envelope for submission. This confirms submission only; it does not by itself verify downstream transport security."
                  : "The SMTP provider accepted the standard email for submission. This message was not end-to-end encrypted because no compatible SecureMailScope recipient key was available."}
              </p>

              {sendResult.e2e?.enabled && (
                <div
                  style={{
                    marginTop:
                      "10px",
                  }}
                >
                  <strong>
                    E2E protection
                  </strong>

                  <span
                    style={{
                      display:
                        "block",
                      marginTop:
                        "4px",
                    }}
                  >
                    AES-256-GCM content
                    encryption ·
                    RSA-OAEP-256 key
                    encryption
                  </span>

                  {sendResult.e2e
                    .recipientKeyId && (
                    <span
                      style={{
                        display:
                          "block",
                        marginTop:
                          "4px",
                        overflowWrap:
                          "anywhere",
                      }}
                    >
                      Key ID:{" "}
                      {
                        sendResult.e2e
                          .recipientKeyId
                      }
                    </span>
                  )}
                </div>
              )}

              {sendResult.data
                ?.result
                ?.attachments
                ?.length > 0 && (
                <div
                  style={{
                    marginTop:
                      "10px",
                  }}
                >
                  <strong>
                    Attachments submitted
                  </strong>

                  {sendResult.data.result.attachments.map(
                    (
                      attachment,
                      index
                    ) => (
                      <span
                        key={index}
                        style={{
                          display:
                            "block",
                          marginTop:
                            "4px",
                        }}
                      >
                        {
                          attachment.filename
                        }{" "}
                        ·{" "}
                        {formatFileSize(
                          attachment.size
                        )}
                      </span>
                    )
                  )}
                </div>
              )}
            </>
          ) : (
            sendResult.message
          )}
        </div>
      )}
    </section>
  );
}

export default SecurityReview;