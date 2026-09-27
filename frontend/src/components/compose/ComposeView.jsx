import { useRef } from "react";

import SecurityPanel from "./SecurityPanel";
import SecurityReview from "./SecurityReview";

function ComposeView({
  recipient,
  setRecipient,
  subject,
  setSubject,
  body,
  setBody,
  attachments,
  handleAttachmentChange,
  removeAttachment,
  attachmentTotalSize,

  mailAccount,
  mailAccountLoading,
  attachedMailAccounts,
  availableMailAccounts,
  savedMailAccounts,
  selectedAccountId,
  selectMailbox,

  attachPanelOpen,
  attachSelectionId,
  setAttachSelectionId,
  openAttachMailbox,
  closeAttachMailbox,
  attachMailbox,

  connectMailbox,
  disconnectMailbox,
  detachMailbox,
  removeMailbox,

  accountConnecting,
  accountError,

  oauthLoading,
  startOAuth,

  addMailboxPanelOpen,
  openAddMailbox,
  closeAddMailbox,

  newMailboxEmail,
  setNewMailboxEmail,
  newMailboxUsername,
  setNewMailboxUsername,
  newMailboxPassword,
  setNewMailboxPassword,
  newMailboxHost,
  setNewMailboxHost,
  newMailboxPort,
  setNewMailboxPort,
  newMailboxSecurityMode,
  setNewMailboxSecurityMode,
  newMailboxProvider,
  setNewMailboxProvider,

  mailboxSaving,
  mailboxRemovingId,
  createMailbox,

  assessment,
  loading,
  checkRecipient,

  sendEmail,
  sendLoading,
  sendResult,

  formatAuthenticationLabel,
  formatFileSize,
  formatDecision,
}) {
  const attachmentInputRef = useRef(null);

  const connected = Boolean(
    mailAccount?.connected
  );

  const selectedAttachedAccount =
    attachedMailAccounts.find(
      (account) =>
        account.account_id ===
        selectedAccountId
    );

  const attachedIds = new Set(
    attachedMailAccounts.map(
      (account) =>
        account.account_id
    )
  );

  const savedAccountsNotAttached =
    savedMailAccounts.filter(
      (account) =>
        !attachedIds.has(
          account.account_id
        )
    );

  const mailboxBusy =
    accountConnecting ||
    mailboxSaving ||
    Boolean(mailboxRemovingId) ||
    Boolean(oauthLoading);

  return (
    <>
      <section className="hero">
        <div>
          <span className="eyebrow">
            SECURE SEND
          </span>

          <h2>
            Understand the destination
            before you send.
          </h2>

          <p>
            Assess the recipient domain,
            review observable security
            evidence, and make an
            informed decision before
            sending.
          </p>
        </div>
      </section>

      <section
        className="card"
        style={{
          marginBottom: "14px",
        }}
      >
        <div className="card-header">
          <div>
            <span className="section-label">
              MAILBOX
            </span>

            <h3>
              {connected
                ? "Connected sending account"
                : attachedMailAccounts.length > 0
                ? "Attached mailboxes"
                : "No mailbox attached"}
            </h3>
          </div>

          {connected && (
            <span className="live-badge">
              CONNECTED
            </span>
          )}
        </div>

        {mailAccountLoading ? (
          <div className="empty-state">
            <div className="shield">
              ⌁
            </div>

            <h4>
              Loading mailbox state
            </h4>

            <p>
              Checking saved and explicitly
              attached mailboxes.
            </p>
          </div>
        ) : (
          <>
            {attachedMailAccounts.length ===
              0 && (
              <div className="empty-state">
                <div className="shield">
                  ⌁
                </div>

                <h4>
                  No mailbox attached
                </h4>

                <p>
                  Attach a saved mailbox or
                  add a new mailbox when you
                  are ready. Nothing is
                  automatically selected or
                  connected.
                </p>

                <div
                  style={{
                    display: "flex",
                    gap: "8px",
                    flexWrap: "wrap",
                    justifyContent: "center",
                    marginTop: "14px",
                  }}
                >
                  <button
                    className="assess-button"
                    type="button"
                    onClick={
                      openAttachMailbox
                    }
                    disabled={mailboxBusy}
                  >
                    + Attach saved mailbox
                  </button>

                  <button
                    className="assess-button"
                    type="button"
                    onClick={
                      openAddMailbox
                    }
                    disabled={mailboxBusy}
                  >
                    + Add mailbox
                  </button>
                </div>
              </div>
            )}

            {savedMailAccounts.length >
              0 && (
              <div
                className="security-findings"
                style={{
                  marginTop:
                    attachedMailAccounts.length >
                    0
                      ? "14px"
                      : "0",
                }}
              >
                <h4>
                  Saved mailboxes
                </h4>

                <p
                  className="security-source"
                  style={{
                    marginTop: "6px",
                    marginBottom: "12px",
                  }}
                >
                  Saved connection details are
                  kept for later use. Credentials
                  and OAuth tokens are never
                  displayed here.
                </p>

                <div
                  style={{
                    display: "grid",
                    gap: "8px",
                  }}
                >
                  {savedMailAccounts.map(
                    (account) => {
                      const isAttached =
                        attachedIds.has(
                          account.account_id
                        );

                      const isConnected =
                        connected &&
                        mailAccount.account_id ===
                          account.account_id;

                      const isRemoving =
                        mailboxRemovingId ===
                        account.account_id;

                      return (
                        <div
                          key={
                            account.account_id
                          }
                          style={{
                            width: "100%",
                            padding:
                              "13px 14px",
                            borderRadius:
                              "10px",
                            border:
                              isConnected
                                ? "2px solid currentColor"
                                : "1px solid currentColor",
                            background:
                              "transparent",
                            opacity:
                              isRemoving
                                ? 0.6
                                : 1,
                          }}
                        >
                          <div
                            style={{
                              display:
                                "flex",
                              justifyContent:
                                "space-between",
                              alignItems:
                                "center",
                              gap: "12px",
                            }}
                          >
                            <div
                              style={{
                                minWidth: 0,
                                flex: 1,
                              }}
                            >
                              <strong
                                style={{
                                  display:
                                    "block",
                                  overflow:
                                    "hidden",
                                  textOverflow:
                                    "ellipsis",
                                  whiteSpace:
                                    "nowrap",
                                }}
                              >
                                {
                                  account.sender_email
                                }
                              </strong>

                              <span
                                className="security-source"
                                style={{
                                  display:
                                    "block",
                                  marginTop:
                                    "3px",
                                }}
                              >
                                {account.provider ||
                                  formatAuthenticationLabel(
                                    account
                                  )}{" "}
                                ·{" "}
                                {account.smtp
                                  ?.host ||
                                  "Provider authorization"}
                                {account.smtp
                                  ?.port
                                  ? `:${account.smtp.port}`
                                  : ""}
                              </span>
                            </div>

                            <span
                              className={
                                isConnected ||
                                isAttached
                                  ? "positive"
                                  : "neutral"
                              }
                              style={{
                                flexShrink:
                                  0,
                              }}
                            >
                              {isConnected
                                ? "Connected"
                                : isAttached
                                ? "Attached"
                                : "Saved"}
                            </span>
                          </div>

                          <div
                            style={{
                              display:
                                "flex",
                              gap: "8px",
                              flexWrap:
                                "wrap",
                              marginTop:
                                "10px",
                            }}
                          >
                            {isAttached ? (
                              <>
                                <button
                                  type="button"
                                  className="assess-button"
                                  onClick={() =>
                                    connectMailbox(
                                      account.account_id
                                    )
                                  }
                                  disabled={
                                    accountConnecting ||
                                    mailboxSaving ||
                                    Boolean(
                                      mailboxRemovingId
                                    ) ||
                                    isConnected ||
                                    Boolean(
                                      oauthLoading
                                    )
                                  }
                                  style={{
                                    flex: 1,
                                  }}
                                >
                                  {isConnected
                                    ? "Connected"
                                    : accountConnecting
                                    ? "Connecting..."
                                    : "Use this account"}
                                </button>

                                {!isConnected && (
                                  <button
                                    type="button"
                                    className="assess-button"
                                    onClick={() =>
                                      detachMailbox(
                                        account.account_id
                                      )
                                    }
                                    disabled={
                                      accountConnecting ||
                                      mailboxSaving ||
                                      Boolean(
                                        mailboxRemovingId
                                      ) ||
                                      Boolean(
                                        oauthLoading
                                      )
                                    }
                                  >
                                    Detach
                                  </button>
                                )}
                              </>
                            ) : (
                              <button
                                type="button"
                                className="assess-button"
                                onClick={async () => {
                                  await openAttachMailbox();

                                  setAttachSelectionId(
                                    account.account_id
                                  );
                                }}
                                disabled={
                                  mailboxBusy
                                }
                                style={{
                                  flex: 1,
                                }}
                              >
                                Attach
                              </button>
                            )}

                            <button
                              type="button"
                              className="assess-button"
                              onClick={() =>
                                removeMailbox(
                                  account.account_id,
                                  account.sender_email
                                )
                              }
                              disabled={
                                accountConnecting ||
                                mailboxSaving ||
                                Boolean(
                                  mailboxRemovingId
                                ) ||
                                isConnected ||
                                Boolean(
                                  oauthLoading
                                )
                              }
                            >
                              {isRemoving
                                ? "Removing..."
                                : "Remove"}
                            </button>
                          </div>

                          {isConnected && (
                            <button
                              type="button"
                              className="assess-button"
                              onClick={
                                disconnectMailbox
                              }
                              disabled={
                                accountConnecting ||
                                mailboxSaving ||
                                Boolean(
                                  mailboxRemovingId
                                )
                              }
                              style={{
                                width: "100%",
                                marginTop: "8px",
                              }}
                            >
                              Disconnect active mailbox
                            </button>
                          )}
                        </div>
                      );
                    }
                  )}
                </div>

                {savedAccountsNotAttached.length ===
                  0 &&
                  attachedMailAccounts.length >
                    0 && (
                    <p
                      className="security-source"
                      style={{
                        marginTop: "10px",
                      }}
                    >
                      All saved mailboxes are
                      currently attached or
                      connected.
                    </p>
                  )}
              </div>
            )}

            {attachedMailAccounts.length >
              0 && (
              <>
                <div className="security-findings">
                  <h4>
                    Attached mailboxes
                  </h4>

                  <p
                    className="security-source"
                    style={{
                      marginTop: "6px",
                      marginBottom: "12px",
                    }}
                  >
                    Choose which attached
                    account should be used.
                    Accounts can belong to
                    the same domain or different
                    domains.
                  </p>

                  <div
                    style={{
                      display: "grid",
                      gap: "8px",
                    }}
                  >
                    {attachedMailAccounts.map(
                      (account) => {
                        const isSelected =
                          selectedAccountId ===
                          account.account_id;

                        const isConnected =
                          connected &&
                          mailAccount.account_id ===
                            account.account_id;

                        return (
                          <div
                            key={
                              account.account_id
                            }
                            style={{
                              width: "100%",
                              padding:
                                "13px 14px",
                              borderRadius:
                                "10px",
                              border:
                                isConnected ||
                                isSelected
                                  ? "2px solid currentColor"
                                  : "1px solid currentColor",
                              background:
                                "transparent",
                              opacity:
                                accountConnecting
                                  ? 0.65
                                  : 1,
                            }}
                          >
                            <div
                              style={{
                                display:
                                  "flex",
                                justifyContent:
                                  "space-between",
                                alignItems:
                                  "center",
                                gap: "12px",
                              }}
                            >
                              <button
                                type="button"
                                onClick={() =>
                                  selectMailbox(
                                    account.account_id
                                  )
                                }
                                disabled={
                                  accountConnecting ||
                                  Boolean(
                                    mailboxRemovingId
                                  )
                                }
                                style={{
                                  flex: 1,
                                  minWidth: 0,
                                  border:
                                    "none",
                                  background:
                                    "transparent",
                                  padding: 0,
                                  textAlign:
                                    "left",
                                  cursor:
                                    accountConnecting
                                      ? "default"
                                      : "pointer",
                                  font: "inherit",
                                }}
                              >
                                <strong
                                  style={{
                                    display:
                                      "block",
                                    overflow:
                                      "hidden",
                                    textOverflow:
                                      "ellipsis",
                                    whiteSpace:
                                      "nowrap",
                                  }}
                                >
                                  {
                                    account.sender_email
                                  }
                                </strong>

                                <span
                                  className="security-source"
                                  style={{
                                    display:
                                      "block",
                                    marginTop:
                                      "3px",
                                  }}
                                >
                                  {account.provider ||
                                    formatAuthenticationLabel(
                                      account
                                    )}{" "}
                                  ·{" "}
                                  {account.smtp
                                    ?.host ||
                                    "Provider authorization"}
                                  {account.smtp
                                    ?.port
                                    ? `:${account.smtp.port}`
                                    : ""}
                                </span>
                              </button>

                              <span
                                className={
                                  isConnected ||
                                  isSelected
                                    ? "positive"
                                    : "neutral"
                                }
                                style={{
                                  flexShrink:
                                    0,
                                }}
                              >
                                {isConnected
                                  ? "Connected"
                                  : isSelected
                                  ? "Selected"
                                  : "Attached"}
                              </span>
                            </div>

                            <div
                              style={{
                                display:
                                  "flex",
                                gap: "8px",
                                marginTop:
                                  "10px",
                              }}
                            >
                              <button
                                type="button"
                                className="assess-button"
                                onClick={() =>
                                  connectMailbox(
                                    account.account_id
                                  )
                                }
                                disabled={
                                  accountConnecting ||
                                  isConnected ||
                                  Boolean(
                                    mailboxRemovingId
                                  )
                                }
                                style={{
                                  flex: 1,
                                }}
                              >
                                {isConnected
                                  ? "Connected"
                                  : accountConnecting
                                  ? "Connecting..."
                                  : "Use this account"}
                              </button>

                              {!isConnected && (
                                <button
                                  type="button"
                                  className="assess-button"
                                  onClick={() =>
                                    detachMailbox(
                                      account.account_id
                                    )
                                  }
                                  disabled={
                                    accountConnecting ||
                                    Boolean(
                                      mailboxRemovingId
                                    )
                                  }
                                >
                                  Detach
                                </button>
                              )}
                            </div>
                          </div>
                        );
                      }
                    )}
                  </div>
                </div>

                {accountError && (
                  <div
                    className="error-box"
                    style={{
                      marginTop: "12px",
                    }}
                  >
                    {accountError}
                  </div>
                )}

                <div
                  style={{
                    display: "grid",
                    gap: "8px",
                    marginTop: "14px",
                  }}
                >
                  <button
                    type="button"
                    className="assess-button"
                    onClick={
                      openAttachMailbox
                    }
                    disabled={mailboxBusy}
                    style={{
                      width: "100%",
                    }}
                  >
                    + Attach saved mailbox
                  </button>

                  <button
                    type="button"
                    className="assess-button"
                    onClick={
                      openAddMailbox
                    }
                    disabled={mailboxBusy}
                    style={{
                      width: "100%",
                    }}
                  >
                    + Add new mailbox
                  </button>
                </div>

                {connected && (
                  <button
                    type="button"
                    className="assess-button"
                    onClick={
                      disconnectMailbox
                    }
                    disabled={
                      accountConnecting ||
                      Boolean(
                        mailboxRemovingId
                      )
                    }
                    style={{
                      width: "100%",
                      marginTop: "8px",
                    }}
                  >
                    Disconnect active mailbox
                  </button>
                )}

                {selectedAttachedAccount && (
                  <p
                    className="security-source"
                    style={{
                      marginTop: "8px",
                    }}
                  >
                    Selected:{" "}
                    {
                      selectedAttachedAccount.sender_email
                    }
                    . Selection alone does not
                    connect the mailbox.
                  </p>
                )}
              </>
            )}

            {accountError &&
              attachedMailAccounts.length ===
                0 && (
                <div
                  className="error-box"
                  style={{
                    marginTop: "12px",
                  }}
                >
                  {accountError}
                </div>
              )}

            {addMailboxPanelOpen && (
              <div
                className="security-findings"
                style={{
                  marginTop: "14px",
                }}
              >
                <div
                  className="card-header"
                  style={{
                    padding: 0,
                    marginBottom: "12px",
                  }}
                >
                  <div>
                    <span className="section-label">
                      ADD MAILBOX
                    </span>

                    <h4>
                      Add a sending account
                    </h4>
                  </div>
                </div>

                <p
                  className="security-source"
                  style={{
                    marginTop: 0,
                    marginBottom: "14px",
                  }}
                >
                  Choose a provider sign-in for
                  Google or Microsoft, or configure
                  a custom SMTP server. Provider
                  authorization saves the mailbox
                  but does not attach or connect it.
                </p>

                <div
                  style={{
                    display: "grid",
                    gap: "8px",
                    marginBottom: "16px",
                  }}
                >
                  <button
                    type="button"
                    className="assess-button"
                    onClick={() =>
                      startOAuth("google")
                    }
                    disabled={mailboxBusy}
                    style={{
                      width: "100%",
                    }}
                  >
                    {oauthLoading === "google"
                      ? "Opening Google authorization..."
                      : "Continue with Google"}
                  </button>

                  <button
                    type="button"
                    className="assess-button"
                    onClick={() =>
                      startOAuth(
                        "microsoft"
                      )
                    }
                    disabled={mailboxBusy}
                    style={{
                      width: "100%",
                    }}
                  >
                    {oauthLoading ===
                    "microsoft"
                      ? "Opening Microsoft authorization..."
                      : "Continue with Microsoft"}
                  </button>
                </div>

                <div
                  className="security-source"
                  style={{
                    textAlign: "center",
                    marginBottom: "14px",
                  }}
                >
                  — or configure a custom SMTP mailbox —
                </div>

                <label>
                  Email address

                  <input
                    type="email"
                    placeholder="user@example.com"
                    value={
                      newMailboxEmail
                    }
                    onChange={(event) =>
                      setNewMailboxEmail(
                        event.target.value
                      )
                    }
                    disabled={
                      mailboxSaving ||
                      Boolean(
                        oauthLoading
                      )
                    }
                    autoComplete="email"
                  />
                </label>

                <label>
                  SMTP username

                  <input
                    type="text"
                    placeholder="SMTP username"
                    value={
                      newMailboxUsername
                    }
                    onChange={(event) =>
                      setNewMailboxUsername(
                        event.target.value
                      )
                    }
                    disabled={
                      mailboxSaving ||
                      Boolean(
                        oauthLoading
                      )
                    }
                    autoComplete="username"
                  />
                </label>

                <label>
                  Server credential

                  <input
                    type="password"
                    placeholder="Credential required by the custom SMTP server"
                    value={
                      newMailboxPassword
                    }
                    onChange={(event) =>
                      setNewMailboxPassword(
                        event.target.value
                      )
                    }
                    disabled={
                      mailboxSaving ||
                      Boolean(
                        oauthLoading
                      )
                    }
                    autoComplete="new-password"
                  />
                </label>

                <label>
                  SMTP host

                  <input
                    type="text"
                    placeholder="smtp.example.com"
                    value={
                      newMailboxHost
                    }
                    onChange={(event) =>
                      setNewMailboxHost(
                        event.target.value
                      )
                    }
                    disabled={
                      mailboxSaving ||
                      Boolean(
                        oauthLoading
                      )
                    }
                  />
                </label>

                <label>
                  SMTP port

                  <input
                    type="number"
                    min="1"
                    max="65535"
                    placeholder="587"
                    value={
                      newMailboxPort
                    }
                    onChange={(event) =>
                      setNewMailboxPort(
                        event.target.value
                      )
                    }
                    disabled={
                      mailboxSaving ||
                      Boolean(
                        oauthLoading
                      )
                    }
                  />
                </label>

                <label>
                  Security

                  <select
                    value={
                      newMailboxSecurityMode
                    }
                    onChange={(event) =>
                      setNewMailboxSecurityMode(
                        event.target.value
                      )
                    }
                    disabled={
                      mailboxSaving ||
                      Boolean(
                        oauthLoading
                      )
                    }
                  >
                    <option value="starttls">
                      STARTTLS
                    </option>

                    <option value="tls">
                      TLS / SSL
                    </option>

                    <option value="none">
                      None
                    </option>
                  </select>
                </label>

                <label>
                  Provider label (optional)

                  <input
                    type="text"
                    placeholder="Company / Custom / Other"
                    value={
                      newMailboxProvider
                    }
                    onChange={(event) =>
                      setNewMailboxProvider(
                        event.target.value
                      )
                    }
                    disabled={
                      mailboxSaving ||
                      Boolean(
                        oauthLoading
                      )
                    }
                  />
                </label>

                {accountError && (
                  <div
                    className="error-box"
                    style={{
                      marginTop: "12px",
                    }}
                  >
                    {accountError}
                  </div>
                )}

                <div
                  style={{
                    display: "flex",
                    gap: "10px",
                    marginTop: "14px",
                  }}
                >
                  <button
                    type="button"
                    className="assess-button"
                    onClick={
                      createMailbox
                    }
                    disabled={
                      mailboxSaving ||
                      Boolean(
                        oauthLoading
                      )
                    }
                    style={{
                      flex: 1,
                    }}
                  >
                    {mailboxSaving
                      ? "Saving..."
                      : "Save custom SMTP mailbox"}
                  </button>

                  <button
                    type="button"
                    className="assess-button"
                    onClick={
                      closeAddMailbox
                    }
                    disabled={
                      mailboxSaving ||
                      Boolean(
                        oauthLoading
                      )
                    }
                  >
                    Cancel
                  </button>
                </div>

                <p
                  className="security-source"
                  style={{
                    marginTop: "8px",
                  }}
                >
                  Google and Microsoft accounts use
                  provider authorization. Custom SMTP
                  accounts use the credential required
                  by that server. Saved credentials are
                  never displayed. Saving does not
                  attach or activate the mailbox.
                </p>
              </div>
            )}

            {attachPanelOpen && (
              <div
                className="security-findings"
                style={{
                  marginTop: "14px",
                }}
              >
                <div
                  className="card-header"
                  style={{
                    padding: 0,
                    marginBottom: "12px",
                  }}
                >
                  <div>
                    <span className="section-label">
                      ATTACH MAILBOX
                    </span>

                    <h4>
                      Choose an account to attach
                    </h4>
                  </div>
                </div>

                {availableMailAccounts.length ===
                0 ? (
                  <div className="unknown-box">
                    <strong>
                      No additional mailboxes
                      available
                    </strong>

                    <p>
                      There are no saved
                      mailboxes available to
                      attach. Add a new mailbox
                      if you need another
                      connection.
                    </p>
                  </div>
                ) : (
                  <div
                    style={{
                      display: "grid",
                      gap: "8px",
                    }}
                  >
                    {availableMailAccounts.map(
                      (account) => {
                        const selected =
                          attachSelectionId ===
                          account.account_id;

                        return (
                          <button
                            key={
                              account.account_id
                            }
                            type="button"
                            onClick={() =>
                              setAttachSelectionId(
                                account.account_id
                              )
                            }
                            disabled={mailboxBusy}
                            style={{
                              width: "100%",
                              textAlign: "left",
                              padding:
                                "13px 14px",
                              borderRadius:
                                "10px",
                              border:
                                selected
                                  ? "2px solid currentColor"
                                  : "1px solid currentColor",
                              background:
                                "transparent",
                              cursor:
                                accountConnecting
                                  ? "default"
                                  : "pointer",
                              font: "inherit",
                              opacity:
                                accountConnecting
                                  ? 0.65
                                  : 1,
                            }}
                          >
                            <div
                              style={{
                                display:
                                  "flex",
                                justifyContent:
                                  "space-between",
                                alignItems:
                                  "center",
                                gap: "12px",
                              }}
                            >
                              <div
                                style={{
                                  minWidth: 0,
                                }}
                              >
                                <strong
                                  style={{
                                    display:
                                      "block",
                                    overflow:
                                      "hidden",
                                    textOverflow:
                                      "ellipsis",
                                    whiteSpace:
                                      "nowrap",
                                  }}
                                >
                                  {
                                    account.sender_email
                                  }
                                </strong>

                                <span
                                  className="security-source"
                                  style={{
                                    display:
                                      "block",
                                    marginTop:
                                      "3px",
                                  }}
                                >
                                  {account.provider ||
                                    formatAuthenticationLabel(
                                      account
                                    )}{" "}
                                  ·{" "}
                                  {account.smtp
                                    ?.host ||
                                    "Provider authorization"}
                                  {account.smtp
                                    ?.port
                                    ? `:${account.smtp.port}`
                                    : ""}
                                </span>
                              </div>

                              <span
                                className={
                                  selected
                                    ? "positive"
                                    : "neutral"
                                }
                                style={{
                                  flexShrink:
                                    0,
                                }}
                              >
                                {selected
                                  ? "Selected"
                                  : "Select"}
                              </span>
                            </div>
                          </button>
                        );
                      }
                    )}
                  </div>
                )}

                <div
                  style={{
                    display: "flex",
                    gap: "10px",
                    marginTop: "14px",
                  }}
                >
                  <button
                    type="button"
                    className="assess-button"
                    onClick={
                      attachMailbox
                    }
                    disabled={
                      accountConnecting ||
                      !attachSelectionId ||
                      Boolean(
                        mailboxRemovingId
                      ) ||
                      Boolean(
                        oauthLoading
                      )
                    }
                    style={{
                      flex: 1,
                    }}
                  >
                    {accountConnecting
                      ? "Attaching..."
                      : "Attach selected"}
                  </button>

                  <button
                    type="button"
                    className="assess-button"
                    onClick={
                      closeAttachMailbox
                    }
                    disabled={
                      accountConnecting ||
                      Boolean(
                        oauthLoading
                      )
                    }
                  >
                    Cancel
                  </button>
                </div>

                <button
                  type="button"
                  className="assess-button"
                  onClick={
                    openAddMailbox
                  }
                  disabled={mailboxBusy}
                  style={{
                    width: "100%",
                    marginTop: "8px",
                  }}
                >
                  + Add new mailbox
                </button>

                <p
                  className="security-source"
                  style={{
                    marginTop: "8px",
                  }}
                >
                  Attaching only adds the mailbox
                  to this workspace. It does not
                  activate, authenticate, or send
                  through it.
                </p>
              </div>
            )}

            {!attachPanelOpen &&
              !addMailboxPanelOpen &&
              attachedMailAccounts.length ===
                0 &&
              !accountError && (
                <p
                  className="security-source"
                  style={{
                    marginTop: "8px",
                    textAlign: "center",
                  }}
                >
                  No mailbox is accessed until
                  you explicitly attach and
                  connect one.
                </p>
              )}
          </>
        )}
      </section>

      <section className="compose-grid">
        <div className="card compose-card">
          <div className="card-header">
            <div>
              <span className="section-label">
                MESSAGE
              </span>

              <h3>
                Compose email
              </h3>
            </div>

            <span className="draft">
              Draft
            </span>
          </div>

          <label>
            Recipient

            <input
              type="email"
              placeholder="recipient@example.com"
              value={recipient}
              onChange={(event) =>
                setRecipient(
                  event.target.value
                )
              }
            />
          </label>

          <button
            className="assess-button"
            onClick={
              checkRecipient
            }
            disabled={
              loading ||
              !recipient.trim()
            }
          >
            {loading
              ? "Assessing..."
              : "Check recipient security"}
          </button>

          <label>
            Subject

            <input
              type="text"
              placeholder="Subject"
              value={subject}
              onChange={(event) =>
                setSubject(
                  event.target.value
                )
              }
            />
          </label>

          <label>
            Message

            <textarea
              placeholder="Write your message..."
              value={body}
              onChange={(event) =>
                setBody(
                  event.target.value
                )
              }
            />
          </label>

          <div
            style={{
              marginTop: "14px",
            }}
          >
            <input
              ref={attachmentInputRef}
              type="file"
              multiple
              onChange={
                handleAttachmentChange
              }
              style={{
                display: "none",
              }}
            />

            <button
              type="button"
              className="assess-button"
              onClick={() =>
                attachmentInputRef.current?.click()
              }
              disabled={sendLoading}
            >
              Add attachments
            </button>

            <p
              className="security-source"
              style={{
                marginTop: "8px",
              }}
            >
              Optional files · Maximum total
              size 10 MB
            </p>

            {attachments.length > 0 && (
              <div
                className="security-findings"
                style={{
                  marginTop: "12px",
                }}
              >
                <h4>
                  Attachments (
                  {attachments.length}
                  )
                </h4>

                {attachments.map(
                  (file, index) => (
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

                      <span
                        className="neutral"
                        style={{
                          display: "flex",
                          alignItems:
                            "center",
                          gap: "8px",
                          flexShrink: 0,
                        }}
                      >
                        {formatFileSize(
                          file.size
                        )}

                        <button
                          type="button"
                          onClick={() =>
                            removeAttachment(
                              index
                            )
                          }
                          disabled={
                            sendLoading
                          }
                          style={{
                            border: "none",
                            background:
                              "transparent",
                            cursor:
                              sendLoading
                                ? "default"
                                : "pointer",
                            padding:
                              "2px 4px",
                            font: "inherit",
                          }}
                        >
                          Remove
                        </button>
                      </span>
                    </div>
                  )
                )}

                <p
                  className="security-source"
                  style={{
                    marginTop: "8px",
                  }}
                >
                  Total:{" "}
                  {formatFileSize(
                    attachmentTotalSize
                  )}{" "}
                  / 10 MB
                </p>
              </div>
            )}
          </div>
        </div>

        <div>
          <SecurityPanel
            assessment={assessment}
            loading={loading}
            formatDecision={
              formatDecision
            }
          />

          {assessment &&
            !assessment.error &&
            !loading && (
              <SecurityReview
                assessment={assessment}
                mailAccount={
                  mailAccount
                }
                mailAccountLoading={
                  mailAccountLoading
                }
                recipient={recipient}
                subject={subject}
                body={body}
                attachments={attachments}
                sendEmail={sendEmail}
                sendLoading={
                  sendLoading
                }
                sendResult={sendResult}
                formatDecision={
                  formatDecision
                }
                formatAuthenticationLabel={
                  formatAuthenticationLabel
                }
                formatFileSize={
                  formatFileSize
                }
              />
            )}
        </div>
      </section>
    </>
  );
}

export default ComposeView;