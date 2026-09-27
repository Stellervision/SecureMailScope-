import MessageView from "./MessageView";

function InboxView({
  messages,
  loading,
  error,
  selectedMessage,
  loadInbox,
  openMessage,
  closeMessage,
  mailAccount,
  formatDate,
}) {
  return (
    <>
      <section className="hero">
        <div>
          <span className="eyebrow">
            INBOX
          </span>

          <h2>
            Your secure inbox.
          </h2>

          <p>
            Incoming messages can be
            inspected and assessed for
            observable security signals.
          </p>
        </div>
      </section>

      {selectedMessage ? (
        <MessageView
          message={selectedMessage}
          onBack={closeMessage}
          formatDate={formatDate}
        />
      ) : (
        <section className="card">
          <div className="card-header">
            <div>
              <span className="section-label">
                MAILBOX
              </span>

              <h3>
                {loading
                  ? "Loading messages..."
                  : `${messages.length} message${
                      messages.length ===
                      1
                        ? ""
                        : "s"
                    }`}
              </h3>
            </div>

            {mailAccount?.connected && (
              <button
                className="assess-button"
                onClick={loadInbox}
                disabled={loading}
              >
                {loading
                  ? "Refreshing..."
                  : "Refresh"}
              </button>
            )}
          </div>

          {!mailAccount?.connected && (
            <div className="unknown-box">
              <strong>
                No mailbox connected
              </strong>

              <p>
                Attach and connect a
                mailbox from the Compose
                workspace before
                accessing mailbox data.
              </p>
            </div>
          )}

          {error && (
            <div className="error-box">
              {error}
            </div>
          )}

          {mailAccount?.connected &&
            loading && (
              <div className="empty-state">
                <div className="shield">
                  ⌁
                </div>

                <h4>
                  Loading inbox
                </h4>

                <p>
                  Retrieving messages from
                  the connected mail provider.
                </p>
              </div>
            )}

          {mailAccount?.connected &&
            !loading &&
            !error &&
            messages.length ===
              0 && (
              <div className="empty-state">
                <div className="shield">
                  ⌁
                </div>

                <h4>
                  No messages
                </h4>

                <p>
                  No messages are available
                  through the current
                  mailbox integration.
                </p>
              </div>
            )}

          {mailAccount?.connected &&
            !loading &&
            messages.length > 0 && (
              <div className="inbox-list">
                {messages.map(
                  (message) => (
                    <button
                      key={message.id}
                      className="inbox-message"
                      onClick={() =>
                        openMessage(
                          message.id
                        )
                      }
                    >
                      <div className="inbox-message-main">
                        <strong>
                          {message.sender}
                        </strong>

                        <span>
                          {message.subject}
                        </span>

                        <p>
                          {message.preview}
                        </p>
                      </div>

                      <div className="inbox-message-meta">
                        <span>
                          {formatDate(
                            message.received_at
                          )}
                        </span>

                        <span className="live-badge">
                          {message.provider}
                        </span>
                      </div>
                    </button>
                  )
                )}
              </div>
            )}
        </section>
      )}
    </>
  );
}

export default InboxView;