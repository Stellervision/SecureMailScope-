import { useEffect, useRef, useState } from "react";

import {
  exportIdentityBackup,
  exportPublicKeyCard,
  getIdentityStatus,
  importIdentityBackup,
  importPublicKeyCard,
  notifyExtension,
  publishLocalIdentity,
  rotateIdentity,
} from "../../services/crypto";

// Receiver-side key management for SecureMailScope E2E.
//
// A message can only be decrypted by the browser holding the private
// key that matches the key registered for the mailbox. This panel makes
// that state visible and fixable: backup/restore, publishing this
// browser's key after a mismatch, rotation, and extension sync status.
function E2EIdentityPanel({
  email,
  registration,
  onChanged,
}) {
  const [status, setStatus] =
    useState(null);

  const [busy, setBusy] =
    useState(false);

  const [notice, setNotice] =
    useState(null);

  const [confirmRotate, setConfirmRotate] =
    useState(false);

  const [extensionPresent, setExtensionPresent] =
    useState(false);

  const importInputRef =
    useRef(null);

  const cardInputRef =
    useRef(null);

  // Card waiting for "replace" confirmation after a key conflict.
  const [pendingCard, setPendingCard] =
    useState(null);

  const refreshStatus = async () => {
    try {
      setStatus(
        await getIdentityStatus(
          email
        )
      );
    } catch (error) {
      setNotice({
        type: "error",
        message:
          error.message ||
          "Unable to read the local identity.",
      });
    }
  };

  useEffect(() => {
    let cancelled = false;

    getIdentityStatus(email)
      .then((result) => {
        if (!cancelled) {
          setStatus(result);
        }
      })
      .catch(() => {});

    return () => {
      cancelled = true;
    };
  }, [
    email,
    registration,
  ]);

  useEffect(() => {
    const handleMessage = (
      event
    ) => {
      if (
        event.source !==
          window ||
        (event.data?.type !==
          "securemailscope-extension-present" &&
          event.data?.type !==
            "securemailscope-extension-synced")
      ) {
        return;
      }

      setExtensionPresent(true);
    };

    window.addEventListener(
      "message",
      handleMessage
    );

    window.postMessage(
      {
        type: "securemailscope-extension-ping",
      },
      window.location.origin
    );

    return () => {
      window.removeEventListener(
        "message",
        handleMessage
      );
    };
  }, []);

  const runAction = async (
    action,
    successMessage
  ) => {
    setBusy(true);
    setNotice(null);

    try {
      const result =
        await action();

      setNotice({
        type: "success",
        message:
          successMessage,
      });

      onChanged?.({
        status: "success",
        email,
        ...(result &&
        typeof result ===
          "object"
          ? result
          : {}),
      });

      await refreshStatus();
    } catch (error) {
      setNotice({
        type: "error",
        message:
          error.message ||
          "The operation failed.",
      });
    } finally {
      setBusy(false);
      setConfirmRotate(false);
    }
  };

  const handleExport = () => {
    try {
      const backup =
        exportIdentityBackup(
          email
        );

      downloadJson(
        backup,
        `securemailscope-identity-${email}.json`
      );

      setNotice({
        type: "success",
        message:
          "Identity backup downloaded. It contains your private key: store it safely and never email it.",
      });
    } catch (error) {
      setNotice({
        type: "error",
        message: error.message,
      });
    }
  };

  const handleImport = async (
    event
  ) => {
    const file =
      event.target.files?.[0];

    event.target.value = "";

    if (!file) {
      return;
    }

    await runAction(
      async () => {
        const backup = JSON.parse(
          await file.text()
        );

        const importedEmail =
          importIdentityBackup(
            backup
          );

        return {
          email: importedEmail,
        };
      },
      "Identity backup imported. Messages encrypted to the imported key can now be decrypted in this browser."
    );
  };

  const downloadJson = (
    data,
    filename
  ) => {
    const url =
      URL.createObjectURL(
        new Blob(
          [
            JSON.stringify(
              data,
              null,
              2
            ),
          ],
          {
            type: "application/json",
          }
        )
      );

    const link =
      document.createElement("a");

    link.href = url;
    link.download = filename;
    link.click();

    URL.revokeObjectURL(url);
  };

  const handleExportCard =
    async () => {
      try {
        const card =
          await exportPublicKeyCard(
            email
          );

        downloadJson(
          card,
          `securemailscope-public-key-${email}.json`
        );

        setNotice({
          type: "success",
          message: `Public key card downloaded. It contains no private key, so it can be sent over WhatsApp or email. Fingerprint: ${card.fingerprint}`,
        });
      } catch (error) {
        setNotice({
          type: "error",
          message: error.message,
        });
      }
    };

  const importCard = async (
    card,
    replace
  ) => {
    setBusy(true);
    setNotice(null);

    try {
      const result =
        await importPublicKeyCard(
          card,
          {
            replace,
          }
        );

      setPendingCard(null);

      setNotice({
        type: "success",
        message: `Key for ${card.email} imported (${result.key?.key_id}). Confirm this fingerprint with them by phone or in person: ${result.key?.fingerprint}`,
      });
    } catch (error) {
      if (
        error.code ===
        "CONTACT_CONFLICT"
      ) {
        setPendingCard(card);
      }

      setNotice({
        type: "error",
        message: error.message,
      });
    } finally {
      setBusy(false);
    }
  };

  const handleImportCard =
    async (event) => {
      const file =
        event.target.files?.[0];

      event.target.value = "";

      if (!file) {
        return;
      }

      try {
        await importCard(
          JSON.parse(
            await file.text()
          ),
          false
        );
      } catch (error) {
        setNotice({
          type: "error",
          message: error.message,
        });
      }
    };

  const mismatch =
    status?.hasLocalKey &&
    status?.registeredKeyId &&
    !status?.match;

  return (
    <section
      className="card"
      style={{
        marginBottom: "16px",
      }}
    >
      <div className="card-header">
        <div>
          <span className="section-label">
            END-TO-END IDENTITY
          </span>

          <h3>
            {status?.match
              ? "Ready to receive encrypted mail"
              : mismatch
                ? "Key mismatch: new encrypted mail cannot be decrypted here"
                : "Encryption identity"}
          </h3>
        </div>

        <span
          className={
            status?.match
              ? "positive"
              : "neutral"
          }
        >
          {status?.match
            ? "Keys match"
            : mismatch
              ? "Action needed"
              : "Checking..."}
        </span>
      </div>

      <div className="security-findings">
        <div className="security-row">
          <span>Mailbox</span>
          <span className="neutral">
            {email}
          </span>
        </div>

        <div className="security-row">
          <span>
            This browser's key
          </span>
          <span className="neutral">
            {status?.localKeyId ||
              "None"}
          </span>
        </div>

        <div className="security-row">
          <span>
            Registered key (senders use)
          </span>
          <span
            className={
              status?.match
                ? "positive"
                : "neutral"
            }
          >
            {status?.registeredKeyId ||
              "Not registered"}
          </span>
        </div>

        {status?.previousKeyIds
          ?.length > 0 && (
          <div className="security-row">
            <span>
              Retired keys kept locally
            </span>
            <span className="neutral">
              {
                status.previousKeyIds
                  .length
              }
            </span>
          </div>
        )}

        <div className="security-row">
          <span>
            Gmail browser extension
          </span>
          <span
            className={
              extensionPresent
                ? "positive"
                : "neutral"
            }
          >
            {extensionPresent
              ? "Connected: keys synced"
              : "Not detected"}
          </span>
        </div>
      </div>

      {mismatch && (
        <div className="unknown-box">
          <strong>
            Why encrypted mail shows as
            ciphertext
          </strong>

          <p>
            Senders encrypt to the
            registered key, but this
            browser holds a different
            private key. Import the backup
            of the registered key to read
            existing messages, or publish
            this browser's key so new
            messages are encrypted to it.
          </p>
        </div>
      )}

      {notice && (
        <div
          className={
            notice.type ===
            "error"
              ? "error-box"
              : "unknown-box"
          }
        >
          {notice.message}
        </div>
      )}

      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: "8px",
          marginTop: "12px",
        }}
      >
        <button
          type="button"
          className="assess-button"
          onClick={handleExport}
          disabled={
            busy ||
            !status?.hasLocalKey
          }
        >
          Export key backup
        </button>

        <button
          type="button"
          className="assess-button"
          onClick={() =>
            importInputRef.current?.click()
          }
          disabled={busy}
        >
          Import key backup
        </button>

        <input
          ref={importInputRef}
          type="file"
          accept="application/json,.json"
          onChange={handleImport}
          style={{
            display: "none",
          }}
        />

        <button
          type="button"
          className="assess-button"
          onClick={handleExportCard}
          disabled={
            busy ||
            !status?.registeredKeyId
          }
        >
          Share my public key card
        </button>

        <button
          type="button"
          className="assess-button"
          onClick={() =>
            cardInputRef.current?.click()
          }
          disabled={busy}
        >
          Import contact's key card
        </button>

        <input
          ref={cardInputRef}
          type="file"
          accept="application/json,.json"
          onChange={handleImportCard}
          style={{
            display: "none",
          }}
        />

        {pendingCard && (
          <button
            type="button"
            className="assess-button"
            onClick={() =>
              importCard(
                pendingCard,
                true
              )
            }
            disabled={busy}
          >
            Replace stored key for{" "}
            {pendingCard.email}
          </button>
        )}

        {mismatch && (
          <button
            type="button"
            className="assess-button"
            onClick={() =>
              runAction(
                () =>
                  publishLocalIdentity(
                    email
                  ),
                "This browser's key is now the registered key. New encrypted messages will be decryptable here."
              )
            }
            disabled={busy}
          >
            Publish this browser's key
          </button>
        )}

        <button
          type="button"
          className="assess-button"
          onClick={() => {
            if (!confirmRotate) {
              setConfirmRotate(true);
              return;
            }

            runAction(
              () =>
                rotateIdentity(
                  email
                ),
              "New key generated and registered. The previous key is kept locally so older messages stay readable."
            );
          }}
          disabled={busy}
        >
          {confirmRotate
            ? "Confirm: rotate key"
            : "Rotate key"}
        </button>

        {extensionPresent && (
          <button
            type="button"
            className="assess-button"
            onClick={() => {
              notifyExtension();

              setNotice({
                type: "success",
                message:
                  "Keys re-synced to the Gmail extension.",
              });
            }}
            disabled={busy}
          >
            Sync to extension
          </button>
        )}
      </div>
    </section>
  );
}

export default E2EIdentityPanel;
