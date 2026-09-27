// Gmail content script.
//
// Receiver-side flow from the SecureMailScope architecture:
//   Gmail -> detect E2E envelope -> local private key -> local decryption
//   -> render the original message in place.
//
// Decryption happens entirely in this tab with WebCrypto. Neither the
// plaintext nor the private key is sent anywhere.

(() => {
  const { decrypt, extractEnvelope, looksEncrypted } = SecureMailScopeE2E;

  // Gmail renders each opened message body in a div.a3s element.
  const MESSAGE_BODY_SELECTOR = "div.a3s";

  function getIdentity(email) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(
          { type: "get-identity", email },
          (response) => {
            if (chrome.runtime.lastError) {
              resolve(null);
              return;
            }

            resolve(response?.identity || null);
          }
        );
      } catch {
        resolve(null);
      }
    });
  }

  function element(tag, className, text) {
    const node = document.createElement(tag);

    if (className) {
      node.className = className;
    }

    if (text !== undefined) {
      node.textContent = text;
    }

    return node;
  }

  function formatSize(bytes) {
    if (!bytes) {
      return "";
    }

    if (bytes < 1024) {
      return `${bytes} B`;
    }

    if (bytes < 1024 * 1024) {
      return `${(bytes / 1024).toFixed(1)} KB`;
    }

    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  function buildHeader(title, stateClass) {
    const header = element("div", `sms-header ${stateClass}`);
    header.append(
      element("span", "sms-lock", stateClass === "sms-ok" ? "🔓" : "🔒"),
      element("span", "sms-title", title)
    );
    return header;
  }

  function buildToggle(bodyElement) {
    const toggle = element("button", "sms-link", "Show encrypted envelope");
    toggle.type = "button";

    toggle.addEventListener("click", () => {
      const hidden = bodyElement.style.display === "none";
      bodyElement.style.display = hidden ? "" : "none";
      toggle.textContent = hidden
        ? "Hide encrypted envelope"
        : "Show encrypted envelope";
    });

    return toggle;
  }

  function renderDecrypted(bodyElement, message, envelope) {
    const panel = element("div", "sms-panel");

    panel.append(buildHeader("Decrypted locally by SecureMailScope", "sms-ok"));

    if (message.subject) {
      panel.append(element("div", "sms-subject", message.subject));
    }

    panel.append(element("div", "sms-body", message.body || ""));

    if (Array.isArray(message.attachments) && message.attachments.length) {
      const list = element("div", "sms-attachments");
      list.append(
        element("div", "sms-label", `Encrypted attachments (${message.attachments.length})`)
      );

      for (const attachment of message.attachments) {
        try {
          const blob = new Blob(
            [SecureMailScopeE2E.base64UrlToBytes(attachment.content || "")],
            { type: attachment.content_type || "application/octet-stream" }
          );

          const link = element(
            "a",
            "sms-attachment",
            `${attachment.filename || "attachment"} ${formatSize(blob.size)}`
          );
          link.href = URL.createObjectURL(blob);
          link.download = attachment.filename || "attachment";
          list.append(link);
        } catch {
          list.append(
            element("div", "sms-attachment", `${attachment.filename}: unreadable`)
          );
        }
      }

      panel.append(list);
    }

    const meta = element("div", "sms-meta");
    meta.append(
      element("span", "", `${envelope.content_encryption} + ${envelope.key_encryption}`),
      element("span", "", `Key ${message.decrypted_with_key_id || envelope.recipient_key_id}`),
      buildToggle(bodyElement)
    );
    panel.append(meta);

    bodyElement.style.display = "none";
    bodyElement.before(panel);
    return panel;
  }

  function renderError(bodyElement, error, envelope) {
    const panel = element("div", "sms-panel sms-panel-error");

    panel.append(
      buildHeader("SecureMailScope encrypted message — not decrypted", "sms-error")
    );
    panel.append(element("div", "sms-body", error.message || String(error)));

    const meta = element("div", "sms-meta");

    if (envelope?.recipient_key_id) {
      meta.append(element("span", "", `Encrypted to key ${envelope.recipient_key_id}`));
    }

    const retry = element("button", "sms-link", "Retry");
    retry.type = "button";
    retry.addEventListener("click", () => {
      panel.remove();
      delete bodyElement.dataset.smsState;
      processBody(bodyElement);
    });

    meta.append(retry);
    panel.append(meta);
    bodyElement.before(panel);
    return panel;
  }

  async function processBody(bodyElement) {
    if (bodyElement.dataset.smsState) {
      return;
    }

    const text = bodyElement.textContent || "";

    if (!looksEncrypted(text)) {
      return;
    }

    bodyElement.dataset.smsState = "pending";

    const envelope = extractEnvelope(text);

    if (!envelope) {
      bodyElement.dataset.smsState = "error";
      renderError(
        bodyElement,
        new Error(
          'The encrypted envelope is incomplete. If Gmail shows "[Message clipped]", open "View entire message" and SecureMailScope will decrypt it there.'
        )
      );
      return;
    }

    try {
      const identity = await getIdentity(envelope.recipient);
      const message = await decrypt(envelope, identity);
      renderDecrypted(bodyElement, message, envelope);
      bodyElement.dataset.smsState = "decrypted";
    } catch (error) {
      renderError(bodyElement, error, envelope);
      bodyElement.dataset.smsState = "error";
    }
  }

  function scan() {
    document.querySelectorAll(MESSAGE_BODY_SELECTOR).forEach(processBody);
  }

  let scheduled = null;

  function scheduleScan() {
    if (scheduled) {
      return;
    }

    scheduled = setTimeout(() => {
      scheduled = null;
      scan();
    }, 250);
  }

  new MutationObserver(scheduleScan).observe(document.body, {
    childList: true,
    subtree: true,
  });

  // When keys are synced or imported, retry messages that failed.
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local" || !changes.identities) {
      return;
    }

    document
      .querySelectorAll(`${MESSAGE_BODY_SELECTOR}[data-sms-state="error"]`)
      .forEach((bodyElement) => {
        const panel = bodyElement.previousElementSibling;

        if (panel?.classList.contains("sms-panel")) {
          panel.remove();
        }

        delete bodyElement.dataset.smsState;
      });

    scan();
  });

  scan();
})();
