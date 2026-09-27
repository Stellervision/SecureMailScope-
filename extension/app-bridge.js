// Runs on the SecureMailScope web app (localhost:5173).
//
// The web app keeps each mailbox identity in localStorage under
// "securemailscope_e2e_identity_v1:<email>". This bridge copies those
// identities into extension storage so gmail.js can decrypt inside
// Gmail. Everything stays on this device.

(() => {
  const PREFIX = "securemailscope_e2e_identity_v1:";

  function collectIdentities() {
    const identities = {};

    for (let index = 0; index < localStorage.length; index += 1) {
      const key = localStorage.key(index);

      if (!key || !key.startsWith(PREFIX)) {
        continue;
      }

      try {
        identities[key.slice(PREFIX.length)] = JSON.parse(
          localStorage.getItem(key)
        );
      } catch {
        // Ignore malformed entries.
      }
    }

    return identities;
  }

  function sync() {
    const identities = collectIdentities();

    if (!Object.keys(identities).length) {
      return;
    }

    try {
      chrome.runtime.sendMessage(
        { type: "sync-identities", identities },
        (response) => {
          if (chrome.runtime.lastError) {
            return;
          }

          window.postMessage(
            {
              type: "securemailscope-extension-synced",
              synced: response?.synced || 0,
            },
            window.location.origin
          );
        }
      );
    } catch {
      // Extension was reloaded; the page needs a refresh.
    }
  }

  window.addEventListener("message", (event) => {
    if (event.source !== window || event.origin !== window.location.origin) {
      return;
    }

    if (event.data?.type === "securemailscope-identities-updated") {
      sync();
    }

    if (event.data?.type === "securemailscope-extension-ping") {
      window.postMessage(
        { type: "securemailscope-extension-present" },
        window.location.origin
      );
    }
  });

  window.postMessage(
    { type: "securemailscope-extension-present" },
    window.location.origin
  );

  sync();
})();
