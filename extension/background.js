// SecureMailScope extension service worker.
//
// Holds the recipient identities (RSA-OAEP key pairs) that were synced
// from the SecureMailScope web app running on this same device, or
// imported from an identity backup file. Keys stay in
// chrome.storage.local and are never sent to any server.

const IDENTITIES_KEY = "identities";

async function readIdentities() {
  const stored = await chrome.storage.local.get(IDENTITIES_KEY);
  return stored[IDENTITIES_KEY] || {};
}

async function writeIdentities(identities) {
  await chrome.storage.local.set({ [IDENTITIES_KEY]: identities });
}

function isIdentity(value) {
  return Boolean(value?.publicKey?.n && value?.privateKey?.d);
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    switch (message?.type) {
      case "sync-identities": {
        const identities = await readIdentities();
        let synced = 0;

        for (const [email, identity] of Object.entries(
          message.identities || {}
        )) {
          if (isIdentity(identity)) {
            identities[email.trim().toLowerCase()] = {
              ...identity,
              syncedAt: new Date().toISOString(),
              source: "app",
            };
            synced += 1;
          }
        }

        await writeIdentities(identities);
        sendResponse({ ok: true, synced });
        return;
      }

      case "import-identity": {
        const email = String(message.email || "").trim().toLowerCase();

        if (!email || !isIdentity(message.identity)) {
          sendResponse({ ok: false, error: "Invalid identity backup." });
          return;
        }

        const identities = await readIdentities();
        identities[email] = {
          ...message.identity,
          syncedAt: new Date().toISOString(),
          source: "backup",
        };
        await writeIdentities(identities);
        sendResponse({ ok: true });
        return;
      }

      case "get-identity": {
        const identities = await readIdentities();
        const email = String(message.email || "").trim().toLowerCase();
        sendResponse({ ok: true, identity: identities[email] || null });
        return;
      }

      case "get-all-identities": {
        sendResponse({ ok: true, identities: await readIdentities() });
        return;
      }

      case "remove-identity": {
        const identities = await readIdentities();
        delete identities[String(message.email || "").trim().toLowerCase()];
        await writeIdentities(identities);
        sendResponse({ ok: true });
        return;
      }

      default:
        sendResponse({ ok: false, error: "Unknown message type." });
    }
  })();

  // Keep the channel open for the async response.
  return true;
});
