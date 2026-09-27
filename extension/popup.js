const identitiesElement = document.getElementById("identities");
const statusElement = document.getElementById("status");

function send(message) {
  return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve));
}

async function render() {
  const response = await send({ type: "get-all-identities" });
  const identities = response?.identities || {};
  identitiesElement.replaceChildren();

  const emails = Object.keys(identities);

  if (!emails.length) {
    const empty = document.createElement("p");
    empty.textContent =
      "No keys yet. Open the SecureMailScope app with your mailbox connected, or import an identity backup.";
    identitiesElement.append(empty);
    return;
  }

  for (const email of emails) {
    const identity = identities[email];
    const card = document.createElement("div");
    card.className = "identity";

    const title = document.createElement("strong");
    title.textContent = email;

    const keyId = document.createElement("small");
    keyId.textContent = `Key ${await SecureMailScopeE2E.calculateKeyId(identity.publicKey)}`;

    const extra = document.createElement("small");
    const previous = identity.previousKeys?.length || 0;
    extra.textContent = `Source: ${identity.source || "app"} · ${previous} retired key${previous === 1 ? "" : "s"}`;

    const remove = document.createElement("button");
    remove.className = "remove";
    remove.textContent = "Remove from extension";
    remove.addEventListener("click", async () => {
      await send({ type: "remove-identity", email });
      render();
    });

    card.append(title, keyId, extra, remove);
    identitiesElement.append(card);
  }
}

document.getElementById("import").addEventListener("change", async (event) => {
  const file = event.target.files?.[0];

  if (!file) {
    return;
  }

  try {
    const backup = JSON.parse(await file.text());

    if (backup?.format !== "securemailscope-identity-backup") {
      throw new Error("Not a SecureMailScope identity backup file.");
    }

    const response = await send({
      type: "import-identity",
      email: backup.email,
      identity: backup.identity,
    });

    if (!response?.ok) {
      throw new Error(response?.error || "Import failed.");
    }

    statusElement.style.color = "#1e7a46";
    statusElement.textContent = `Imported key for ${backup.email}.`;
    render();
  } catch (error) {
    statusElement.style.color = "#b42318";
    statusElement.textContent = error.message;
  } finally {
    event.target.value = "";
  }
});

render();
