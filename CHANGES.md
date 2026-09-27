# SecureMailScope — Fixes, Improvements & Testing Guide

This document lists everything that was changed in the codebase, why it was
changed, what was **added to the architecture**, and how to test the whole
product manually (including sending an encrypted message to a friend).

The core architecture is unchanged:

```
Frontend (React/Vite)  →  FastAPI backend  →  EML analyzer / Mailbox integration / Security intelligence
Sender: Compose → Security check → AI/Risk → AES-256-GCM + RSA-OAEP-256 → SMTP/TLS → Gmail
Receiver: Gmail → SecureMailScope (app or browser extension) → local private key → local decryption → "Hello"
```

The backend still **never** sees a private key or the plaintext of an E2E message.

---

## 1. Quick start (any Windows laptop)

1. Install **Python 3.11+** (tick "Add to PATH") and **Node.js 22 LTS**.
2. Double-click **`setup.bat`**: it creates `backend\.venv`, installs the backend
   requirements and runs `npm install` in `frontend`.
   - If the `.venv` came from another laptop inside a zip, it is detected as
     broken and rebuilt automatically.
3. Make sure `backend\.env` contains the Google OAuth client ID and secret
   (see `backend\.env.example`).
4. Double-click **`start.bat`**. It opens:
   - the backend at http://127.0.0.1:8000 (API docs: `/docs`);
   - the frontend at http://localhost:5173.
5. Optional, for the receiver-in-Gmail experience: load the browser extension
   (section 6, step B-6).

> Hosts and ports are intentionally fixed to `127.0.0.1:8000` and `localhost:5173`.
> They match the Google OAuth redirect URI and the CORS configuration.

---

## 2. The main problem: why the receiver saw the encrypted content

**Symptom:** the receiver got the SecureMailScope envelope (ciphertext and key ID)
instead of the decrypted message.

**Root causes found:**

| # | Cause | Effect |
|---|-------|--------|
| 1 | No receiver-side integration existed for Gmail. It was planned in the architecture as a browser extension but never implemented. | Anyone opening the mail in Gmail saw only raw JSON ciphertext. |
| 2 | The in-app decryption did `JSON.parse(whole body)`. | Any extra text, re-wrapping or client formatting made the app treat the mail as plain text and show the ciphertext. |
| 3 | If the receiver's browser had no key, or a different key (new laptop, cleared browser data, other browser), a new key was generated. The backend then rejected it with **409 conflict**, and the error was only written to the console. | Senders kept encrypting to the old registered key, which this browser can never decrypt. Nothing told the user why, or how to fix it. |
| 4 | Decryption errors were generic WebCrypto errors ("OperationError"). | No way to tell a wrong key from a corrupted message. |
| 5 | Encrypted send with any attachment crashed (`file.arrayBuffer is not a function`). Envelopes over 1 MB were rejected by the backend's multipart field limit. | Encrypted attachments never worked. |
| 6 | The public-key registry is a local SQLite file on each laptop. | A sender on laptop A could never encrypt to a friend whose key lives on laptop B. |

**Fixes:**

1. **Gmail browser extension** (`extension/`). It detects the envelope inside Gmail
   and decrypts it locally with WebCrypto. The original message, including
   downloadable attachments, is shown in place.
2. **Robust envelope detection** (`extractEnvelope`). It finds the envelope anywhere
   in the body. Both the old raw-JSON format and the new readable "armored" format
   are supported. The same logic is used in the app, the extension and the backend
   inbox detector.
3. **End-to-end identity panel** (Inbox). It shows this browser's key and the
   registered key, and whether they match. It offers these actions:
   - **Export/Import key backup**;
   - **Publish this browser's key** (fixes the conflict);
   - **Rotate key**;
   - **Sync to extension**.
4. **Keyring.** Retired private keys are kept locally, so older mail stays readable
   after a rotation. The right key is picked by `recipient_key_id`.
5. **Clear error codes**: `NO_LOCAL_KEY`, `KEY_MISMATCH`, `UNWRAP_FAILED` and
   `INTEGRITY_FAILED` (message modified in transit). Each one comes with actionable
   instructions.
6. **Public key cards.** A recipient exports a card containing only the public key
   and sends it to the sender over WhatsApp or email. The sender imports it, and the
   fingerprint is compared by phone. This enables laptop-to-laptop E2E.
7. **Attachments and large envelopes.** File objects are passed straight to
   `encryptMessage`. The envelope is uploaded as a file part (`body_file`, up to
   25 MB). Base64 encoding is chunked, which makes it much faster.

Verified with an automated round trip:

- The app encrypts with a 300 KB attachment.
- The backend builds a real MIME email (quoted-printable) and parses it the way the
  Gmail inbox does.
- Both the app and the extension decrypt it, including the Gmail "text without
  newlines" rendering.
- A tampered ciphertext gives `INTEGRITY_FAILED`.
- After a rotation, old mail still decrypts.
- A fresh browser gives `KEY_MISMATCH`; after importing the backup it decrypts.

---

## 3. ⚠️ Architecture additions (new components / changed contracts)

These are the only places where something **new** was added to the architecture.
Everything else in this document is a bug fix inside existing modules.

### 3.1 NEW: `extension/` — SecureMailScope E2E browser extension (Chrome/Edge, Manifest V3)

This is the "Receiver side → SecureMailScope Browser Extension" box from the
architecture diagram, now implemented.

| File | Role |
|------|------|
| `manifest.json` | Permissions: `storage`. Hosts: `mail.google.com` and the app at `localhost:5173` / `127.0.0.1:5173`. |
| `app-bridge.js` | Runs on the SecureMailScope app. Copies the identities from the app's localStorage into extension storage. Everything stays on the same device. |
| `background.js` | Stores identities in `chrome.storage.local`. |
| `e2e-core.js` | The same crypto as `frontend/src/services/crypto.js`: AES-256-GCM, RSA-OAEP-256, the same AAD and the same key ID. |
| `gmail.js` + `gmail.css` | Watches Gmail message bodies (`div.a3s`), detects envelopes, decrypts locally and renders the plaintext and attachments. Also offers "Show encrypted envelope" and "Retry". |
| `popup.html` / `popup.js` | Lists the synced keys. Imports an identity backup, for a different device or browser. |

Private keys never leave the device: they are copied only from the app's
localStorage into the extension's local storage.

### 3.2 NEW: E2E key-management endpoints (`backend/app/api/crypto.py`, `services/crypto/registry.py`)

| Endpoint | Purpose |
|----------|---------|
| `POST /api/crypto/keys/rotate` | Explicit key rotation. The old public key is moved to the new `crypto_key_history` table. |
| `GET /api/crypto/keys/history?email=` | History of retired keys (audit). |
| `POST /api/crypto/keys/import-contact` | Import a recipient's **public key card**. Stored with `source='contact_card'`, trust model `imported_contact_card`. |
| `POST /api/crypto/assess-recipient` | Now also returns the `key` object, which saves one round trip. |

**Security hardening (changed behaviour).**

- `register` and `rotate` now only accept keys for a mailbox that is authenticated
  in this SecureMailScope instance, through OAuth or SMTP. Other emails get
  **403**.
- Before this, anyone could publish their own key for someone else's address and
  read mail meant for them.
- Contact cards cannot overwrite the key of a mailbox authenticated here.

**Database migrations.** These run automatically, are additive, and keep all
existing data:

- `crypto_keys.db`: new table `crypto_key_history`, and a new column
  `crypto_public_keys.source` (default `mailbox`).
- `mailboxes.db`: new tables `mailbox_state` (attached/connected mailbox) and
  `oauth_pending` (OAuth login sessions).

### 3.3 CHANGED: envelope transport format (backward compatible)

The encrypted email body is now "armored" so it is readable by a human:

```
-----BEGIN SECUREMAILSCOPE E2E MESSAGE-----
This message is end-to-end encrypted with SecureMailScope
(AES-256-GCM + RSA-OAEP-256).
Open it with the SecureMailScope app or the SecureMailScope
browser extension for Gmail to decrypt it locally.

{"protocol":"SecureMailScope-E2E","version":1, ... }
-----END SECUREMAILSCOPE E2E MESSAGE-----
```

- The JSON envelope itself (fields, crypto, AAD) is **unchanged**.
- Old messages in the raw-JSON format still decrypt.

### 3.4 CHANGED: `POST /api/send/email` accepts `body_file`

This is an optional file part carrying the message body (used for encrypted
envelopes, max 25 MB). The old `body` form field still works.

### 3.5 NEW frontend files

- `frontend/src/components/security/E2EIdentityPanel.jsx`: the identity and key
  management UI.
- `frontend/src/services/config.js`: a single `API_BASE`, overridable with
  `VITE_API_BASE`. Before this it was hard-coded in three places, in different
  forms.

### 3.6 NEW project files

- `setup.bat` and `start.bat` (portable setup and start).
- `backend/.env.example` and `frontend/.env.example`.
- `CHANGES.md` (this file).

---

## 4. All bug fixes by area

### 4.1 Mailbox / OAuth / sending (`backend/app/services/email_sender.py`, `api/send.py`, `api/mailbox.py`)

| Bug | Fix |
|-----|-----|
| Re-authorizing an existing Google account always failed with `UNIQUE constraint failed` (inverted branch). After a token expiry, which happens every 7 days in Google "Testing" mode, the account could never reconnect. | Saved accounts are now updated. The refresh token is preserved when Google omits it. |
| Attach/connect state and OAuth state lived only in memory. Every backend reload (`--reload` on any file save) disconnected the mailbox and broke logins that were in progress. | Stored in SQLite (`mailbox_state`, `oauth_pending`) and restored on startup. |
| All `Received` headers were joined into one string. Hop reconstruction therefore always saw **one** hop, and `Authentication-Results` / `DKIM-Signature` were merged too. | Repeated headers are kept as lists. |
| Sending blocked the whole server (blocking SMTP call inside an `async` endpoint). | Runs in the threadpool. |
| The inbox did 20 sequential full raw downloads, attachments included. | Parallel `format=metadata` requests (8 workers). The full message is fetched only when opened. |
| Empty subject or body was rejected, although the API documents both as optional. | Both are allowed. |
| HTML-only emails leaked CSS/JS text into the body and preview. | `<style>`, `<script>` and `<head>` are stripped first. |
| OAuth errors hid Google's real reason (`redirect_uri_mismatch`, `invalid_grant`, ...). | The provider's JSON error body is now parsed. |
| The XOAUTH2 callback resent the token on a server challenge, which caused an auth loop instead of a clean error. | It now answers the challenge with an empty response. |
| The database schema migration ran on every lookup (writes, "database is locked"). | It runs once per process. |
| The inbox preview showed ciphertext for E2E messages. | E2E is detected (metadata only, no decryption). The preview reads "End-to-end encrypted…" and the message gets an `e2e` field. |
| The `/inbox` limit allowed 100, but the service caps it at 50. | Aligned to 50. |
| `requirements.txt` was missing `python-dotenv`, which is imported by `main.py`. A fresh install crashed. | Added. |
| **WinError 10060 on send.** Many campus, office and hackathon networks block outbound SMTP ports (25, 465, 587) but allow HTTPS; sending hung for about 30 s and failed. | ⚠️ **New transport path.** Gmail OAuth accounts first check the SMTP port (5 s timeout). If it is blocked, the already-built message (still E2E-encrypted in the browser) is submitted through the **Gmail API over HTTPS** (`users.messages.send`, covered by the existing `https://mail.google.com/` scope). The result records `submission_channel: gmail_api_https` or `smtp`. Non-Gmail accounts get a clear "network may block SMTP" error. |

### 4.2 Security analysis services (`backend/app/services/...`)

| Bug | Fix |
|-----|-----|
| **Risk score was always "unknown"** and recommendations were nearly empty. Two incompatible `domain_summary` shapes overwrote each other (`domain_assessment.py`). | The shapes are merged. Verified: missing STARTTLS now gives 70/"medium" with the STARTTLS and MTA-STS recommendations. |
| Domains that don't exist or have no MX were rated "low" risk (score 90). | Now "critical" or "unknown" (`domain_scorer.py`, new optional `mx_status`). |
| TLS certificate details were always empty. `getpeercert()` returns `{}` with an unverified context. | The DER certificate is parsed with `cryptography.x509`. Added: key algorithm and size, signature algorithm, expiry, days left, and `certificate_verified: false`. |
| Forward secrecy for static-RSA TLS 1.2 suites showed "unknown". | Now "no". |
| The SMTP prober reported STARTTLS/TLS failures as "host unreachable". `SMTPException` and `SSLError` are subclasses of `OSError`, so they were caught by the wrong handler. | New `tls_error` status and a new **high** finding. TLS evidence is kept even if the EHLO after TLS fails. Uses a fixed `local_hostname`, which avoids slow lookups on Windows. |
| DKIM and DMARC **fail** scored as harmless. A `dmarc=fail (p=REJECT)` message scored 100/"low". | A severity map is used, and the most severe result wins. Verified: now 60/"high". |
| Received-header parsing read the protocol from inside comments (Postfix gave `cipher`). SMTPS, ESMTPSA and Exchange TLS were not recognised as TLS, which inflated HNDL. | Comments are stripped before parsing, and the TLS protocol set was extended. |
| Authentication-Results parsing kept only the last value per method, and Gmail's ARC comment injected fake "pass" results. | Comments are stripped, and all results are kept (new `method_results` field). |
| SSRF: `/api/domain/analyze` and `check-recipient` accepted values like `x@169.254.169.254`. | Strict public-domain validation, returning 400. |
| Bracketed IP literals (`[192.168.1.5]`) became bogus domains. | Fixed in `entities.py`. |
| Multiple MTA-STS `mx:` lines overwrote each other. | All are kept (`mx_patterns`). |
| No size limit on EML uploads. | 25 MB cap, returning 413. |
| TLSA, MTA-STS and SMTP lookups ran one after another. | They run concurrently: `gmail.com` is assessed in about 3 s. |
| The AI engine received empty risk, PQC and MTA-STS evidence (wrong keys), and read the wrong recommendation fields. | It accepts both the top-level and the nested shapes. `check-recipient` now also returns top-level `risk` and `pqc`. |

### 4.3 Frontend (`frontend/src/App.jsx`, `SecurityReview.jsx`, `services/crypto.js`)

| Bug | Fix |
|-----|-----|
| Encrypted send crashed with any attachment. | Fixed (see section 2). |
| Encrypted envelopes over 1 MB were rejected. | `body_file` upload. |
| Envelope detection failed when a body still contained quoted-printable soft line breaks, `=3D` escapes or hard-wrapped lines, so the receiver saw raw ciphertext. | The app, extension and backend now also try an "unwrapped" copy of the body. Verified with normal, soft-break, CRLF soft-break and wrapped bodies. |
| The sender could encrypt to the key of a **previously assessed** recipient after editing the address. | The key is reused only if it belongs to the current recipient. |
| The assessment stayed on screen after the recipient was edited (showed the wrong domain and E2E status). | The assessment is cleared when the recipient changes. |
| The AI assessment was re-requested on **every keystroke**. | Runs once per assessment. |
| The risk panel always showed "Unknown" and the MTA-STS row always showed a green "Observed" (wrong keys). | Correct fields. MTA-STS now shows Enforce / Testing only / Not published. |
| The "Transport" row was blank (a boolean was rendered). | Shows STARTTLS or TLS. |
| The attachment-size error was invisible before an assessment existed. | Shown in the compose card. |
| The OAuth success message never named the provider. A stale closure cleared the mailbox selection after OAuth. | Both fixed. |
| The message view showed "decrypted locally" while still decrypting or after a failure. The authentication row always said "Unknown". | Correct states. Shows SPF, DKIM and DMARC. |
| **+ Add mailbox** opened its panel far below the saved-mailbox list, so it looked like nothing happened. | The panel now scrolls into view when opened. |
| Epoch timestamps were shown as raw digits. There was no loading state when opening a message. The message ID was not URL-encoded. | All fixed. |
| ESLint reported 5 errors. | `npm run lint` is clean. |

### 4.4 Known, intentionally unchanged

- These files are **not used** by the app (`App.jsx` defines its own inline
  versions):
  - `frontend/src/components/compose/ComposeView.jsx`
  - `frontend/src/components/compose/SecurityPanel.jsx`
  - `frontend/src/components/inbox/*`
  - `frontend/src/components/layout/*`
  - `frontend/src/components/security/Metric.jsx`
  - `frontend/src/components/security/SecurityRow.jsx`
  - `frontend/src/services/api.js`, `mailbox.js`, `sending.js`

  They were kept to avoid changing the project structure. Edit the inline versions
  in `App.jsx`.
- Hop numbering: hop 1 is the top `Received` header, which is the final delivery
  step (unchanged semantics).
- Inbox reading is Gmail-only. Microsoft accounts can send but not read, as before.
- Outbound port 25 is blocked on many home and college networks. Live SMTP/TLS
  probing then correctly reports "not observable" and the risk is "unknown". Use a
  mobile hotspot or cloud VM for the live-probe demo if needed.

---

## 5. Handover checklist (zip back to the original laptop)

1. **Delete before zipping:** `backend\.venv` and `frontend\node_modules`.
   - They are machine-specific and large. `setup.bat` recreates them. A copied venv
     is also auto-detected and rebuilt.
2. **Keep:** `backend\data\` (saved mailboxes, OAuth tokens, registered keys) and
   `backend\.env` (OAuth client secret).
   - ⚠️ Because of these, **never share the zip publicly or upload it to GitHub.**
3. On the laptop: run `setup.bat`, then `start.bat`.
4. Private E2E keys live in **the browser** (localStorage), not in the zip. The
   original laptop's browser still has its keys: the storage format is unchanged.
5. Google Cloud Console: the OAuth client must list the redirect URI
   `http://127.0.0.1:8000/api/mailbox/oauth/gmail/callback`. While the consent
   screen is in *Testing* mode, **every Gmail account that logs in must be added as
   a Test user**. Scope used: `https://mail.google.com/`.

---

## 6. Manual testing guide (step by step)

### Test A — Everything on one laptop with two Gmail accounts (fastest demo)

This uses two Gmail accounts, **Sender = A** and **Receiver = B**. Both must be
Test users in Google Cloud.

1. Run `start.bat` and open http://localhost:5173 in **Chrome**.
2. **Register the receiver first.** On the **Compose** page, in the sending-account
   panel:
   1. Choose **Add a sending account**, then **Continue with Google**, and log in
      as **B** in the popup.
   2. Attach B (**Attach**), then click **Use this account** to connect it.
   3. Connecting creates B's key pair *in this browser* and publishes B's public key.
3. Go to **Inbox**. The **End-to-end identity** panel must say **"Keys match"**.
4. Back on **Compose**, add, attach and **Use this account** for account **A** in
   the same way. This makes A the active sending mailbox.
5. Type recipient **B**, then click **Check recipient security**. You should see:
   - the transport posture (MX, MTA-STS, risk);
   - the AI summary;
   - under *End-to-end encryption*, **Recipient key: Available**.
6. Type a subject and "Hello", attach a small file, and click **Confirm & Send**. The
   result
   card shows **"Encrypted SecureMailScope message submitted"** with AES-256-GCM,
   RSA-OAEP-256 and the key ID.
7. **Prove what traveled.** Open B's mailbox at mail.google.com *without* the
   extension. You see only the armored ciphertext block, not "Hello".
8. **Receive in the app.** Switch to **B** (Compose, then **Use this account** on B), open
   **Inbox** and find the message with the **E2E ENCRYPTED** badge. Opening it shows
   "Message decrypted locally", the subject, "Hello" and the decrypted attachment.

### Test B — Receive directly inside Gmail (browser extension)

1. Open `chrome://extensions` (or `edge://extensions`) and turn on **Developer
   mode**.
2. Click **Load unpacked** and select the project's **`extension`** folder.
3. Reload the SecureMailScope tab (http://localhost:5173) once. The extension copies
   the local keys; the Inbox panel shows **"Gmail browser extension: Connected"**.
4. Click the extension icon. Account B must be listed with its key ID.
5. Open mail.google.com as **B** and open the encrypted message. A green panel shows
   **"Decrypted locally by SecureMailScope"** with "Hello" and a download link for
   the attachment. **Show encrypted envelope** reveals the ciphertext that actually
   traveled.
6. If Gmail shows "[Message clipped]" (large attachments), click **View entire
   message**; it is decrypted there.

### Test C — You (laptop 1) send an encrypted message to your friend (laptop 2)

Each laptop has its own backend and key registry, so the friend's **public key
card** must be exchanged first.

On the **friend's laptop** (receiver):

1. Run `start.bat` and connect **the friend's Gmail** in SecureMailScope.
2. Go to **Inbox**, End-to-end identity panel, and confirm it says **Keys match**.
3. Click **Share my public key card**. A file
   `securemailscope-public-key-<friend-email>.json` downloads. It contains **no
   private key**.
4. Send that file to yourself over WhatsApp or email. Also read the **fingerprint**
   shown in the notice aloud to you on a call.

On **your laptop** (sender):

5. Your Gmail account must be a Test user of the Google Cloud project in `.env`. Run
   `start.bat` and connect **your Gmail** as the sending mailbox.
6. Go to **Inbox**, End-to-end identity panel, and click **Import contact's key
   card**. Choose the friend's file.
7. Compare the fingerprint in the success notice with what your friend read out.
   They must be identical; this is what protects against a swapped key.
8. On **Compose**, type the friend's email and click **Check recipient security**.
   It should show **Recipient key: Available**.
9. Write "Hello", then **Confirm & Send**.

Back on the **friend's laptop**:

10. Open the message in the SecureMailScope **Inbox**, or in Gmail with the
    extension loaded (Test B). It decrypts locally to "Hello".

If your friend ever rotates their key, they must send you a new card. When you
import it, click **Replace stored key for …** after verifying the new fingerprint.

### Test D — Failure cases (good to show the judges)

| Scenario | How | Expected result |
|----------|-----|-----------------|
| Wrong/missing key | Open the encrypted mail in another browser or profile that never connected B. | "No SecureMailScope private key…" or `KEY_MISMATCH`, with instructions. |
| Recover on a new device | On the original browser: Inbox, then **Export key backup**. On the new browser: **Import key backup** (or use the extension popup, *Import identity backup*). | The message decrypts. |
| Key mismatch fix | In a fresh browser, connect B. | The panel shows **Action needed**. **Publish this browser's key** makes new mail decryptable here. |
| Rotation | Click **Rotate key**, then **Confirm**. | New key ID. Old mail still opens (retired key kept locally). |
| No key registered | Send to an address that never used SecureMailScope. | A confirm dialog offers a standard (non-E2E) email; the result card says E2E was not available. |
| Attacker publishes a key | `POST /api/crypto/keys/register` for an email not authenticated here (e.g. from `/docs`). | **403**. |

### Test E — Security intelligence features

1. **Recipient posture:** on Compose, check any address, e.g. `someone@gmail.com`.
   It shows MX hosts, MTA-STS mode (gmail.com gives *Enforce*), STARTTLS/TLS,
   risk, PQC readiness, recommendations and the AI summary.
   - If port 25 is blocked on your network, SMTP/TLS shows "Not observable". That is
     the honest result, not a bug.
2. **EML forensics:** open http://127.0.0.1:8000/docs, then **POST /api/eml/analyze**.
   Upload `samples/test_email.eml` or any `.eml` you export from Gmail ("Show
   original", then "Download original"). It returns the hop reconstruction, the
   SPF/DKIM/DMARC evaluation, findings, risk and HNDL.
3. **Received-message analysis:** open any normal (non-E2E) mail in the Inbox. The
   Security analysis card shows risk, SPF/DKIM/DMARC and HNDL, computed from all
   `Received` hops.

---

## 7. Suggested demo script (hackathon)

1. Compose "Hello" to the receiver, then **Check recipient security**. Show the
   transport posture, MTA-STS, the AI explanation and "Recipient key: Available".
2. **Confirm & Send.** Show the result card: AES-256-GCM + RSA-OAEP-256 and the key ID.
3. Show Gmail **without** the extension: only ciphertext traveled.
4. Enable the extension and open the same mail. It decrypts locally to "Hello"; click
   **Show encrypted envelope** to contrast.
5. Show the Inbox security analysis (DKIM/SPF/DMARC and hops) and explain the
   difference between transport security and E2E.
6. Show resilience: key backup/restore, rotation with the old-key keyring, a
   tampered message (integrity failure), and a 403 when someone tries to register a
   key for an address they don't own.
