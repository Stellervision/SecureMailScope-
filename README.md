# SecureMailScope

**AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**
SIH Problem Statement **26159** · Theme: Blockchain & Cybersecurity

SecureMailScope checks how securely an email will travel *before* you send it, then encrypts it
end-to-end so that only the recipient can read it.

It evaluates:

- MX, MTA-STS, DANE/TLSA and STARTTLS/TLS for the recipient's mail servers;
- certificates, HNDL exposure and PQC readiness;
- SPF, DKIM and DMARC for received mail.

Messages are encrypted **in your browser** with AES-256-GCM + RSA-OAEP-256. The recipient decrypts
locally in the SecureMailScope dashboard, or directly inside Gmail with the included browser
extension. The backend never sees private keys or plaintext.

```
Sender:   Compose → Security check → AI / Risk → AES-256-GCM + RSA-OAEP-256 → Gmail
Receiver: Gmail → SecureMailScope (dashboard or extension) → local private key → "Hello"
```

---

## For judges: what to look at (60 seconds)

1. **Compose → Check recipient security** — live DNS/TLS posture of the recipient's mail
   servers (MX, MTA-STS, STARTTLS, certificate, risk score, PQC readiness, AI explanation).
2. **Confirm & Send** — the message is encrypted in the browser. Open the same mail in **plain
   Gmail**: you see only the ciphertext block. Even Google cannot read the content.
3. **INBOX in SecureMailScope (or the Chrome extension)** — the recipient's browser decrypts the
   mail locally with the private key that never left that browser.
4. **The E2E proof:** the same mailbox opened on a *second* machine (or another instance) shows
   ciphertext — only the key holder's browser can decrypt. This is the property that
   transport security (TLS alone) cannot give you.
5. **FORENSICS** — upload any `.eml` (e.g. `samples/test_email.eml`) for hop reconstruction,
   SPF/DKIM/DMARC authentication results, findings and risk scoring.

| Folder | What it is |
|--------|------------|
| `backend/` | FastAPI backend: DNS/SMTP/TLS analysis, EML forensics, risk/HNDL/PQC, AI explanation layer, sending (SMTP/Gmail API), inbox retrieval (IMAP/Gmail API), key registry |
| `frontend/` | React + Vite dashboard (Compose, Security review, Inbox, E2E key management) |
| `extension/` | Chrome/Edge extension that decrypts SecureMailScope messages inside Gmail |
| `samples/` | Sample `.eml` for the forensics API |
| `CHANGES.md` | Detailed change log, architecture notes and extended test guide |
| `RUN-DEMO.md` | Short operator script for a live demo |

---

## 1. Prerequisites (install once)

| Software | Version | Notes |
|----------|---------|-------|
| **Python** | 3.11 or newer | Windows: tick **"Add python.exe to PATH"** during install |
| **Node.js** | 22 LTS (or 20.19+) | https://nodejs.org |
| **Git** | any | https://git-scm.com |
| **Google Chrome** or Edge | recent | Needed for the Gmail extension |

## 2. Run it locally (Windows, one click)

1. Clone the repository:
   ```bat
   git clone https://github.com/Stellervision/SecureMailScope-.git
   cd SecureMailScope-
   ```
2. Double-click **`setup.bat`** once. It creates `backend\.venv`, installs Python packages and
   runs `npm install` in `frontend`.
3. Double-click **`start.bat`**. Two windows open (backend on port 8000, frontend on port 5173).
   **Keep both open.** Your browser opens **http://localhost:5173**.

macOS / Linux:

```bash
git clone https://github.com/Stellervision/SecureMailScope-.git
cd SecureMailScope-

# Backend
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# Frontend (second terminal)
cd frontend
npm install
npm run dev -- --host localhost --port 5173 --strictPort
```

## 3. Connect a Gmail account — choose ONE of the two ways

The page switcher is the small bar at the bottom: **INBOX · SENT · COMPOSE · SECURITY · FORENSICS**.

### Option A — Gmail App Password (recommended: no Google Cloud setup, works anywhere)

1. In the Gmail account you want to use, enable **2-Step Verification**, then create an
   **App password**: https://myaccount.google.com/apppasswords (16 letters, shown once).
2. In the app: **COMPOSE → Mailbox → + Add mailbox → custom SMTP form**.
   Fill in:
   | Field | Value |
   |-------|-------|
   | Email / Username | the Gmail address |
   | Password | the 16-letter **App password** (not the Gmail password) |
   | SMTP host | `smtp.gmail.com` |
   | SMTP port | `587` |
   | Security mode | `starttls` |
3. Save → **Attach** the account → **Use this account**.

Connecting creates the **encryption key pair inside this browser**. The private key never leaves
the browser; only the public key is registered with the backend. Sending happens over SMTP with
the App Password; the inbox is read over IMAP — both work without any OAuth configuration.

### Option B — Google OAuth (optional)

1. Open https://console.cloud.google.com and create a project.
2. **Enable the Gmail API** (*APIs & Services → Library*).
3. **OAuth consent screen**: user type *External*, scopes `openid`, `email`, `profile`,
   `https://mail.google.com/`, and add every team Gmail as a **Test user**.
4. **Credentials → Create credentials → OAuth client ID** (Web application) with redirect URI
   ```
   http://127.0.0.1:8000/api/mailbox/oauth/gmail/callback
   ```
5. Put the client ID and secret into `backend/.env`:
   ```
   SECUREMAILSCOPE_GOOGLE_CLIENT_ID=xxxxxxxx.apps.googleusercontent.com
   SECUREMAILSCOPE_GOOGLE_CLIENT_SECRET=xxxxxxxx
   ```
6. In the app, click **Continue with Google** and sign in.

> Keep the client secret private. It goes only into `backend/.env`, which is git-ignored.

## 4. Send an encrypted email and read it

**Same browser, two Gmail accounts (simplest demo):** connect both accounts (Option A twice).
Connect the **recipient's** account first so its key is registered, then connect the sender.
Compose → recipient address → **Check recipient security** → write the message → **Confirm & Send**.
Switch to the recipient account → **INBOX** → open the mail marked **E2E encrypted** → it decrypts
locally.

**Two laptops:** each instance holds its own keys, so the sender imports the recipient's
**public key card** (contains no private key — safe to send over WhatsApp):

1. Recipient: **INBOX → END-TO-END IDENTITY → Share my public key card**, send the downloaded
   `.json` to the sender and read the **fingerprint** out loud.
2. Sender: **INBOX → Import contact's key card**, choose the file, verify the fingerprint.
3. Compose → send as above. The recipient's browser decrypts it in their **INBOX**.

## 5. Decrypt directly inside Gmail (browser extension)

Plain Gmail shows only the encrypted block. That is intended: it proves only ciphertext travelled.

1. Open `chrome://extensions` (or `edge://extensions`) and turn on **Developer mode**.
2. Click **Load unpacked** and select the **`extension`** folder of this repo.
3. Open or reload **http://localhost:5173** once, in the same browser where you connected your
   Gmail. The extension copies your keys locally, and the INBOX card shows
   **Gmail browser extension: Connected**.
4. Open the encrypted mail in Gmail. A green **"Decrypted locally by SecureMailScope"** panel shows
   the message and any attachments.

## 6. Deploying for an online round (optional)

The E2E layer uses the Web Crypto API, which requires a **secure context (HTTPS)** — every free
hosting platform below provides HTTPS automatically.

**Backend — Render (free web service):**

1. Push this repository to GitHub.
2. Render → **New → Web Service** → select the repo, **Root directory** `backend`.
3. Build command: `pip install -r requirements.txt`
   Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. Environment variable:
   `SECUREMAILSCOPE_CORS_ORIGINS=https://<your-frontend-domain>` (comma-separated list; the
   localhost defaults are always included).
5. Free-tier notes: the service sleeps after inactivity (first request takes ~50 s to wake), and
   the SQLite databases reset on redeploy — re-add the demo mailboxes after deploying.

**Frontend — Netlify (drag & drop, no Git needed):**

1. In `frontend/`, build with the backend URL baked in:
   ```bat
   set VITE_API_BASE=https://<your-backend>.onrender.com
   npm run build
   ```
   (PowerShell: `$env:VITE_API_BASE="https://<your-backend>.onrender.com"; npm run build`)
2. Drag the generated **`dist`** folder onto https://app.netlify.com/drop.
3. Open the Netlify URL — it talks to the Render backend over HTTPS.

**Security caveat for hosted demos:** the API has no user authentication (out of scope for the
prototype), and the backend stores mailbox App Passwords so it can send/receive. Keep the deployed
URL unlisted, use dedicated demo Gmail accounts only, and delete the service after evaluation.

## 7. Other features to try

- **Recipient security posture:** on COMPOSE, enter any address and click **Check recipient
  security**: MX hosts, MTA-STS mode, STARTTLS/TLS and certificate details, risk score, PQC
  readiness, recommendations and an AI explanation.
- **EML forensics:** open http://127.0.0.1:8000/docs, then use **POST /api/eml/analyze** to upload
  any `.eml` file (e.g. `samples/test_email.eml`, or Gmail's *Show original → Download original*).
  It returns hop reconstruction, SPF/DKIM/DMARC, findings, risk and HNDL.
- **Key management** (INBOX, END-TO-END IDENTITY card):
  - **Export/Import key backup**: move your key to another browser or laptop.
  - **Rotate key**: old keys are kept locally, so old mail stays readable.
  - **Publish this browser's key**: fixes a key mismatch.
- **Optional AI provider:** add `SECUREMAILSCOPE_AI_API_KEY` (plus optional `..._BASE_URL` and
  `..._MODEL`) to `backend/.env`. Without it, the built-in deterministic engine is used.

## 8. Troubleshooting

| Problem | Fix |
|---------|-----|
| **"Failed to fetch"** | The backend is not running. Double-click `start.bat` and refresh the page. |
| "Authentication failed" when saving/sending | You used the normal Gmail password. Use a **16-letter App Password** (section 3, Option A). |
| Inbox shows no messages / mentions OAuth | Only if the account was added *before* IMAP support: remove and re-add the mailbox with its App Password. New accounts read the inbox over IMAP automatically. |
| Encrypted mail shows as raw text / **Key mismatch** | Open it in the **same browser** where that Gmail was connected, or use **Import key backup**. To make *new* mail readable in the current browser, click **Publish this browser's key**. |
| "This mailbox is authenticated here…" when importing a key card | Contact cards cannot replace the key of a mailbox saved on this instance. Use **Publish this browser's key** instead, or remove the saved mailbox first. |
| "Access blocked" when signing in with Google | Add that Gmail as a **Test user** (section 3, Option B, step 3). |
| `redirect_uri_mismatch` | The redirect URI in Google Cloud must be exactly `http://127.0.0.1:8000/api/mailbox/oauth/gmail/callback`. Start the app with `start.bat`. |
| SMTP/TLS shows "Not observable" and risk is "unknown" | Port 25 is blocked on your network. This is an honest result, not a bug. Use a mobile hotspot to see live SMTP/TLS evidence. |
| "Port 5173 is in use" | Another copy is running. Close all SecureMailScope windows (or restart), then run `start.bat` again. |
| Deployed site can't encrypt / crypto errors | The page must be served over **HTTPS** (Web Crypto requirement). Use the Netlify/Render URLs, not a plain-HTTP host. |

## 9. Security notes

- **Never commit these** (they are in `.gitignore`):
  - `backend/.env`: the OAuth client secret;
  - `backend/data/`: mailbox credentials, OAuth tokens and the key registry;
  - `securemailscope-identity-*.json`: **private key** backups.
- Private keys live only in the browser (localStorage) and the extension's local storage. They are
  generated with Web Crypto in a secure context and never transmitted.
- Keys can only be published for mailboxes authenticated in your SecureMailScope instance.
  Contact cards hold public keys only; always verify the fingerprint out of band.
- The backend registry stores **public** keys only (`crypto_keys.db`); mailbox credentials are
  stored server-side so the backend can send over SMTP and read over IMAP.

See **`CHANGES.md`** for the full list of fixes, architecture additions and extended test scenarios,
and **`RUN-DEMO.md`** for a two-minute live demo script.
