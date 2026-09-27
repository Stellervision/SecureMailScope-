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

| Folder | What it is |
|--------|------------|
| `backend/` | FastAPI backend: DNS/SMTP/TLS analysis, EML forensics, risk/HNDL/PQC, AI explanation layer, Gmail OAuth, sending, key registry |
| `frontend/` | React + Vite dashboard (Compose, Security review, Inbox, E2E key management) |
| `extension/` | Chrome/Edge extension that decrypts SecureMailScope messages inside Gmail |
| `samples/` | Sample `.eml` for the forensics API |
| `CHANGES.md` | Detailed change log, architecture notes and extended test guide |

---

## 1. Prerequisites (install once)

| Software | Version | Notes |
|----------|---------|-------|
| **Python** | 3.11 or newer | Windows: tick **"Add python.exe to PATH"** during install |
| **Node.js** | 22 LTS (or 20.19+) | https://nodejs.org |
| **Git** | any | https://git-scm.com |
| **Google Chrome** or Edge | recent | Needed for the Gmail extension |

---

## 2. Google OAuth setup (once per team)

The dashboard signs in to Gmail with Google OAuth. **You need a Google Cloud OAuth client.** If
a teammate already has one, ask them privately for the client ID and secret, and make sure your
Gmail is added as a *Test user*. Then skip to section 3.

1. Open https://console.cloud.google.com and create a project, e.g. `SecureMailScope`.
2. **Enable the Gmail API:** go to *APIs & Services*, then *Library*, search for **Gmail API** and
   click **Enable**.
3. **Set up the OAuth consent screen** under *APIs & Services*:
   1. User type: **External**. Fill in the app name and your email.
   2. Scopes: add `openid`, `email`, `profile` and `https://mail.google.com/`.
   3. **Test users:** add **every Gmail address** that will sign in, both senders and receivers.
      While the app is in *Testing* mode, anyone not on this list gets "Access blocked".
4. **Create the OAuth client** under *APIs & Services*:
   1. Go to *Credentials*, then **Create credentials**, then **OAuth client ID**.
   2. Application type: **Web application**.
   3. **Authorized redirect URIs**, add exactly:
      ```
      http://127.0.0.1:8000/api/mailbox/oauth/gmail/callback
      ```
   4. Copy the **Client ID** and **Client secret**.

> Keep the client secret private. It goes only into `backend/.env`, which is git-ignored.

---

## 3. Get the code and run it

### Windows (recommended: one-click scripts)

1. Clone the repository:
   ```bat
   git clone https://github.com/Stellervision/SecureMailScope-.git
   cd SecureMailScope-
   ```
2. Double-click **`setup.bat`**, or run it in a terminal. It:
   - creates `backend\.venv` and installs the Python packages;
   - runs `npm install` in `frontend`;
   - creates `backend\.env` from `backend\.env.example`.
3. Open **`backend\.env`** in Notepad and fill in the two values from section 2:
   ```
   SECUREMAILSCOPE_GOOGLE_CLIENT_ID=xxxxxxxx.apps.googleusercontent.com
   SECUREMAILSCOPE_GOOGLE_CLIENT_SECRET=xxxxxxxx
   ```
4. Double-click **`start.bat`**. Two windows open: the backend on port 8000 and the frontend on
   port 5173. **Keep both open.** Your browser opens **http://localhost:5173**.

### macOS / Linux (manual)

```bash
git clone https://github.com/Stellervision/SecureMailScope-.git
cd SecureMailScope-

# Backend
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # then edit .env and add the Google client ID/secret
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# Frontend (in a second terminal)
cd frontend
npm install
npm run dev -- --host localhost --port 5173 --strictPort
```

Open **http://localhost:5173**.

> ⚠️ Do **not** change the addresses. Use `127.0.0.1:8000` for the backend and
> `localhost:5173` for the frontend: they are registered as the OAuth redirect URI and the CORS
> origins.

---

## 4. First use: connect your Gmail

The page switcher is the small bar at the bottom: **INBOX · SENT · COMPOSE · SECURITY · FORENSICS**.

1. Click **COMPOSE**.
2. In the **Mailbox** card, click **+ Add mailbox**. The *Add a sending account* panel opens.
3. Click **Continue with Google** and sign in with your Gmail.
   - If you see "Google hasn't verified this app", click **Continue**.
   - Allow the requested access.
4. The popup closes and your Gmail appears under **Saved mailboxes**. Click **Attach** on it.
5. Under **Attached mailboxes**, click **Use this account**.

Connecting creates your **encryption key pair inside this browser**. The private key never leaves
the browser; only the public key is registered with the backend.

6. Click **INBOX**. The **END-TO-END IDENTITY** card must say **Keys match**.

---

## 5. Send an encrypted email to a teammate (two laptops)

Each laptop runs its own SecureMailScope, so the sender first needs the recipient's **public key
card**. The card contains no private key, so it is safe to send over WhatsApp or email.

**Recipient's laptop**

1. Complete section 4 with the recipient's Gmail.
2. Go to **INBOX**, find the END-TO-END IDENTITY card, and click **Share my public key card**.
   A `securemailscope-public-key-<email>.json` file downloads.
3. Send that file to the sender, and read the **fingerprint** shown on screen to them over a call.

**Sender's laptop**

4. Complete section 4 with the sender's Gmail.
5. Go to **INBOX** and click **Import contact's key card**. Choose the recipient's file.
6. Check that the fingerprint in the success message **exactly matches** the one the recipient
   read out.
7. On **COMPOSE**:
   1. Type the recipient's email and click **Check recipient security**.
   2. Wait until the right panel shows **Recipient key: Available**.
   3. Write a subject and message, and add attachments if you like.
   4. Click **Confirm & Send**.
8. You should see **"Encrypted SecureMailScope message submitted successfully"**.

**Recipient's laptop, to read it**

9. Go to **INBOX** and click **Refresh**. Open the mail marked **E2E encrypted**. It decrypts
   locally and shows the original message.

> Same laptop, two Gmail accounts: connect both accounts in the same browser and skip the key
> card. The recipient's key is already registered there.

---

## 6. Decrypt directly inside Gmail (browser extension)

Plain Gmail shows only the encrypted block. That is intended: it proves only ciphertext travelled.

1. Open `chrome://extensions` (or `edge://extensions`) and turn on **Developer mode**.
2. Click **Load unpacked** and select the **`extension`** folder of this repo.
3. Open or reload **http://localhost:5173** once, in the same browser where you connected your
   Gmail. The extension copies your keys locally, and the INBOX card shows
   **Gmail browser extension: Connected**.
4. Open the encrypted mail in Gmail. A green **"Decrypted locally by SecureMailScope"** panel shows
   the message and any attachments.

---

## 7. Other features to try

- **Recipient security posture:** on COMPOSE, enter any address and click **Check recipient
  security**. You get:
  - MX hosts, MTA-STS mode, STARTTLS/TLS and certificate details;
  - risk score, PQC readiness, recommendations and an AI explanation.
- **EML forensics:** open http://127.0.0.1:8000/docs, then use **POST /api/eml/analyze** to upload
  any `.eml` file (e.g. `samples/test_email.eml`, or Gmail's *Show original → Download original*).
  It returns hop reconstruction, SPF/DKIM/DMARC, findings, risk and HNDL.
- **Key management** (INBOX, END-TO-END IDENTITY card):
  - **Export/Import key backup**: move your key to another browser or laptop.
  - **Rotate key**: old keys are kept locally, so old mail stays readable.
  - **Publish this browser's key**: fixes a key mismatch.
- **Optional AI provider:** add `SECUREMAILSCOPE_AI_API_KEY` (plus optional `..._BASE_URL` and
  `..._MODEL`) to `backend/.env`. Without it, the built-in deterministic engine is used.

---

## 8. Troubleshooting

| Problem | Fix |
|---------|-----|
| "Access blocked" when signing in with Google | Add that Gmail as a **Test user** (section 2, step 3). |
| `redirect_uri_mismatch` | The redirect URI in Google Cloud must be exactly `http://127.0.0.1:8000/api/mailbox/oauth/gmail/callback`. Start the app with `start.bat`. |
| "OAuth is not configured" | `backend/.env` is missing the client ID or secret. Restart after editing it. |
| `WinError 10060` / send timeout | Your network blocks SMTP ports. Gmail accounts automatically send over HTTPS (Gmail API); make sure the **Gmail API is enabled** (section 2, step 2). |
| SMTP/TLS shows "Not observable" and risk is "unknown" | Port 25 is blocked on your network. This is an honest result, not a bug. Use a mobile hotspot to see live SMTP/TLS evidence. |
| Encrypted mail shows as raw text / **Key mismatch** | Open it in the **same browser** where that Gmail was connected, or use **Import key backup**. Don't click *Publish this browser's key* unless you intend to replace the registered key. |
| "Port 5173 is in use" | Another copy is running. Close all SecureMailScope windows (or restart), then run `start.bat` again. |
| `setup.bat`: Python/Node not found | Reinstall with *Add to PATH* ticked, then open a new terminal. |
| Old version still showing after an update | Close every SecureMailScope window, run `start.bat`, then press **Ctrl + Shift + R** in the browser. |

---

## 9. Security notes

- **Never commit these** (they are in `.gitignore`):
  - `backend/.env`: the OAuth client secret;
  - `backend/data/`: Gmail OAuth tokens and the key registry;
  - `securemailscope-identity-*.json`: **private key** backups.
- Private keys live only in the browser (localStorage) and the extension's local storage.
- Keys can only be published for mailboxes authenticated in your SecureMailScope instance.
  Contact cards hold public keys only; always verify the fingerprint out of band.

See **`CHANGES.md`** for the full list of fixes, architecture additions and extended test scenarios.
