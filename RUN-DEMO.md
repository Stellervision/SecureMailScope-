# SecureMailScope — Hackathon demo run guide

## What was broken and fixed (2026-09-28)

**Bug:** you could not add any Gmail mailbox. The backend rejected
`smtp.gmail.com` with "Gmail accounts should be connected through the
provider OAuth flow", and the OAuth flow was not configured (empty
client ID/secret in `backend/.env`). With no mailbox saved, nothing
could be attached, connected, or sent — which is why sending always
failed.

**Fix (in `backend/app/services/email_sender.py`):**

1. `add_mailbox` now accepts Gmail / Microsoft / any SMTP host with a
   credential (App Password). It no longer forces the OAuth route.
2. When saving a Gmail mailbox the response tells you an App Password
   is required.
3. If Gmail rejects the password at send time, the error now explains
   exactly how to create an App Password instead of a generic message.

Both the sender path and the receiver key-registration path
(`_require_owned_mailbox` requires the recipient's mailbox to be saved
in this backend) were blocked by the same bug, so this one fix unlocks
the full E2E flow. Verified end-to-end on this machine: register key →
encrypt in the browser format → send through the real `/api/send/email`
endpoint → decrypt with the recipient private key → original message
recovered.

---

## One-time setup (do this the night before)

### 1. Gmail App Passwords (sender account AND receiver account)

Google does not accept ordinary passwords for SMTP. For each Gmail
account you will use:

1. Go to https://myaccount.google.com/security
2. Enable **2-Step Verification** (required for App Passwords).
3. Go to Security → **App passwords** (search "App passwords" in the
   account search bar if you cannot find it).
4. Create one, name it `SecureMailScope`, copy the 16-character code.

### 2. Start the two servers

```bat
:: Terminal 1 — backend (already running if you kept this session's server)
cd C:\Users\SHAYAN\OneDrive\Desktop\mailscope\SecureMailScope-\backend
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000

:: Terminal 2 — frontend
cd C:\Users\SHAYAN\OneDrive\Desktop\mailscope\SecureMailScope-\frontend
npm run dev
```

Open http://localhost:5173

### 3. Add and connect the SENDER mailbox (in the app)

Compose page → MAILBOX → **+ Add mailbox**:

| Field | Value |
|---|---|
| Email address | your sender Gmail, e.g. `sender.demo@gmail.com` |
| SMTP username | same Gmail address |
| Server credential | the **App Password** from step 1 |
| SMTP host | `smtp.gmail.com` |
| SMTP port | `587` |
| Security | `STARTTLS` |
| Provider label | leave empty |

Save → **Attach saved mailbox** → select it → Attach → **Use this
account** (button changes to "Connected").

### 4. Add the RECEIVER mailbox (same app, same backend)

Repeat step 3 with the receiver's Gmail address and **its** App
Password. You do **not** need to attach/connect the receiver mailbox —
it only needs to be saved so the receiver may publish their encryption
key.

### 5. Receiver creates their encryption identity

Still at http://localhost:5173, open the **End-to-end identity**
panel (workspace nav), enter the **receiver's** Gmail address, and
create/register the identity. This:

- generates the receiver's RSA key pair **in this browser**
  (private key never leaves it), and
- publishes the public key to the backend registry so senders can
  encrypt to it.

### 6. Receiver loads the Gmail extension (for the "decrypt inside
Gmail" moment)

1. Chrome → `chrome://extensions` → enable **Developer mode**.
2. **Load unpacked** → select `SecureMailScope-\extension`.
3. With the app tab open (step 5 browser), the extension copies the
   receiver identity into extension storage automatically (app-bridge).
   You can check via the extension popup.

---

## The demo (2 minutes on stage)

1. **Compose** in the app: recipient = receiver's Gmail, subject +
   message. Click **Check recipient security** (live domain
   assessment — talk about this), then send from the security review
   panel.
2. The app encrypts locally with the receiver's public key
   (AES-256-GCM content + RSA-OAEP-256 key wrapping) and the backend
   submits via `smtp.gmail.com:587` STARTTLS. The receiver sees only
   the armored `-----BEGIN SECUREMAILSCOPE E2E MESSAGE-----` block.
3. **Open Gmail** (receiver account, same browser as steps 5–6). The
   message body shows the ciphertext; the SecureMailScope panel
   renders **"Decrypted locally by SecureMailScope"** with the
   original subject/body. Nothing left the browser to do that.
4. Backup path (no extension): receiver opens the web app → Inbox →
   the same envelope is decrypted in the app with the local key.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `535 Bad credentials` when sending | Ordinary Gmail password used. Repeat setup step 1 and save the **App Password** as the credential. |
| "No sending mailbox has been selected" | Attach + connect a mailbox on the Compose page (steps 3). |
| "Encryption keys can only be published for a mailbox that is authenticated" | Save the receiver's mailbox first (step 4), then create the identity (step 5). |
| Gmail shows "[Message clipped]" and the extension can't parse | Click **View entire message** in Gmail, then Retry. |
| Envelope error "KEY_MISMATCH" / "NO_LOCAL_KEY" | The browser doing the decrypting has no receiver private key. Either open the app in that browser once (step 5), or export the identity backup from the app and import it in the extension popup. |
| Send times out (WinError 10060) | The demo network blocks outbound SMTP 587. Use a phone hotspot, or connect a Gmail account via OAuth over HTTPS. |
| Extension popup empty after reloading the extension | Refresh both the app tab and Gmail once so the bridge re-syncs identities. |

## Notes for judges (if asked)

- Private keys are generated and stored only in the recipient's
  browser (localStorage / extension storage). The backend stores
  public keys and fingerprints only, and can never decrypt.
- Envelope integrity: AES-GCM AAD binds
  `protocol + version + recipient + recipient_key_id`, so envelopes
  cannot be re-addressed to another recipient without detection.
- Key authentication: key IDs are `smsk-<24 hex>` SHA-256 of the
  canonical RSA JWK; the UI shows the full 16-group fingerprint for
  out-of-band comparison.
- Google/Microsoft OAuth sign-in is also implemented; it only needs
  `SECUREMAILSCOPE_GOOGLE_CLIENT_ID` / `_SECRET` in
  `backend/.env` (empty by default, hence the App Password route).
