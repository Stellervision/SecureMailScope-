import { API_BASE } from "./config";

export const ENVELOPE_PROTOCOL =
  "SecureMailScope-E2E";

const ARMOR_BEGIN =
  "-----BEGIN SECUREMAILSCOPE E2E MESSAGE-----";

const ARMOR_END =
  "-----END SECUREMAILSCOPE E2E MESSAGE-----";

const BACKUP_FORMAT =
  "securemailscope-identity-backup";

// Storage format is unchanged from the original implementation so
// identities already stored in a browser keep working.
const CRYPTO_STORAGE_PREFIX =
  "securemailscope_e2e_identity_v1:";

const LEGACY_CRYPTO_STORAGE_KEY =
  "securemailscope_e2e_identity_v1";

const RSA_ALGORITHM = {
  name: "RSA-OAEP",
  modulusLength: 2048,
  publicExponent: new Uint8Array([
    1,
    0,
    1,
  ]),
  hash: "SHA-256",
};

const AES_ALGORITHM = {
  name: "AES-GCM",
  length: 256,
};

function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function getIdentityStorageKey(email) {
  const normalizedEmail =
    normalizeEmail(email);

  if (!normalizedEmail) {
    throw new Error(
      "A valid email address is required for identity storage."
    );
  }

  return `${CRYPTO_STORAGE_PREFIX}${normalizedEmail}`;
}

function bytesToBase64Url(bytes) {
  let binary = "";

  // Chunked: per-byte concatenation is very slow for multi-MB
  // attachments.
  for (
    let index = 0;
    index < bytes.length;
    index += 0x8000
  ) {
    binary += String.fromCharCode.apply(
      null,
      bytes.subarray(
        index,
        index + 0x8000
      )
    );
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padding =
    "=".repeat(
      (4 - (normalized.length % 4)) % 4
    );

  const binary = atob(
    normalized + padding
  );

  return Uint8Array.from(
    binary,
    (character) =>
      character.charCodeAt(0)
  );
}

function textToBytes(value) {
  return new TextEncoder().encode(
    value
  );
}

function bytesToText(bytes) {
  return new TextDecoder().decode(
    bytes
  );
}

async function exportPublicKey(
  publicKey
) {
  return window.crypto.subtle.exportKey(
    "jwk",
    publicKey
  );
}

async function exportPrivateKey(
  privateKey
) {
  return window.crypto.subtle.exportKey(
    "jwk",
    privateKey
  );
}

async function importPublicKey(
  publicJwk
) {
  return window.crypto.subtle.importKey(
    "jwk",
    publicJwk,
    RSA_ALGORITHM,
    true,
    ["encrypt"]
  );
}

async function importPrivateKey(
  privateJwk
) {
  return window.crypto.subtle.importKey(
    "jwk",
    privateJwk,
    RSA_ALGORITHM,
    true,
    ["decrypt"]
  );
}

function normalizePublicKeyJwk(
  publicKey
) {
  return {
    kty: "RSA",
    n: publicKey.n,
    e: publicKey.e,
    alg: "RSA-OAEP-256",
    use: "enc",
  };
}

function stableStringify(value) {
  if (
    value === null ||
    typeof value !== "object"
  ) {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value
      .map((item) =>
        stableStringify(item)
      )
      .join(",")}]`;
  }

  return `{${Object.keys(value)
    .sort()
    .map(
      (key) =>
        `${JSON.stringify(
          key
        )}:${stableStringify(
          value[key]
        )}`
    )
    .join(",")}}`;
}

async function calculateKeyId(
  publicKey
) {
  const normalized =
    normalizePublicKeyJwk(
      publicKey
    );

  const canonical =
    stableStringify(normalized);

  const digest =
    await window.crypto.subtle.digest(
      "SHA-256",
      textToBytes(canonical)
    );

  const digestBytes =
    new Uint8Array(digest);

  const hex = Array.from(
    digestBytes,
    (byte) =>
      byte
        .toString(16)
        .padStart(2, "0")
  ).join("");

  return `smsk-${hex.slice(0, 24)}`;
}

async function generateIdentity() {
  const keyPair =
    await window.crypto.subtle.generateKey(
      RSA_ALGORITHM,
      true,
      ["encrypt", "decrypt"]
    );

  const publicKey =
    await exportPublicKey(
      keyPair.publicKey
    );

  const privateKey =
    await exportPrivateKey(
      keyPair.privateKey
    );

  return {
    version: 1,
    algorithm: "RSA-OAEP-256",
    publicKey:
      normalizePublicKeyJwk(
        publicKey
      ),
    privateKey,
    createdAt:
      new Date().toISOString(),
  };
}

function readStoredIdentity(
  storageKey
) {
  const stored =
    localStorage.getItem(
      storageKey
    );

  if (!stored) {
    return null;
  }

  try {
    return JSON.parse(stored);
  } catch {
    localStorage.removeItem(
      storageKey
    );

    return null;
  }
}

function storeIdentity(
  email,
  identity
) {
  localStorage.setItem(
    getIdentityStorageKey(email),
    JSON.stringify(identity)
  );
}

export async function createIdentity(
  email
) {
  const normalizedEmail =
    normalizeEmail(email);

  if (!normalizedEmail) {
    throw new Error(
      "A valid email address is required to create an encryption identity."
    );
  }

  const existing =
    getStoredIdentity(
      normalizedEmail
    );

  if (existing) {
    return existing;
  }

  const identity =
    await generateIdentity();

  storeIdentity(
    normalizedEmail,
    identity
  );

  return identity;
}

export function getStoredIdentity(
  email
) {
  const normalizedEmail =
    normalizeEmail(email);

  if (!normalizedEmail) {
    return null;
  }

  return readStoredIdentity(
    getIdentityStorageKey(
      normalizedEmail
    )
  );
}

async function getLegacyIdentityForEmail(
  email
) {
  const legacyIdentity =
    readStoredIdentity(
      LEGACY_CRYPTO_STORAGE_KEY
    );

  if (!legacyIdentity?.publicKey) {
    return null;
  }

  const normalizedEmail =
    normalizeEmail(email);

  if (!normalizedEmail) {
    return null;
  }

  try {
    const localKeyId =
      await calculateKeyId(
        legacyIdentity.publicKey
      );

    const response =
      await fetch(
        `${API_BASE}/api/crypto/keys?email=${encodeURIComponent(
          normalizedEmail
        )}`
      );

    if (response.status === 404) {
      return null;
    }

    if (!response.ok) {
      return null;
    }

    const data =
      await response.json();

    if (
      data?.key?.key_id ===
      localKeyId
    ) {
      return legacyIdentity;
    }
  } catch {
    return null;
  }

  return null;
}

async function migrateLegacyIdentityIfOwned(
  email
) {
  const normalizedEmail =
    normalizeEmail(email);

  const existing =
    getStoredIdentity(
      normalizedEmail
    );

  if (existing) {
    return existing;
  }

  const legacyIdentity =
    await getLegacyIdentityForEmail(
      normalizedEmail
    );

  if (!legacyIdentity) {
    return null;
  }

  storeIdentity(
    normalizedEmail,
    legacyIdentity
  );

  return legacyIdentity;
}

export async function registerIdentity(
  email
) {
  const normalizedEmail =
    normalizeEmail(email);

  if (!normalizedEmail) {
    throw new Error(
      "A valid email address is required to register the encryption identity."
    );
  }

  let identity =
    await migrateLegacyIdentityIfOwned(
      normalizedEmail
    );

  if (!identity) {
    identity =
      await createIdentity(
        normalizedEmail
      );
  }

  const response =
    await fetch(
      `${API_BASE}/api/crypto/keys/register`,
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json",
        },
        body: JSON.stringify({
          email:
            normalizedEmail,
          public_key: {
            ...identity.publicKey,
            alg: "RSA-OAEP-256",
            use: "enc",
          },
        }),
      }
    );

  const data =
    await response
      .json()
      .catch(() => ({}));

  const localKeyId =
    await calculateKeyId(
      identity.publicKey
    );

  // 409 = the registry already holds a DIFFERENT key for this mailbox
  // (new browser, cleared storage, ...). Senders would keep
  // encrypting to that stale key and this browser could never
  // decrypt, so the conflict is surfaced instead of being swallowed.
  if (response.status === 409) {
    notifyExtension();

    return {
      status: "conflict",
      email: normalizedEmail,
      localKeyId,
      registeredKeyId:
        data?.detail?.existing_key
          ?.key_id || null,
      message: detailMessage(
        data,
        "A different encryption key is registered for this mailbox."
      ),
    };
  }

  if (!response.ok) {
    throw new Error(
      detailMessage(
        data,
        "Unable to register the encryption key."
      )
    );
  }

  notifyExtension();

  return {
    ...data,
    localKeyId,
  };
}

function detailMessage(
  data,
  fallback
) {
  const detail = data?.detail;

  if (typeof detail === "string") {
    return detail;
  }

  if (detail?.message) {
    return detail.message;
  }

  return data?.message || fallback;
}

/* -------------------------------------------------------------------------- */
/* Browser extension bridge                                                   */
/* -------------------------------------------------------------------------- */

// The SecureMailScope browser extension listens for this message on the
// app origin and copies the local identities into extension storage so
// it can decrypt envelopes directly inside Gmail. Keys never leave the
// device.
export function notifyExtension() {
  try {
    window.postMessage(
      {
        type: "securemailscope-identities-updated",
      },
      window.location.origin
    );
  } catch {
    // Extension is optional.
  }
}

/* -------------------------------------------------------------------------- */
/* Key management                                                             */
/* -------------------------------------------------------------------------- */

export async function getLocalKeyId(
  email
) {
  const identity =
    getStoredIdentity(email);

  if (!identity?.publicKey) {
    return null;
  }

  return calculateKeyId(
    identity.publicKey
  );
}

export async function getIdentityStatus(
  email
) {
  const normalizedEmail =
    normalizeEmail(email);

  const identity =
    getStoredIdentity(
      normalizedEmail
    );

  const localKeyId =
    identity?.publicKey
      ? await calculateKeyId(
          identity.publicKey
        )
      : null;

  const previousKeyIds = [];

  for (const previous of identity?.previousKeys ||
    []) {
    if (previous?.publicKey) {
      previousKeyIds.push(
        await calculateKeyId(
          previous.publicKey
        )
      );
    }
  }

  const registeredKey =
    await getRecipientPublicKey(
      normalizedEmail
    ).catch(() => null);

  const registeredKeyId =
    registeredKey?.key_id || null;

  return {
    email: normalizedEmail,
    hasLocalKey: Boolean(
      identity?.privateKey
    ),
    localKeyId,
    previousKeyIds,
    registeredKeyId,
    registeredFingerprint:
      registeredKey?.fingerprint ||
      null,
    match:
      Boolean(localKeyId) &&
      localKeyId ===
        registeredKeyId,
  };
}

async function publishPublicKey(
  email,
  publicKey
) {
  const response =
    await fetch(
      `${API_BASE}/api/crypto/keys/rotate`,
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json",
        },
        body: JSON.stringify({
          email,
          public_key: {
            ...publicKey,
            alg: "RSA-OAEP-256",
            use: "enc",
          },
        }),
      }
    );

  const data =
    await response
      .json()
      .catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      detailMessage(
        data,
        "Unable to publish the encryption key."
      )
    );
  }

  notifyExtension();

  return data;
}

// Fixes a local/registry mismatch by publishing the key this browser
// actually holds. New messages become decryptable here.
export async function publishLocalIdentity(
  email
) {
  const normalizedEmail =
    normalizeEmail(email);

  const identity =
    getStoredIdentity(
      normalizedEmail
    ) ||
    (await createIdentity(
      normalizedEmail
    ));

  return publishPublicKey(
    normalizedEmail,
    identity.publicKey
  );
}

// Generates a fresh key pair. The previous key pair is kept in the
// local keyring so older messages stay readable.
export async function rotateIdentity(
  email
) {
  const normalizedEmail =
    normalizeEmail(email);

  const current =
    getStoredIdentity(
      normalizedEmail
    );

  const next =
    await generateIdentity();

  if (current?.privateKey) {
    next.previousKeys = [
      {
        publicKey:
          current.publicKey,
        privateKey:
          current.privateKey,
        createdAt:
          current.createdAt,
        retiredAt:
          new Date().toISOString(),
      },
      ...(current.previousKeys ||
        []),
    ];
  }

  const result =
    await publishPublicKey(
      normalizedEmail,
      next.publicKey
    );

  storeIdentity(
    normalizedEmail,
    next
  );

  notifyExtension();

  return result;
}

export function exportIdentityBackup(
  email
) {
  const normalizedEmail =
    normalizeEmail(email);

  const identity =
    getStoredIdentity(
      normalizedEmail
    );

  if (!identity?.privateKey) {
    throw new Error(
      "No local SecureMailScope identity exists for this mailbox."
    );
  }

  return {
    format: BACKUP_FORMAT,
    version: 1,
    email: normalizedEmail,
    exported_at:
      new Date().toISOString(),
    identity,
  };
}

function sameKey(a, b) {
  return (
    Boolean(a?.n) &&
    a?.n === b?.n &&
    a?.e === b?.e
  );
}

export function importIdentityBackup(
  backup
) {
  if (
    backup?.format !==
      BACKUP_FORMAT ||
    !backup?.identity
      ?.privateKey ||
    !backup?.identity
      ?.publicKey
  ) {
    throw new Error(
      "This file is not a SecureMailScope identity backup."
    );
  }

  const normalizedEmail =
    normalizeEmail(
      backup.email
    );

  if (!normalizedEmail) {
    throw new Error(
      "The identity backup does not contain an email address."
    );
  }

  const imported =
    backup.identity;

  const current =
    getStoredIdentity(
      normalizedEmail
    );

  const keyring = [
    ...(imported.previousKeys ||
      []),
  ];

  // Keep whatever this browser had so nothing becomes unreadable.
  if (
    current?.privateKey &&
    !sameKey(
      current.publicKey,
      imported.publicKey
    )
  ) {
    keyring.unshift({
      publicKey:
        current.publicKey,
      privateKey:
        current.privateKey,
      createdAt:
        current.createdAt,
      retiredAt:
        new Date().toISOString(),
    });
  }

  for (const previous of current?.previousKeys ||
    []) {
    keyring.push(previous);
  }

  const uniqueKeyring =
    keyring.filter(
      (entry, index) =>
        entry?.publicKey &&
        !sameKey(
          entry.publicKey,
          imported.publicKey
        ) &&
        keyring.findIndex(
          (other) =>
            sameKey(
              other?.publicKey,
              entry.publicKey
            )
        ) === index
    );

  storeIdentity(
    normalizedEmail,
    {
      ...imported,
      previousKeys:
        uniqueKeyring,
    }
  );

  notifyExtension();

  return normalizedEmail;
}

/* -------------------------------------------------------------------------- */
/* Public key cards (cross-device key exchange)                               */
/* -------------------------------------------------------------------------- */

const CONTACT_CARD_FORMAT =
  "securemailscope-public-key-card";

// Public key only: safe to share over any channel. The recipient's
// fingerprint should be compared out of band before relying on it.
export async function exportPublicKeyCard(
  email
) {
  const normalizedEmail =
    normalizeEmail(email);

  const registered =
    await getRecipientPublicKey(
      normalizedEmail
    );

  if (!registered?.public_key) {
    throw new Error(
      "No registered public key exists for this mailbox yet."
    );
  }

  return {
    format: CONTACT_CARD_FORMAT,
    version: 1,
    email: normalizedEmail,
    key_id: registered.key_id,
    fingerprint:
      registered.fingerprint,
    public_key:
      registered.public_key,
    exported_at:
      new Date().toISOString(),
  };
}

export async function importPublicKeyCard(
  card,
  { replace = false } = {}
) {
  if (
    card?.format !==
      CONTACT_CARD_FORMAT ||
    !card?.public_key?.n
  ) {
    throw new Error(
      "This file is not a SecureMailScope public key card."
    );
  }

  if (card.private_key || card.identity) {
    throw new Error(
      "Public key cards must not contain private keys."
    );
  }

  const response =
    await fetch(
      `${API_BASE}/api/crypto/keys/import-contact`,
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json",
        },
        body: JSON.stringify({
          email: card.email,
          public_key:
            card.public_key,
          replace,
        }),
      }
    );

  const data =
    await response
      .json()
      .catch(() => ({}));

  if (response.status === 409) {
    const error = new Error(
      detailMessage(
        data,
        "A different key is already stored for this recipient."
      )
    );

    error.code = "CONTACT_CONFLICT";

    throw error;
  }

  if (!response.ok) {
    throw new Error(
      detailMessage(
        data,
        "Unable to import the public key card."
      )
    );
  }

  return data;
}

/* -------------------------------------------------------------------------- */
/* Envelope transport format                                                  */
/* -------------------------------------------------------------------------- */

// The envelope travels as the plain-text email body. A short
// human-readable header is added so a recipient without SecureMailScope
// understands what they are looking at instead of seeing raw JSON.
export function formatEnvelopeForEmail(
  envelope
) {
  return [
    ARMOR_BEGIN,
    "This message is end-to-end encrypted with SecureMailScope",
    `(${envelope.content_encryption} + ${envelope.key_encryption}).`,
    "Open it with the SecureMailScope app or the SecureMailScope",
    "browser extension for Gmail to decrypt it locally.",
    "",
    JSON.stringify(envelope),
    ARMOR_END,
  ].join("\n");
}

// Accepts both the original raw-JSON body and the armored body.
// Mail clients may re-wrap or pad the text, so the envelope object is
// located by its protocol marker rather than by parsing the whole body.
export function extractEnvelope(
  text
) {
  if (typeof text !== "string") {
    return null;
  }

  const cleaned = text.replace(
    /[\u200B-\u200D\uFEFF\u00AD]/g,
    ""
  );

  if (
    !cleaned.includes(
      ENVELOPE_PROTOCOL
    )
  ) {
    return null;
  }

  const candidates = [];

  const trimmed = cleaned.trim();

  if (trimmed.startsWith("{")) {
    candidates.push(trimmed);
  }

  const pattern =
    /\{[^{}]*"protocol"\s*:\s*"SecureMailScope-E2E"[^{}]*\}/g;

  candidates.push(
    ...(cleaned.match(pattern) || [])
  );

  // Fallback for bodies that still carry mail-encoding artefacts
  // (quoted-printable soft breaks, "=3D", hard-wrapped lines).
  const unwrapped = cleaned
    .replace(/=\r?\n/g, "")
    .replace(/=3D/gi, "=")
    .replace(/\r?\n/g, "");

  candidates.push(
    ...(unwrapped.match(pattern) || [])
  );

  for (const candidate of candidates) {
    try {
      const parsed =
        JSON.parse(candidate);

      if (
        parsed?.protocol ===
        ENVELOPE_PROTOCOL
      ) {
        for (const field of [
          "nonce",
          "wrapped_key",
          "ciphertext",
        ]) {
          if (
            typeof parsed[field] ===
            "string"
          ) {
            parsed[field] =
              parsed[field].replace(
                /\s+/g,
                ""
              );
          }
        }

        return parsed;
      }
    } catch {
      // Try the next candidate.
    }
  }

  return null;
}

export async function assessRecipient(
  email
) {
  const response =
    await fetch(
      `${API_BASE}/api/crypto/assess-recipient`,
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json",
        },
        body: JSON.stringify({
          email:
            normalizeEmail(email),
        }),
      }
    );

  const data =
    await response.json();

  if (!response.ok) {
    throw new Error(
      data?.detail ||
        "Unable to assess recipient encryption support."
    );
  }

  return data;
}

export async function getRecipientPublicKey(
  email
) {
  const response =
    await fetch(
      `${API_BASE}/api/crypto/keys?email=${encodeURIComponent(
        normalizeEmail(email)
      )}`
    );

  if (response.status === 404) {
    return null;
  }

  const data =
    await response.json();

  if (!response.ok) {
    throw new Error(
      data?.detail ||
        "Unable to retrieve recipient encryption key."
    );
  }

  return data.key;
}

async function readAttachment(
  file
) {
  const arrayBuffer =
    await file.arrayBuffer();

  return {
    filename: file.name,
    content_type:
      file.type ||
      "application/octet-stream",
    size: file.size,
    content:
      bytesToBase64Url(
        new Uint8Array(
          arrayBuffer
        )
      ),
  };
}

function createAdditionalData({
  recipientEmail,
  recipientKeyId,
}) {
  return textToBytes(
    JSON.stringify({
      protocol:
        "SecureMailScope-E2E",
      version: 1,
      recipient:
        recipientEmail,
      recipient_key_id:
        recipientKeyId,
    })
  );
}

export async function encryptMessage({
  recipientEmail,
  subject,
  body,
  attachments = [],
  recipientKey,
}) {
  if (
    !recipientEmail?.trim()
  ) {
    throw new Error(
      "A recipient email address is required."
    );
  }

  if (!recipientKey?.public_key) {
    throw new Error(
      "A compatible recipient encryption key is required."
    );
  }

  if (!recipientKey.key_id) {
    throw new Error(
      "The recipient encryption key is missing its key identifier."
    );
  }

  const recipientPublicKey =
    await importPublicKey(
      recipientKey.public_key
    );

  const messageKey =
    await window.crypto.subtle.generateKey(
      AES_ALGORITHM,
      true,
      ["encrypt", "decrypt"]
    );

  const nonce =
    window.crypto.getRandomValues(
      new Uint8Array(12)
    );

  const encryptedAttachments =
    [];

  for (
    const attachment of attachments
  ) {
    encryptedAttachments.push(
      await readAttachment(
        attachment
      )
    );
  }

  const normalizedRecipient =
    normalizeEmail(
      recipientEmail
    );

  const payload = {
    version: 1,
    recipient:
      normalizedRecipient,
    subject,
    body,
    attachments:
      encryptedAttachments,
    created_at:
      new Date().toISOString(),
  };

  const plaintext =
    textToBytes(
      JSON.stringify(payload)
    );

  const additionalData =
    createAdditionalData({
      recipientEmail:
        normalizedRecipient,
      recipientKeyId:
        recipientKey.key_id,
    });

  const ciphertext =
    await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData,
        tagLength: 128,
      },
      messageKey,
      plaintext
    );

  const rawMessageKey =
    await window.crypto.subtle.exportKey(
      "raw",
      messageKey
    );

  const wrappedKey =
    await window.crypto.subtle.encrypt(
      {
        name: "RSA-OAEP",
      },
      recipientPublicKey,
      rawMessageKey
    );

  return {
    protocol:
      "SecureMailScope-E2E",
    version: 1,
    content_encryption:
      "AES-256-GCM",
    key_encryption:
      "RSA-OAEP-256",
    recipient:
      normalizedRecipient,
    recipient_key_id:
      recipientKey.key_id,
    recipient_key_fingerprint:
      recipientKey.fingerprint ||
      null,
    nonce:
      bytesToBase64Url(
        nonce
      ),
    wrapped_key:
      bytesToBase64Url(
        new Uint8Array(
          wrappedKey
        )
      ),
    ciphertext:
      bytesToBase64Url(
        new Uint8Array(
          ciphertext
        )
      ),
    created_at:
      new Date().toISOString(),
  };
}

export async function decryptMessage(
  envelope,
  recipientEmail
) {
  if (
    envelope?.protocol !==
    "SecureMailScope-E2E"
  ) {
    throw new Error(
      "Unsupported encrypted message format."
    );
  }

  if (
    envelope.version !== 1
  ) {
    throw new Error(
      "Unsupported SecureMailScope E2E protocol version."
    );
  }

  if (
    envelope.content_encryption !==
    "AES-256-GCM"
  ) {
    throw new Error(
      "Unsupported content encryption algorithm."
    );
  }

  if (
    envelope.key_encryption !==
    "RSA-OAEP-256"
  ) {
    throw new Error(
      "Unsupported key encryption algorithm."
    );
  }

  const normalizedRecipient =
    normalizeEmail(
      recipientEmail ||
        envelope.recipient
    );

  const identity =
    getStoredIdentity(
      normalizedRecipient
    );

  if (
    !identity?.privateKey
  ) {
    throw decryptionError(
      "NO_LOCAL_KEY",
      `This browser has no SecureMailScope private key for ${normalizedRecipient}. Connect that mailbox here once, or import its identity backup.`
    );
  }

  const selected =
    await selectDecryptionKey(
      identity,
      envelope.recipient_key_id
    );

  if (!selected) {
    const localKeyId =
      await calculateKeyId(
        identity.publicKey
      );

    throw decryptionError(
      "KEY_MISMATCH",
      `This message was encrypted to key ${envelope.recipient_key_id}, but this browser holds key ${localKeyId}. Import the identity backup that contains ${envelope.recipient_key_id}. To make future messages readable here, use "Publish this browser's key".`
    );
  }

  const privateKey =
    await importPrivateKey(
      selected.privateKey
    );

  const wrappedKey =
    base64UrlToBytes(
      envelope.wrapped_key
    );

  let rawMessageKey;

  try {
    rawMessageKey =
      await window.crypto.subtle.decrypt(
        {
          name: "RSA-OAEP",
        },
        privateKey,
        wrappedKey
      );
  } catch {
    throw decryptionError(
      "UNWRAP_FAILED",
      "The message key could not be unwrapped with the local private key. The envelope may be corrupted or encrypted to a different key."
    );
  }

  const messageKey =
    await window.crypto.subtle.importKey(
      "raw",
      rawMessageKey,
      AES_ALGORITHM,
      false,
      ["decrypt"]
    );

  const ciphertext =
    base64UrlToBytes(
      envelope.ciphertext
    );

  const nonce =
    base64UrlToBytes(
      envelope.nonce
    );

  const additionalData =
    createAdditionalData({
      recipientEmail:
        envelope.recipient,
      recipientKeyId:
        envelope.recipient_key_id,
    });

  let plaintext;

  try {
    plaintext =
      await window.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: nonce,
          additionalData,
          tagLength: 128,
        },
        messageKey,
        ciphertext
      );
  } catch {
    throw decryptionError(
      "INTEGRITY_FAILED",
      "AES-GCM authentication failed. The encrypted message was modified in transit or is incomplete."
    );
  }

  return {
    ...JSON.parse(
      bytesToText(
        new Uint8Array(
          plaintext
        )
      )
    ),
    decrypted_with_key_id:
      selected.keyId,
  };
}

function decryptionError(
  code,
  message
) {
  const error =
    new Error(message);

  error.code = code;

  return error;
}

// Picks the current key or a retired key from the local keyring whose
// key ID matches the envelope.
async function selectDecryptionKey(
  identity,
  recipientKeyId
) {
  const candidates = [
    identity,
    ...(identity.previousKeys ||
      []),
  ];

  for (const candidate of candidates) {
    if (
      !candidate?.publicKey ||
      !candidate?.privateKey
    ) {
      continue;
    }

    const keyId =
      await calculateKeyId(
        candidate.publicKey
      );

    if (
      !recipientKeyId ||
      keyId === recipientKeyId
    ) {
      return {
        keyId,
        privateKey:
          candidate.privateKey,
      };
    }
  }

  return null;
}

export function clearIdentity(
  email
) {
  const normalizedEmail =
    normalizeEmail(email);

  if (!normalizedEmail) {
    return;
  }

  localStorage.removeItem(
    getIdentityStorageKey(
      normalizedEmail
    )
  );
}