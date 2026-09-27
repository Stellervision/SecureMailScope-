// SecureMailScope E2E core (extension copy).
//
// Mirrors frontend/src/services/crypto.js so envelopes created by the
// web app can be decrypted inside Gmail:
//   AES-256-GCM content encryption + RSA-OAEP-256 key wrapping,
//   AAD = {"protocol","version","recipient","recipient_key_id"}.

/* exported SecureMailScopeE2E */
const SecureMailScopeE2E = (() => {
  const PROTOCOL = "SecureMailScope-E2E";

  const RSA_ALGORITHM = {
    name: "RSA-OAEP",
    hash: "SHA-256",
  };

  const ENVELOPE_PATTERN =
    /\{[^{}]*"protocol"\s*:\s*"SecureMailScope-E2E"[^{}]*\}/g;

  function base64UrlToBytes(value) {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padding = "=".repeat((4 - (normalized.length % 4)) % 4);
    const binary = atob(normalized + padding);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  function stableStringify(value) {
    if (value === null || typeof value !== "object") {
      return JSON.stringify(value);
    }

    if (Array.isArray(value)) {
      return `[${value.map(stableStringify).join(",")}]`;
    }

    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
      .join(",")}}`;
  }

  async function calculateKeyId(publicKey) {
    const canonical = stableStringify({
      kty: "RSA",
      n: publicKey.n,
      e: publicKey.e,
      alg: "RSA-OAEP-256",
      use: "enc",
    });

    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(canonical)
    );

    const hex = Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, "0")
    ).join("");

    return `smsk-${hex.slice(0, 24)}`;
  }

  function looksEncrypted(text) {
    return typeof text === "string" && text.includes(PROTOCOL);
  }

  function extractEnvelope(text) {
    if (!looksEncrypted(text)) {
      return null;
    }

    const cleaned = text.replace(/[\u200B-\u200D\uFEFF\u00AD]/g, "");
    // Fallback for leftover quoted-printable soft breaks / wrapped lines.
    const unwrapped = cleaned
      .replace(/=\r?\n/g, "")
      .replace(/=3D/gi, "=")
      .replace(/\r?\n/g, "");
    const matches = [
      ...(cleaned.match(ENVELOPE_PATTERN) || []),
      ...(unwrapped.match(ENVELOPE_PATTERN) || []),
    ];

    for (const candidate of matches) {
      try {
        const parsed = JSON.parse(candidate);

        if (parsed?.protocol === PROTOCOL) {
          for (const field of ["nonce", "wrapped_key", "ciphertext"]) {
            if (typeof parsed[field] === "string") {
              parsed[field] = parsed[field].replace(/\s+/g, "");
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

  async function selectKey(identity, recipientKeyId) {
    const candidates = [identity, ...(identity.previousKeys || [])];

    for (const candidate of candidates) {
      if (!candidate?.publicKey || !candidate?.privateKey) {
        continue;
      }

      const keyId = await calculateKeyId(candidate.publicKey);

      if (!recipientKeyId || keyId === recipientKeyId) {
        return { keyId, privateKey: candidate.privateKey };
      }
    }

    return null;
  }

  function fail(code, message) {
    const error = new Error(message);
    error.code = code;
    return error;
  }

  async function decrypt(envelope, identity) {
    if (
      envelope?.version !== 1 ||
      envelope?.content_encryption !== "AES-256-GCM" ||
      envelope?.key_encryption !== "RSA-OAEP-256"
    ) {
      throw fail("UNSUPPORTED", "Unsupported SecureMailScope envelope format.");
    }

    if (!identity?.privateKey) {
      throw fail(
        "NO_LOCAL_KEY",
        `No private key for ${envelope.recipient} is available in this extension. Open the SecureMailScope app once with that mailbox connected, or import its identity backup from the extension popup.`
      );
    }

    const selected = await selectKey(identity, envelope.recipient_key_id);

    if (!selected) {
      throw fail(
        "KEY_MISMATCH",
        `This message was encrypted to key ${envelope.recipient_key_id}, which is not in this extension's keyring. Import the matching identity backup.`
      );
    }

    const privateKey = await crypto.subtle.importKey(
      "jwk",
      selected.privateKey,
      RSA_ALGORITHM,
      false,
      ["decrypt"]
    );

    let rawKey;

    try {
      rawKey = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        base64UrlToBytes(envelope.wrapped_key)
      );
    } catch {
      throw fail("UNWRAP_FAILED", "The message key could not be unwrapped.");
    }

    const messageKey = await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );

    const additionalData = new TextEncoder().encode(
      JSON.stringify({
        protocol: PROTOCOL,
        version: 1,
        recipient: envelope.recipient,
        recipient_key_id: envelope.recipient_key_id,
      })
    );

    let plaintext;

    try {
      plaintext = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: base64UrlToBytes(envelope.nonce),
          additionalData,
          tagLength: 128,
        },
        messageKey,
        base64UrlToBytes(envelope.ciphertext)
      );
    } catch {
      throw fail(
        "INTEGRITY_FAILED",
        "AES-GCM authentication failed: the message was modified or is incomplete."
      );
    }

    return {
      ...JSON.parse(new TextDecoder().decode(plaintext)),
      decrypted_with_key_id: selected.keyId,
    };
  }

  return {
    PROTOCOL,
    base64UrlToBytes,
    calculateKeyId,
    decrypt,
    extractEnvelope,
    looksEncrypted,
  };
})();
