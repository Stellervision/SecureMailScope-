import { API_BASE } from "./config";

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options);

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const error = new Error(
      data.detail ||
        data.error ||
        data.message ||
        "Request failed."
    );

    error.status = response.status;
    error.data = data;

    throw error;
  }

  return data;
}

/* -------------------------------------------------------------------------- */
/* Mailbox                                                                    */
/* -------------------------------------------------------------------------- */

export function getMailboxAccounts() {
  return request("/api/mailbox/accounts");
}

export function getAvailableMailboxAccounts() {
  return request("/api/mailbox/available-accounts");
}

export function getConfiguredMailboxAccounts() {
  return request("/api/mailbox/configured-accounts");
}

export function getConnectedMailbox() {
  return request("/api/send/account");
}

export function attachMailbox(accountId) {
  return request("/api/mailbox/attach", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      account_id: accountId,
    }),
  });
}

export function connectMailbox(accountId) {
  return request("/api/mailbox/connect", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      account_id: accountId,
    }),
  });
}

export function disconnectMailbox() {
  return request("/api/mailbox/disconnect", {
    method: "POST",
  });
}

export function detachMailbox(accountId) {
  return request("/api/mailbox/detach", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      account_id: accountId,
    }),
  });
}

export function createMailbox(mailbox) {
  return request("/api/mailbox/accounts", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(mailbox),
  });
}

export function removeMailbox(accountId) {
  return request(
    `/api/mailbox/accounts/${encodeURIComponent(accountId)}`,
    {
      method: "DELETE",
    }
  );
}

/* -------------------------------------------------------------------------- */
/* OAuth                                                                      */
/* -------------------------------------------------------------------------- */

export function getOAuthAuthorizationUrl(provider) {
  return request(
    `/api/mailbox/oauth/${encodeURIComponent(provider)}/start`
  );
}

/* -------------------------------------------------------------------------- */
/* Recipient security assessment                                              */
/* -------------------------------------------------------------------------- */

export function checkRecipientSecurity(recipientEmail) {
  return request("/api/send/check-recipient", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      recipient_email: recipientEmail,
    }),
  });
}

/* -------------------------------------------------------------------------- */
/* Email sending                                                              */
/* -------------------------------------------------------------------------- */

export function sendEmail({
  recipientEmail,
  subject,
  body,
  attachments = [],
}) {
  const formData = new FormData();

  formData.append(
    "recipient_email",
    recipientEmail
  );

  formData.append("subject", subject);
  formData.append("body", body);

  attachments.forEach((file) => {
    formData.append(
      "attachments",
      file,
      file.name
    );
  });

  return request("/api/send/email", {
    method: "POST",
    body: formData,
  });
}

/* -------------------------------------------------------------------------- */
/* Inbox                                                                      */
/* -------------------------------------------------------------------------- */

export function getInbox(accountId, limit = 20) {
  return request(
    `/api/mailbox/inbox?account_id=${encodeURIComponent(
      accountId
    )}&limit=${encodeURIComponent(limit)}`
  );
}

export function getMessage(messageId, accountId) {
  return request(
    `/api/mailbox/message/${encodeURIComponent(
      messageId
    )}?account_id=${encodeURIComponent(accountId)}`
  );
}

export { API_BASE };