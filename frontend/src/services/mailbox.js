import { checkRecipientSecurity } from "./api";

export async function assessRecipient(recipientEmail) {
  const recipient = recipientEmail.trim();

  if (!recipient) {
    throw new Error("A recipient email address is required.");
  }

  return checkRecipientSecurity(recipient);
}