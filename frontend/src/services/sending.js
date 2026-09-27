import { sendEmail as sendEmailRequest } from "./api";

export async function submitEmail({
  recipientEmail,
  subject,
  body,
  attachments = [],
}) {
  const recipient = recipientEmail.trim();
  const trimmedSubject = subject.trim();
  const trimmedBody = body.trim();

  if (!recipient) {
    throw new Error("A recipient email address is required.");
  }

  if (!trimmedSubject) {
    throw new Error("A subject is required.");
  }

  if (!trimmedBody) {
    throw new Error("A message body is required.");
  }

  return sendEmailRequest({
    recipientEmail: recipient,
    subject: trimmedSubject,
    body,
    attachments,
  });
}