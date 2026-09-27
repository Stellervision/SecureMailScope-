from datetime import datetime, timezone

from app.services.mail.base import MailProvider


class MockMailProvider(MailProvider):
    def connect(self, credentials: dict) -> dict:
        return {
            "status": "connected",
            "provider": "mock",
            "account_id": "demo-account",
        }

    def list_messages(
        self,
        account_id: str,
        limit: int = 20,
    ) -> list[dict]:
        messages = [
            {
                "id": "demo-001",
                "thread_id": "thread-001",
                "sender": "security@example.com",
                "recipients": ["user@example.com"],
                "subject": "Security notification",
                "preview": "Your account security settings were updated.",
                "received_at": datetime.now(timezone.utc).isoformat(),
                "labels": ["INBOX"],
                "provider": "mock",
            },
            {
                "id": "demo-002",
                "thread_id": "thread-002",
                "sender": "research@example.org",
                "recipients": ["user@example.com"],
                "subject": "Research document",
                "preview": "Please review the attached research document.",
                "received_at": datetime.now(timezone.utc).isoformat(),
                "labels": ["INBOX"],
                "provider": "mock",
            },
        ]

        return messages[:limit]

    def get_message(
        self,
        account_id: str,
        message_id: str,
    ) -> dict:
        messages = {
            "demo-001": {
                "id": "demo-001",
                "thread_id": "thread-001",
                "sender": "security@example.com",
                "recipients": ["user@example.com"],
                "subject": "Security notification",
                "body": (
                    "Your account security settings were updated. "
                    "If you did not make this change, please review your account."
                ),
                "received_at": datetime.now(timezone.utc).isoformat(),
                "headers": {
                    "Authentication-Results": "unknown",
                    "Received": "unknown",
                },
                "attachments": [],
                "provider": "mock",
            },
            "demo-002": {
                "id": "demo-002",
                "thread_id": "thread-002",
                "sender": "research@research.example.org",
                "recipients": ["user@example.com"],
                "subject": "Research document",
                "body": (
                    "Please review the attached research document "
                    "before our next meeting."
                ),
                "received_at": datetime.now(timezone.utc).isoformat(),
                "headers": {
                    "Authentication-Results": "unknown",
                    "Received": "unknown",
                },
                "attachments": [
                    {
                        "filename": "research-document.pdf",
                        "content_type": "application/pdf",
                    }
                ],
                "provider": "mock",
            },
        }

        message = messages.get(message_id)

        if message is None:
            raise ValueError("Message not found")

        return message

    def send_message(
        self,
        account_id: str,
        message: dict,
    ) -> dict:
        return {
            "status": "sent",
            "provider": "mock",
            "message_id": "demo-sent-001",
            "submitted_at": datetime.now(timezone.utc).isoformat(),
        }

    def disconnect(self, account_id: str) -> dict:
        return {
            "status": "disconnected",
            "account_id": account_id,
            "provider": "mock",
        }