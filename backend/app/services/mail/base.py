from abc import ABC, abstractmethod
from typing import Any


class MailProvider(ABC):
    @abstractmethod
    def connect(self, credentials: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def list_messages(
        self,
        account_id: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def get_message(
        self,
        account_id: str,
        message_id: str,
    ) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def send_message(
        self,
        account_id: str,
        message: dict[str, Any],
    ) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def disconnect(self, account_id: str) -> dict[str, Any]:
        raise NotImplementedError