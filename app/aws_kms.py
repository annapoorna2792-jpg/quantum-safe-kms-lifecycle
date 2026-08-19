from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class KmsDataKeyProvider(Protocol):
    region: str
    key_id: str

    def generate_data_key(self, encryption_context: dict[str, str]) -> tuple[bytes, bytes]: ...

    def decrypt_data_key(self, ciphertext: bytes, encryption_context: dict[str, str]) -> bytes: ...

    def status(self) -> dict[str, Any]: ...


@dataclass
class AwsKmsProvider:
    """Small AWS KMS adapter that relies on the EC2 instance role credential chain."""

    region: str
    key_id: str
    client: Any | None = None
    _status_cache: dict[str, Any] | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.client is None:
            import boto3

            self.client = boto3.client("kms", region_name=self.region)

    @staticmethod
    def _message(exc: Exception) -> str:
        response = getattr(exc, "response", {})
        if isinstance(response, dict):
            error = response.get("Error", {})
        else:
            error = {}
        if error:
            return f"{error.get('Code', 'ClientError')}: {error.get('Message', str(exc))}"
        return str(exc)

    def status(self) -> dict[str, Any]:
        if self._status_cache is not None:
            return dict(self._status_cache)
        try:
            metadata = self.client.describe_key(KeyId=self.key_id)["KeyMetadata"]
            self._status_cache = {
                "available": bool(metadata.get("Enabled")),
                "mode": "LIVE",
                "region": self.region,
                "configured_key": self.key_id,
                "key_id": metadata.get("KeyId"),
                "arn": metadata.get("Arn"),
                "key_state": metadata.get("KeyState"),
                "key_manager": metadata.get("KeyManager"),
                "error": None,
            }
        except Exception as exc:
            self._status_cache = {
                "available": False,
                "mode": "LIVE",
                "region": self.region,
                "configured_key": self.key_id,
                "error": self._message(exc),
            }
        return dict(self._status_cache)

    def generate_data_key(self, encryption_context: dict[str, str]) -> tuple[bytes, bytes]:
        try:
            response = self.client.generate_data_key(
                KeyId=self.key_id,
                KeySpec="AES_256",
                EncryptionContext=encryption_context,
            )
            return bytes(response["Plaintext"]), bytes(response["CiphertextBlob"])
        except Exception as exc:
            raise RuntimeError(f"AWS KMS GenerateDataKey failed: {self._message(exc)}") from exc

    def decrypt_data_key(self, ciphertext: bytes, encryption_context: dict[str, str]) -> bytes:
        try:
            response = self.client.decrypt(
                KeyId=self.key_id,
                CiphertextBlob=ciphertext,
                EncryptionContext=encryption_context,
            )
            return bytes(response["Plaintext"])
        except Exception as exc:
            raise RuntimeError(f"AWS KMS Decrypt failed: {self._message(exc)}") from exc
