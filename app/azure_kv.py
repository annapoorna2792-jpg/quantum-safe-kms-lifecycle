from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Protocol


class AzureKeyProvider(Protocol):
    vault_url: str
    key_name: str

    def generate_data_key(self, encryption_context: dict[str, str]) -> tuple[bytes, bytes]: ...
    def decrypt_data_key(self, ciphertext: bytes, encryption_context: dict[str, str]) -> bytes: ...
    def status(self) -> dict[str, Any]: ...


@dataclass
class AzureKeyVaultProvider:
    """Azure Key Vault adapter using a service-principal credential. Azure has no native
    GenerateDataKey primitive, so this mirrors AWS KMS by generating a local AES-256 key
    and wrapping/unwrapping it with an RSA key held in the vault."""

    vault_url: str
    key_name: str
    tenant_id: str
    client_id: str
    client_secret: str
    crypto_client: Any | None = None
    _status_cache: dict[str, Any] | None = field(default=None, init=False, repr=False)
    _wrap_algorithm: str = field(default="RSA-OAEP-256", init=False, repr=False)

    def __post_init__(self) -> None:
        if self.crypto_client is None:
            from azure.identity import ClientSecretCredential
            from azure.keyvault.keys import KeyClient
            from azure.keyvault.keys.crypto import CryptographyClient

            credential = ClientSecretCredential(self.tenant_id, self.client_id, self.client_secret)
            key_client = KeyClient(vault_url=self.vault_url, credential=credential)
            key = key_client.get_key(self.key_name)
            self.crypto_client = CryptographyClient(key, credential=credential)

    @staticmethod
    def _message(exc: Exception) -> str:
        return str(exc)

    def status(self) -> dict[str, Any]:
        if self._status_cache is not None:
            return dict(self._status_cache)
        try:
            probe = os.urandom(32)
            wrapped = self.crypto_client.wrap_key(self._wrap_algorithm, probe)
            self.crypto_client.unwrap_key(self._wrap_algorithm, wrapped.encrypted_key)
            self._status_cache = {
                "available": True, "mode": "LIVE",
                "vault_url": self.vault_url, "key_name": self.key_name, "error": None,
            }
        except Exception as exc:
            self._status_cache = {
                "available": False, "mode": "LIVE",
                "vault_url": self.vault_url, "key_name": self.key_name,
                "error": self._message(exc),
            }
        return dict(self._status_cache)

    def generate_data_key(self, encryption_context: dict[str, str]) -> tuple[bytes, bytes]:
        plaintext = os.urandom(32)
        try:
            result = self.crypto_client.wrap_key(self._wrap_algorithm, plaintext)
            return plaintext, bytes(result.encrypted_key)
        except Exception as exc:
            raise RuntimeError(f"Azure Key Vault WrapKey failed: {self._message(exc)}") from exc

    def decrypt_data_key(self, ciphertext: bytes, encryption_context: dict[str, str]) -> bytes:
        try:
            result = self.crypto_client.unwrap_key(self._wrap_algorithm, ciphertext)
            return bytes(result.key)
        except Exception as exc:
            raise RuntimeError(f"Azure Key Vault UnwrapKey failed: {self._message(exc)}") from exc
