"""
Base KMS Provider interface — Capstone 2.
All providers implement this ABC. Added health() method for the /healthz endpoint.
"""
from abc import ABC, abstractmethod


class BaseKMSProvider(ABC):
    """Abstract base class for all KMS provider adapters."""

    provider_name: str = "base"

    @abstractmethod
    def create_key(self, key_id: str, algorithm: str, **kwargs) -> dict:
        """Create and store a new key in the KMS."""
        ...

    @abstractmethod
    def get_key(self, kms_key_id: str) -> dict:
        """Retrieve key metadata from KMS."""
        ...

    @abstractmethod
    def rotate_key(self, kms_key_id: str) -> dict:
        """Rotate a key, returning new version metadata."""
        ...

    @abstractmethod
    def revoke_key(self, kms_key_id: str, reason: str) -> bool:
        """Revoke/disable a key in the KMS."""
        ...

    @abstractmethod
    def delete_key(self, kms_key_id: str) -> bool:
        """Schedule key deletion."""
        ...

    @abstractmethod
    def encrypt(self, kms_key_id: str, plaintext: bytes) -> str:
        """Encrypt data using the KMS-managed key."""
        ...

    @abstractmethod
    def decrypt(self, kms_key_id: str, ciphertext: str) -> bytes:
        """Decrypt data using the KMS-managed key."""
        ...

    def health(self) -> dict:
        """Return provider health info for /healthz endpoint."""
        return {
            "provider":           self.provider_name,
            "mode":               "SIM",
            "pq_import_support":  False,
            "transit_posture":    "classical_only",
        }

    def health_check(self) -> dict:
        """Legacy alias."""
        return self.health()
