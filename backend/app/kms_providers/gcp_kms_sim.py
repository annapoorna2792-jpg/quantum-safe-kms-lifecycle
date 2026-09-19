"""
GCP Cloud KMS Provider — documentation-only per §10.5 and §11.1.

Google Cloud KMS supports HPKE-based import with ML-KEM-768/ML-KEM-1024
(preview, software protection level only). This capability is documented
in the report but NOT exercised against the live service (no GCP deployment).
The provider reports transit_posture = pq_native for completeness in the
provider capability matrix (Table 10.5).
"""
import uuid
import base64
import os
from datetime import datetime
from app.kms_providers.base import BaseKMSProvider
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_SIM_STORE: dict = {}


class GCPCloudKMSProvider(BaseKMSProvider):
    """
    GCP Cloud KMS — simulated only. provider_mode = DOC.
    Represents the post-quantum import capability documented in §10.5
    (HPKE X-Wing / ML-KEM-768 import, software protection level).
    """
    provider_name = "gcp_kms"

    def create_key(self, key_id: str, algorithm: str, **kwargs) -> dict:
        sim_key = os.urandom(32)
        kms_id  = f"projects/quantum-kms-demo/locations/global/keyRings/qkms/cryptoKeys/{uuid.uuid4().hex[:8]}"
        _SIM_STORE[kms_id] = sim_key
        return {
            "kms_key_id":  kms_id,
            "provider":    self.provider_name,
            "mode":        "DOC",
            "region":      "global",
            "created_at":  datetime.utcnow().isoformat(),
        }

    def get_key(self, kms_key_id: str) -> dict:
        return {"kms_key_id": kms_key_id, "enabled": True, "mode": "DOC"}

    def rotate_key(self, kms_key_id: str) -> dict:
        if kms_key_id in _SIM_STORE:
            _SIM_STORE[kms_key_id] = os.urandom(32)
        return {"kms_key_id": kms_key_id, "rotated_at": datetime.utcnow().isoformat()}

    def revoke_key(self, kms_key_id: str, reason: str) -> bool:
        return True

    def delete_key(self, kms_key_id: str) -> bool:
        _SIM_STORE.pop(kms_key_id, None)
        return True

    def encrypt(self, kms_key_id: str, plaintext: bytes) -> str:
        sim_key = _SIM_STORE.get(kms_key_id, os.urandom(32))
        iv  = os.urandom(12)
        ct  = AESGCM(sim_key).encrypt(iv, plaintext, None)
        return base64.b64encode(iv + ct).decode()

    def decrypt(self, kms_key_id: str, ciphertext: str) -> bytes:
        raw = base64.b64decode(ciphertext)
        iv, ct = raw[:12], raw[12:]
        sim_key = _SIM_STORE.get(kms_key_id, b"\x00" * 32)
        return AESGCM(sim_key).decrypt(iv, ct, None)

    def health(self) -> dict:
        return {
            "provider":  "gcp_kms",
            "mode":      "DOC",   # capability read from vendor API reference
            "region":    "global",
            "pq_import_support": True,         # §10.5 — HPKE ML-KEM-768 in preview
            "transit_posture":   "pq_native",  # pq_native per report notation
            "note": "GCP PQ import not exercised against live service (no deployment)",
        }


# Legacy alias
GCPKMSSimulator = GCPCloudKMSProvider
