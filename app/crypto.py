from __future__ import annotations

import base64
import ctypes.util
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .aws_kms import KmsDataKeyProvider
from .azure_kv import AzureKeyProvider

def _native_oqs_present() -> bool:
    """Avoid liboqs-python's network auto-installer when a native library is absent."""
    if ctypes.util.find_library("oqs"):
        return True
    roots = [Path("/usr/local/lib"), Path("/opt/homebrew/lib")]
    install_path = os.getenv("OQS_INSTALL_PATH")
    if install_path:
        roots.append(Path(install_path) / "lib")
    roots.extend(Path(item) for item in os.getenv("LD_LIBRARY_PATH", "").split(":") if item)
    return any(any(root.glob(pattern)) for root in roots for pattern in ("liboqs.so*", "liboqs.dylib"))


if not _native_oqs_present():
    oqs = None
    OQS_IMPORT_ERROR = "native liboqs shared library was not found; use the Docker image or install liboqs 0.16.0"
else:
    try:
        import oqs  # type: ignore
    except (ImportError, RuntimeError, OSError, SystemExit) as exc:
        oqs = None
        OQS_IMPORT_ERROR = str(exc)
    else:
        OQS_IMPORT_ERROR = None


KEM_ALGORITHM = "ML-KEM-768"
SIGNATURE_ALGORITHM = "ML-DSA-65"
CLASSICAL_ALGORITHM = "AWS KMS data key + AES-256-GCM + AES-256-KW"
ENVELOPE_FORMAT = "QSKMS-AWS-HYBRID-ENVELOPE/v2"


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


class PQCUnavailable(RuntimeError):
    pass


def pqc_status() -> dict[str, Any]:
    if oqs is None:
        return {"available": False, "error": OQS_IMPORT_ERROR or "liboqs-python is not installed"}
    try:
        kems = oqs.get_enabled_kem_mechanisms()
        sigs = oqs.get_enabled_sig_mechanisms()
        missing = [name for name, enabled in ((KEM_ALGORITHM, KEM_ALGORITHM in kems), (SIGNATURE_ALGORITHM, SIGNATURE_ALGORITHM in sigs)) if not enabled]
        if missing:
            return {"available": False, "error": f"native liboqs build is missing: {', '.join(missing)}"}
        return {"available": True, "error": None}
    except Exception as exc:
        return {"available": False, "error": str(exc)}


def require_pqc() -> None:
    status = pqc_status()
    if not status["available"]:
        raise PQCUnavailable(f"Real liboqs support is required: {status['error']}")


class MasterKeyProtector:
    """AES-256-GCM protection for every persisted secret/private byte string."""

    def __init__(self, master_key: bytes):
        if len(master_key) != 32:
            raise ValueError("master key must be 32 bytes")
        self.aead = AESGCM(master_key)

    def seal(self, values: dict[str, bytes], context: str) -> str:
        nonce = os.urandom(12)
        plaintext = json.dumps({name: b64(value) for name, value in values.items()}, sort_keys=True).encode()
        ciphertext = self.aead.encrypt(nonce, plaintext, context.encode())
        return json.dumps({"v": 1, "nonce": b64(nonce), "ciphertext": b64(ciphertext)})

    def open(self, sealed: str, context: str) -> dict[str, bytes]:
        payload = json.loads(sealed)
        plaintext = self.aead.decrypt(unb64(payload["nonce"]), unb64(payload["ciphertext"]), context.encode())
        return {name: unb64(value) for name, value in json.loads(plaintext).items()}


def derive_hybrid_kek(aws_kek: bytes, azure_kek: bytes, pq_shared_secret: bytes, context: bytes) -> bytes:
    """Demo-only combiner. This is intentionally versioned, but is not a standardized hybrid protocol."""
    input_key_material = b"AWS-KMS-LIVE\0" + aws_kek + b"AZURE-KV-SIM\0" + azure_kek + b"ML-KEM\0" + pq_shared_secret
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=context, info=b"QSKMS-AWS-HYBRID-KEK/v2").derive(
        input_key_material
    )


def kms_encryption_context(key_id: str) -> dict[str, str]:
    return {
        "application": "quantum-safe-kms-demo",
        "logical-key-id": key_id,
        "envelope-format": ENVELOPE_FORMAT,
    }


@dataclass
class HybridCrypto:
    protector: MasterKeyProtector
    aws_kms: KmsDataKeyProvider
    azure_kv: AzureKeyProvider

    def create_version_material(self, key_id: str, expires_at: str) -> dict[str, Any]:
        require_pqc()
        aws_kek, aws_kms_ciphertext = self.aws_kms.generate_data_key(kms_encryption_context(key_id))
        azure_kek, azure_ciphertext = self.azure_kv.generate_data_key({"application": "quantum-safe-kms-demo", "key_id": key_id})
        dek = os.urandom(32)
        with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
            pq_public = kem.generate_keypair()
            pq_secret = kem.export_secret_key()
            kem_ciphertext, pq_shared = kem.encap_secret(pq_public)
        context = f"{ENVELOPE_FORMAT}|{key_id}".encode()
        hybrid_kek = derive_hybrid_kek(aws_kek, azure_kek, pq_shared, context)
        wrapped_dek = aes_key_wrap(hybrid_kek, dek)
        protected = self.protector.seal(
            {
                "aws_kms_ciphertext": aws_kms_ciphertext,
                "azure_kv_ciphertext": azure_ciphertext,
                "ml_kem_secret": pq_secret,
            },
            f"key-version:{key_id}",
        )
        aws_status = self.aws_kms.status()
        return {
            "expires_at": expires_at,
            "classical_algorithm": CLASSICAL_ALGORITHM,
            "pqc_kem_algorithm": KEM_ALGORITHM,
            "pqc_signature_algorithm": SIGNATURE_ALGORITHM,
            "envelope_format": ENVELOPE_FORMAT,
            "public_material": {
                "ml_kem_public_key": b64(pq_public),
                "providers": [
                    {
                        "name": "AWS KMS",
                        "mode": "LIVE",
                        "region": self.aws_kms.region,
                        "key_id": aws_status.get("arn") or self.aws_kms.key_id,
                        "key": "KMS GenerateDataKey AES-256 contribution",
                    },
                    {"name": "Azure Key Vault", "mode": "LIVE", "vault_url": self.azure_kv.vault_url, "key": "WrapKey AES-256 contribution"},
                ],
            },
            "protected_material": protected,
            "wrapped_dek": b64(wrapped_dek),
            "kem_ciphertext": b64(kem_ciphertext),
            "risk_tags": ["HYBRID_READY", "PQC_READY"],
        }

    def _unwrap_dek(self, version: dict[str, Any]) -> bytes:
        require_pqc()
        if version["state"] in {"REVOKED", "DESTROYED"}:
            raise ValueError(f"version is {version['state']} and cannot decrypt")
        if not version.get("protected_material"):
            raise ValueError("secret material has been destroyed")
        secrets = self.protector.open(version["protected_material"], f"key-version:{version['key_id']}")
        aws_kek = self.aws_kms.decrypt_data_key(
            secrets["aws_kms_ciphertext"], kms_encryption_context(version["key_id"])
        )
        with oqs.KeyEncapsulation(KEM_ALGORITHM, secrets["ml_kem_secret"]) as kem:
            pq_shared = kem.decap_secret(unb64(version["kem_ciphertext"]))
        context = f"{ENVELOPE_FORMAT}|{version['key_id']}".encode()
        hybrid_kek = derive_hybrid_kek(
            aws_kek, self.azure_kv.decrypt_data_key(secrets["azure_kv_ciphertext"], {}), pq_shared, context
        )
        return aes_key_unwrap(hybrid_kek, unb64(version["wrapped_dek"]))

    def encrypt(self, version: dict[str, Any], plaintext: str, user_aad: str = "") -> str:
        if version["state"] != "ACTIVE":
            raise ValueError("new encryption requires an ACTIVE version")
        dek = self._unwrap_dek(version)
        nonce = os.urandom(12)
        metadata_aad = f"{ENVELOPE_FORMAT}|{version['key_id']}|{version['version_number']}|{user_aad}".encode()
        ciphertext = AESGCM(dek).encrypt(nonce, plaintext.encode(), metadata_aad)
        envelope = {
            "format": ENVELOPE_FORMAT,
            "key_id": version["key_id"],
            "key_version": version["version_number"],
            "algorithms": {"content": "AES-256-GCM", "key_wrap": "AES-256-KW", "pqc": KEM_ALGORITHM},
            "nonce": b64(nonce),
            "aad": user_aad,
            "ciphertext": b64(ciphertext),
        }
        return b64(json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode())

    def decrypt(self, version: dict[str, Any], encoded_envelope: str) -> str:
        envelope = json.loads(unb64(encoded_envelope))
        if envelope.get("format") != ENVELOPE_FORMAT:
            raise ValueError("unsupported envelope format")
        if envelope.get("key_id") != version["key_id"] or envelope.get("key_version") != version["version_number"]:
            raise ValueError("envelope key reference does not match the selected immutable version")
        dek = self._unwrap_dek(version)
        metadata_aad = (
            f"{ENVELOPE_FORMAT}|{version['key_id']}|{version['version_number']}|{envelope.get('aad', '')}"
        ).encode()
        plaintext = AESGCM(dek).decrypt(unb64(envelope["nonce"]), unb64(envelope["ciphertext"]), metadata_aad)
        return plaintext.decode()

    def sign(self, message: str) -> str:
        require_pqc()
        payload = message.encode()
        ec_private = ec.generate_private_key(ec.SECP256R1())
        ec_signature = ec_private.sign(payload, ec.ECDSA(hashes.SHA256()))
        ec_public = ec_private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with oqs.Signature(SIGNATURE_ALGORITHM) as signer:
            pq_public = signer.generate_keypair()
            pq_signature = signer.sign(payload)
        package = {
            "format": "QSKMS-DEMO-HYBRID-SIGNATURE/v1",
            "message_sha256": hashlib.sha256(payload).hexdigest(),
            "classical": {"algorithm": "ECDSA-P256-SHA256", "public_key": b64(ec_public), "signature": b64(ec_signature)},
            "pqc": {"algorithm": SIGNATURE_ALGORITHM, "public_key": b64(pq_public), "signature": b64(pq_signature)},
        }
        return b64(json.dumps(package, separators=(",", ":"), sort_keys=True).encode())

    def verify(self, message: str, encoded_package: str) -> dict[str, bool]:
        require_pqc()
        package = json.loads(unb64(encoded_package))
        if package.get("format") != "QSKMS-DEMO-HYBRID-SIGNATURE/v1":
            raise ValueError("unsupported signature package")
        payload = message.encode()
        classical_ok = False
        try:
            public = serialization.load_der_public_key(unb64(package["classical"]["public_key"]))
            public.verify(unb64(package["classical"]["signature"]), payload, ec.ECDSA(hashes.SHA256()))
            classical_ok = True
        except Exception:
            classical_ok = False
        with oqs.Signature(SIGNATURE_ALGORITHM) as verifier:
            pqc_ok = verifier.verify(payload, unb64(package["pqc"]["signature"]), unb64(package["pqc"]["public_key"]))
        return {"classical": classical_ok, "pqc": bool(pqc_ok), "hybrid": classical_ok and bool(pqc_ok)}
