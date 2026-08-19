from __future__ import annotations

from datetime import timedelta

import pytest

from app.db import iso, utc_now


class FakeAwsKmsProvider:
    region = "eu-north-1"
    key_id = "alias/quantum-safe-kms-demo"

    def generate_data_key(self, encryption_context):
        plaintext = bytes(range(32))
        return plaintext, b"TEST-KMS-CIPHERTEXT:" + plaintext

    def decrypt_data_key(self, ciphertext, encryption_context):
        prefix = b"TEST-KMS-CIPHERTEXT:"
        if not ciphertext.startswith(prefix):
            raise ValueError("invalid fake KMS ciphertext")
        return ciphertext[len(prefix):]

    def status(self):
        return {
            "available": True,
            "mode": "LIVE",
            "region": self.region,
            "configured_key": self.key_id,
            "arn": "arn:aws:kms:eu-north-1:111122223333:key/test",
            "error": None,
        }


@pytest.fixture
def fake_aws_kms():
    return FakeAwsKmsProvider()


@pytest.fixture
def metadata_material():
    """Non-cryptographic repository fixture; never presented as a successful PQC operation."""
    return {
        "expires_at": iso(utc_now() + timedelta(hours=1)),
        "classical_algorithm": "AWS KMS data key + AES-256-GCM + AES-256-KW",
        "pqc_kem_algorithm": "ML-KEM-768",
        "pqc_signature_algorithm": "ML-DSA-65",
        "envelope_format": "QSKMS-AWS-HYBRID-ENVELOPE/v2",
        "public_material": {
            "providers": [
                {"name": "AWS KMS", "mode": "LIVE"},
                {"name": "Azure Key Vault", "mode": "SIMULATION"},
            ]
        },
        "protected_material": "repository-test-placeholder-not-cryptographic-material",
        "wrapped_dek": "repository-test-placeholder",
        "kem_ciphertext": "repository-test-placeholder",
        "risk_tags": ["HYBRID_READY", "PQC_READY"],
    }
