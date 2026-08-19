from __future__ import annotations

from app.aws_kms import AwsKmsProvider


class FakeKmsClient:
    def __init__(self):
        self.calls = []

    def describe_key(self, **kwargs):
        self.calls.append(("describe_key", kwargs))
        return {
            "KeyMetadata": {
                "Enabled": True,
                "KeyId": "key-123",
                "Arn": "arn:aws:kms:eu-north-1:111122223333:key/key-123",
                "KeyState": "Enabled",
                "KeyManager": "CUSTOMER",
            }
        }

    def generate_data_key(self, **kwargs):
        self.calls.append(("generate_data_key", kwargs))
        return {"Plaintext": b"p" * 32, "CiphertextBlob": b"kms-ciphertext"}

    def decrypt(self, **kwargs):
        self.calls.append(("decrypt", kwargs))
        return {"Plaintext": b"p" * 32}


def test_provider_uses_configured_key_region_and_encryption_context():
    client = FakeKmsClient()
    provider = AwsKmsProvider("eu-north-1", "alias/quantum-safe-kms-demo", client=client)
    context = {"application": "quantum-safe-kms-demo", "logical-key-id": "logical-1"}

    status = provider.status()
    plaintext, ciphertext = provider.generate_data_key(context)
    recovered = provider.decrypt_data_key(ciphertext, context)

    assert status["available"] is True
    assert status["mode"] == "LIVE"
    assert plaintext == recovered == b"p" * 32
    assert ciphertext == b"kms-ciphertext"
    assert client.calls[1] == (
        "generate_data_key",
        {
            "KeyId": "alias/quantum-safe-kms-demo",
            "KeySpec": "AES_256",
            "EncryptionContext": context,
        },
    )
    assert client.calls[2][1]["KeyId"] == "alias/quantum-safe-kms-demo"
    assert client.calls[2][1]["EncryptionContext"] == context
