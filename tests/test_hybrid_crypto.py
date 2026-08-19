from __future__ import annotations

import pytest

from app.crypto import HybridCrypto, MasterKeyProtector, pqc_status
from app.db import Repository
from app.service import KMSService


pytestmark = pytest.mark.skipif(not pqc_status()["available"], reason="real native liboqs ML-KEM-768/ML-DSA-65 is unavailable")


def test_old_version_ciphertext_decrypts_after_rotation(tmp_path, fake_aws_kms):
    repository = Repository(tmp_path / "test.db")
    service = KMSService(repository, HybridCrypto(MasterKeyProtector(bytes(range(32))), fake_aws_kms), 120)
    key_id = service.create_key("orders")
    envelope = service.encrypt(key_id, "old ciphertext survives", "tenant-7")
    service.rotate(key_id)
    assert repository.get_version(key_id, 1)["state"] == "RETIRED"
    assert service.decrypt(envelope) == "old ciphertext survives"


def test_classical_and_pqc_signatures_must_both_verify(tmp_path, fake_aws_kms):
    crypto = HybridCrypto(MasterKeyProtector(bytes(range(32))), fake_aws_kms)
    package = crypto.sign("approve")
    assert crypto.verify("approve", package) == {"classical": True, "pqc": True, "hybrid": True}
    assert crypto.verify("reject", package)["hybrid"] is False
