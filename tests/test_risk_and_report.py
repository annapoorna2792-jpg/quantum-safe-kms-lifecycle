from __future__ import annotations

from datetime import timedelta

from app.crypto import HybridCrypto, MasterKeyProtector
from app.db import Repository, iso, utc_now
from app.service import KMSService, assess_risk


def test_risk_tags_cover_classical_hybrid_pqc_and_non_compliant():
    tags, _ = assess_risk({"state": "ACTIVE", "classical_algorithm": "AES", "pqc_kem_algorithm": "", "provider_count": 2, "aws_kms_live": True})
    assert tags == ["QUANTUM_VULNERABLE"]
    tags, _ = assess_risk({"state": "ACTIVE", "classical_algorithm": "AES", "pqc_kem_algorithm": "ML-KEM-768", "provider_count": 2, "aws_kms_live": True, "expires_at": "2999-01-01T00:00:00+00:00"})
    assert "HYBRID_READY" in tags and "PQC_READY" in tags
    tags, _ = assess_risk({"state": "REVOKED", "classical_algorithm": "AES", "pqc_kem_algorithm": "ML-KEM-768", "provider_count": 2, "aws_kms_live": True})
    assert "NON_COMPLIANT" in tags


def test_report_contains_inventory_algorithms_rotations_and_append_only_audit(tmp_path, metadata_material, fake_aws_kms):
    repository = Repository(tmp_path / "test.db")
    repository.create_key("key-1", "orders", 120, iso(utc_now() + timedelta(seconds=120)))
    repository.add_version("key-1", metadata_material, iso(utc_now() + timedelta(seconds=120)), "INITIAL_CREATE")
    service = KMSService(repository, HybridCrypto(MasterKeyProtector(bytes(32)), fake_aws_kms), 120)
    report = service.compliance_report()
    assert report["summary"]["keys"] == 1
    assert report["summary"]["versions"] == 1
    assert report["versions"][0]["pqc_kem_algorithm"] == "ML-KEM-768"
    assert report["rotation_events"][0]["trigger"] == "INITIAL_CREATE"
    assert report["cloud_status"]["aws_kms"]["mode"] == "LIVE"
    assert {event["action"] for event in report["audit_events"]} == {"KEY_CREATED", "VERSION_ACTIVATED"}
    assert "protected_material" not in report["versions"][0]

    with repository.connect() as db:
        try:
            db.execute("UPDATE audit_events SET action='TAMPERED' WHERE id=1")
        except Exception as exc:
            assert "append-only" in str(exc)
        else:
            raise AssertionError("append-only trigger did not reject audit mutation")
