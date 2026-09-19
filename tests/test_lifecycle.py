"""
Tests for the immutable key lifecycle model (Algorithm 8.3 / §7.3).
Verifies create → rotate (v1→v4) → version states → encrypt → decrypt.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base
from app.models import CryptographicKey, KeyVersion, VersionState, QuantumRiskTag
from app.services.key_lifecycle_service import KeyLifecycleService

# ── In-memory SQLite test database ────────────────────────────────────

@pytest.fixture(scope="function")
def db():
    engine  = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def lifecycle():
    return KeyLifecycleService()


# ── Create ────────────────────────────────────────────────────────────

def test_create_key_creates_v1(db, lifecycle):
    key = lifecycle.create_key(db, "test-key", algorithm="HYBRID-ML-KEM-768-AES-256-GCM")
    assert key.name == "test-key"
    assert key.active_version_number == 1
    assert key.total_versions == 1


def test_create_key_v1_is_active(db, lifecycle):
    key = lifecycle.create_key(db, "test-key-2")
    versions = lifecycle.get_versions(db, key.id)
    assert len(versions) == 1
    assert versions[0].state == VersionState.ACTIVE
    assert versions[0].version_number == 1


def test_create_key_v1_has_ml_kem_768(db, lifecycle):
    key = lifecycle.create_key(db, "pqc-key")
    v1  = lifecycle.get_versions(db, key.id)[0]
    assert "ML-KEM-768" in v1.pqc_algorithm
    assert "ML-DSA-65"  in v1.sign_algorithm


def test_create_key_v1_risk_tag_is_hybrid_ready(db, lifecycle):
    key = lifecycle.create_key(db, "risk-key")
    v1  = lifecycle.get_versions(db, key.id)[0]
    assert v1.quantum_risk_tag == QuantumRiskTag.HYBRID_READY


def test_create_duplicate_key_returns_existing(db, lifecycle):
    k1 = lifecycle.create_key(db, "dup-key")
    k2 = lifecycle.create_key(db, "dup-key")
    assert k1.id == k2.id


# ── Rotate (Algorithm 8.3) ────────────────────────────────────────────

def test_rotate_creates_new_version(db, lifecycle):
    key = lifecycle.create_key(db, "rotate-key")
    lifecycle.rotate_key(db, key.id)
    versions = lifecycle.get_versions(db, key.id)
    assert len(versions) == 2


def test_rotate_retires_old_version(db, lifecycle):
    key = lifecycle.create_key(db, "retire-key")
    lifecycle.rotate_key(db, key.id)
    versions = lifecycle.get_versions(db, key.id)
    v1 = next(v for v in versions if v.version_number == 1)
    v2 = next(v for v in versions if v.version_number == 2)
    assert v1.state == VersionState.RETIRED
    assert v2.state == VersionState.ACTIVE


def test_rotate_four_times_creates_v5(db, lifecycle):
    """Simulate the report's v1→v4 demonstration (Chapter 9.1)."""
    key = lifecycle.create_key(db, "multi-rotate")
    for i in range(4):
        lifecycle.rotate_key(db, key.id)
    db.refresh(key)
    versions = lifecycle.get_versions(db, key.id)
    assert len(versions) == 5
    assert key.active_version_number == 5


def test_only_one_active_version_at_a_time(db, lifecycle):
    key = lifecycle.create_key(db, "one-active")
    lifecycle.rotate_key(db, key.id)
    lifecycle.rotate_key(db, key.id)
    versions = lifecycle.get_versions(db, key.id)
    active = [v for v in versions if v.state == VersionState.ACTIVE]
    assert len(active) == 1


# ── Revoke / Destroy ──────────────────────────────────────────────────

def test_revoke_sets_non_compliant(db, lifecycle):
    key = lifecycle.create_key(db, "revoke-key")
    lifecycle.revoke_key(db, key.id, reason="Test revocation")
    versions = lifecycle.get_versions(db, key.id)
    active_v = versions[0]
    assert active_v.state == VersionState.REVOKED
    assert active_v.quantum_risk_tag == QuantumRiskTag.NON_COMPLIANT


def test_destroy_retired_version(db, lifecycle):
    key = lifecycle.create_key(db, "destroy-key")
    lifecycle.rotate_key(db, key.id)
    versions = lifecycle.get_versions(db, key.id)
    v1 = next(v for v in versions if v.version_number == 1)
    assert v1.state == VersionState.RETIRED
    # Revoke then destroy
    v1.state = VersionState.REVOKED
    db.commit()
    lifecycle.destroy_version(db, key.id, v1.id)
    db.refresh(v1)
    assert v1.state == VersionState.DESTROYED


# ── Encrypt / Decrypt ─────────────────────────────────────────────────

def test_encrypt_returns_envelope_id(db, lifecycle):
    key  = lifecycle.create_key(db, "enc-key")
    res  = lifecycle.encrypt(db, key.id, "Hello, quantum world!", "tenant-a")
    assert "envelope_id" in res
    assert res["key_alias"] == "enc-key"


def test_decrypt_recovers_plaintext(db, lifecycle):
    key       = lifecycle.create_key(db, "dec-key")
    plaintext = "Harvest report: 42 tonnes"
    enc       = lifecycle.encrypt(db, key.id, plaintext, "tenant-a")
    dec       = lifecycle.decrypt(db, enc["envelope_id"])
    assert dec["plaintext"] == plaintext


def test_decrypt_after_rotation_uses_retired_version(db, lifecycle):
    """RETIRED versions must still be usable for historical decrypt (§7.3)."""
    key = lifecycle.create_key(db, "hist-key")
    enc = lifecycle.encrypt(db, key.id, "historical data", "tenant-a")
    # Rotate — v1 becomes RETIRED
    lifecycle.rotate_key(db, key.id)
    # Decrypt with envelope referencing v1 (RETIRED) must still succeed
    dec = lifecycle.decrypt(db, enc["envelope_id"])
    assert dec["plaintext"] == "historical data"


def test_encrypt_on_revoked_key_raises(db, lifecycle):
    key = lifecycle.create_key(db, "rev-enc-key")
    lifecycle.revoke_key(db, key.id, reason="test")
    with pytest.raises((ValueError, KeyError)):
        lifecycle.encrypt(db, key.id, "should fail", "t")
