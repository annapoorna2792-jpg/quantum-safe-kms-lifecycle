"""
Tests for the v2 hybrid combiner (Algorithm 8.2).
Verifies ML-KEM-768 + AES-256-GCM encrypt / decrypt round-trip
and envelope structure matches report requirements.
"""
import pytest
from app.crypto.hybrid import wrap_envelope, unwrap_envelope, wrap_nested_envelope, unwrap_nested_envelope
from app.crypto.pqc import pqc_available


PLAINTEXT  = b"Harvest report: 42 tonnes"
ALIAS      = "test-key"
TENANT     = "test-tenant-1"
VERSION    = "v1"


def test_wrap_returns_all_fields():
    """Envelope must contain all v2 required fields."""
    env = wrap_envelope(PLAINTEXT, TENANT, ALIAS, VERSION)
    required = [
        "version", "combiner", "pqc_algo", "sign_algo",
        "classical_algo", "ciphertext", "iv", "wrapped_key",
        "mlkem_pk", "mlkem_ct", "mldsa_pk", "mldsa_sig",
        "aws_wrapped_dk", "aad",
    ]
    for field in required:
        assert field in env, f"Missing envelope field: {field}"


def test_envelope_version_is_v2():
    env = wrap_envelope(PLAINTEXT, TENANT, ALIAS, VERSION)
    assert env["version"] == "v2"


def test_envelope_algorithm_labels():
    """Envelope must reference ML-KEM-768 and ML-DSA-65 per FIPS 203/204."""
    env = wrap_envelope(PLAINTEXT, TENANT, ALIAS, VERSION)
    assert env["pqc_algo"] == "ML-KEM-768"
    assert env["sign_algo"] == "ML-DSA-65"
    assert env["classical_algo"] == "AES-256-GCM"


def test_encrypt_decrypt_roundtrip():
    """Full v2 envelope encrypt → decrypt must recover plaintext exactly."""
    env       = wrap_envelope(PLAINTEXT, TENANT, ALIAS, VERSION)
    recovered = unwrap_envelope(env)
    assert recovered == PLAINTEXT


def test_different_plaintexts_produce_different_ciphertexts():
    env1 = wrap_envelope(b"message A", TENANT, ALIAS, VERSION)
    env2 = wrap_envelope(b"message B", TENANT, ALIAS, VERSION)
    assert env1["ciphertext"] != env2["ciphertext"]


def test_pqc_availability_reflected_in_envelope():
    """Envelope pqc_available field must match runtime availability."""
    env = wrap_envelope(PLAINTEXT, TENANT, ALIAS, VERSION)
    assert env["pqc_available"] == pqc_available()


def test_nested_compensating_envelope():
    """§10.6 nested envelope round-trip."""
    nested    = wrap_nested_envelope(PLAINTEXT, TENANT, ALIAS, VERSION)
    assert nested["transit_posture"] == "hybrid_compensated"
    recovered = unwrap_nested_envelope(nested)
    assert recovered == PLAINTEXT


def test_tampered_ciphertext_raises():
    """Modified ciphertext must fail decryption (AEAD authentication)."""
    import base64
    env = wrap_envelope(PLAINTEXT, TENANT, ALIAS, VERSION)
    ct  = base64.b64decode(env["ciphertext"])
    # Flip last byte
    ct_tampered        = ct[:-1] + bytes([ct[-1] ^ 0xFF])
    env["ciphertext"]  = base64.b64encode(ct_tampered).decode()
    with pytest.raises(Exception):
        unwrap_envelope(env)
