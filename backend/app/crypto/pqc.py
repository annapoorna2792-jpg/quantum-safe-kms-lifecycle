"""
Post-Quantum Cryptography — ML-KEM-768 and ML-DSA-65
FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) via liboqs/pyoqs.

Security level: NIST Level 3 (comparable to AES-192) for ML-KEM-768.
Falls back to a deterministic simulation when liboqs is unavailable (Windows).
"""
import os
import base64
import hashlib
import hmac as _hmac
from typing import Tuple, Optional


# ── liboqs import ─────────────────────────────────────────────────────────────

def _try_import_oqs():
    try:
        import oqs
        return oqs
    except ImportError:
        return None


OQS = _try_import_oqs()


def pqc_available() -> bool:
    """Return True when real liboqs operations are available."""
    return OQS is not None


# ── ML-KEM-768 (FIPS 203, replaces CRYSTALS-Kyber) ───────────────────────────

class MLKEM768:
    """
    Module-Lattice-Based Key Encapsulation Mechanism, 768-bit variant.
    Targets NIST Security Level 3 (≈ AES-192).
    Used in Chapter 8.2 (v2 hybrid combiner) and throughout the report.
    """
    ALGORITHM = "ML-KEM-768"
    OQS_NAME  = "ML-KEM-768"          # liboqs algorithm name
    NIST_STANDARD = "FIPS 203"
    SECURITY_LEVEL = 3                 # NIST PQC Level 3

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """Returns (public_key, secret_key)."""
        if OQS:
            with OQS.KeyEncapsulation(MLKEM768.OQS_NAME) as kem:
                public_key = kem.generate_keypair()
                secret_key = kem.export_secret_key()
                return public_key, secret_key
        # ── Simulation fallback ──────────────────────────────────────────────
        # pk[:64] is deterministically derived from sk so decapsulate can re-derive it.
        secret_key = os.urandom(64)
        pk_prefix  = hashlib.sha3_512(secret_key).digest()[:64]  # 64 bytes
        public_key = pk_prefix + os.urandom(1184 - 64)
        return public_key, secret_key

    @staticmethod
    def encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
        """Returns (ciphertext, shared_secret_32_bytes)."""
        if OQS:
            with OQS.KeyEncapsulation(MLKEM768.OQS_NAME) as kem:
                ciphertext, shared_secret = kem.encap_secret(public_key)
                return ciphertext, shared_secret
        # ── Simulation fallback ──────────────────────────────────────────────
        # ss = random 32 bytes.  We XOR-wrap it under HKDF(pk_prefix, nonce)
        # so that decapsulate(sk, ct) can recover it using sk→pk_prefix.
        # Layout: ct = nonce(32) | wrapped_ss(32) | padding(1024)
        ss     = os.urandom(32)
        nonce  = os.urandom(32)
        mask   = hashlib.sha3_256(public_key[:64] + nonce).digest()   # 32 bytes
        wrapped = bytes(a ^ b for a, b in zip(ss, mask))
        ciphertext = nonce + wrapped + os.urandom(1088 - 64)
        return ciphertext, ss

    @staticmethod
    def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
        """Returns shared_secret."""
        if OQS:
            with OQS.KeyEncapsulation(MLKEM768.OQS_NAME, secret_key=secret_key) as kem:
                return kem.decap_secret(ciphertext)
        # ── Simulation fallback ──────────────────────────────────────────────
        # Re-derive the pk prefix from sk (same derivation used in generate_keypair).
        pk_prefix = hashlib.sha3_512(secret_key).digest()[:64]
        nonce     = ciphertext[:32]
        wrapped   = ciphertext[32:64]
        mask      = hashlib.sha3_256(pk_prefix + nonce).digest()
        return bytes(a ^ b for a, b in zip(wrapped, mask))

    @staticmethod
    def key_info() -> dict:
        return {
            "algorithm": "ML-KEM-768",
            "nist_standard": "FIPS 203",
            "security_level": "NIST Level 3 (≈ AES-192)",
            "quantum_safe": True,
            "public_key_bytes": 1184,
            "ciphertext_bytes": 1088,
            "shared_secret_bytes": 32,
            "simulated": not pqc_available(),
        }


# ── ML-DSA-65 (FIPS 204, replaces CRYSTALS-Dilithium) ────────────────────────

class MLDSA65:
    """
    Module-Lattice-Based Digital Signature Algorithm, 65-bit variant.
    Provides PQC signing of envelope headers (Chapter 8.2).
    """
    ALGORITHM = "ML-DSA-65"
    OQS_NAME  = "ML-DSA-65"
    NIST_STANDARD = "FIPS 204"
    SECURITY_LEVEL = 3

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        if OQS:
            with OQS.Signature(MLDSA65.OQS_NAME) as sig:
                public_key = sig.generate_keypair()
                secret_key = sig.export_secret_key()
                return public_key, secret_key
        secret_key = os.urandom(64)
        public_key = hashlib.sha3_512(secret_key).digest() + os.urandom(1952 - 64)
        return public_key, secret_key

    @staticmethod
    def sign(secret_key: bytes, message: bytes) -> bytes:
        if OQS:
            with OQS.Signature(MLDSA65.OQS_NAME, secret_key=secret_key) as sig:
                return sig.sign(message)
        return _hmac.new(secret_key[:64], message, hashlib.sha3_512).digest() + os.urandom(3293 - 64)

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        if OQS:
            with OQS.Signature(MLDSA65.OQS_NAME) as sig:
                return sig.verify(message, signature, public_key)
        return True  # simulation: always valid

    @staticmethod
    def key_info() -> dict:
        return {
            "algorithm": "ML-DSA-65",
            "nist_standard": "FIPS 204",
            "security_level": "NIST Level 3",
            "quantum_safe": True,
            "public_key_bytes": 1952,
            "signature_bytes": 3293,
            "simulated": not pqc_available(),
        }


# ── SLH-DSA / SPHINCS+ (FIPS 205 — hash-based fallback) ─────────────────────

class SLHDSA:
    """
    Stateless Hash-Based Digital Signature (FIPS 205).
    Conservative fallback where lattice assumptions alone are insufficient.
    """
    ALGORITHM  = "SLH-DSA-SHA2-128s"
    OQS_NAME   = "SPHINCS+-SHA2-128s-simple"
    NIST_STANDARD = "FIPS 205"

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        if OQS:
            with OQS.Signature(SLHDSA.OQS_NAME) as sig:
                public_key = sig.generate_keypair()
                secret_key = sig.export_secret_key()
                return public_key, secret_key
        secret_key = os.urandom(32)
        public_key = hashlib.sha256(secret_key).digest() + os.urandom(32)
        return public_key, secret_key

    @staticmethod
    def sign(secret_key: bytes, message: bytes) -> bytes:
        if OQS:
            with OQS.Signature(SLHDSA.OQS_NAME, secret_key=secret_key) as sig:
                return sig.sign(message)
        return hashlib.sha256(secret_key + message).digest() + os.urandom(7856 - 32)

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        if OQS:
            with OQS.Signature(SLHDSA.OQS_NAME) as sig:
                return sig.verify(message, signature, public_key)
        return True

    @staticmethod
    def key_info() -> dict:
        return {
            "algorithm": "SLH-DSA-SHA2-128s",
            "nist_standard": "FIPS 205",
            "security_level": "NIST Level 1 (hash-based)",
            "quantum_safe": True,
            "simulated": not pqc_available(),
        }


# ── Backward-compat aliases (kept so existing imports don't break) ─────────────
KyberKEM     = MLKEM768
DilithiumDSA = MLDSA65
SPHINCSPlus  = SLHDSA
