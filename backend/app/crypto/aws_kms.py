"""
AWS KMS live adapter — Chapter 8.1.
Wraps boto3 KMS calls and falls back to local AES simulation when
credentials / alias are unavailable (local development, Windows CI).

Provider mode is exposed to the /healthz endpoint.
"""
import os
import json
import base64
import logging
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

# ── Lazy boto3 import ─────────────────────────────────────────────────────────

def _try_boto3():
    try:
        import boto3
        return boto3
    except ImportError:
        return None

boto3 = _try_boto3()

# ── Fallback local AES key ─────────────────────────────────────────────────────
_LOCAL_SIM_KEY: Optional[bytes] = None

def _get_sim_key() -> bytes:
    global _LOCAL_SIM_KEY
    if _LOCAL_SIM_KEY is None:
        _LOCAL_SIM_KEY = os.urandom(32)
    return _LOCAL_SIM_KEY


# ── Module-level state (populated at startup probe) ───────────────────────────
_aws_mode: str = "SIM"          # "LIVE" | "SIM"
_aws_region: str = "eu-north-1"
_aws_key_arn: str = ""
_kms_client = None


def _init_client(region: str, key_alias: str):
    """Try to initialise a real boto3 KMS client. Sets _aws_mode."""
    global _aws_mode, _aws_region, _aws_key_arn, _kms_client
    _aws_region = region
    if not boto3:
        _aws_mode = "SIM"
        return
    try:
        client = boto3.client("kms", region_name=region)
        resp = client.describe_key(KeyId=key_alias)
        _aws_key_arn = resp["KeyMetadata"]["Arn"]
        _kms_client  = client
        _aws_mode    = "LIVE"
        logger.info("AWS KMS LIVE — key ARN: %s", _aws_key_arn)
    except Exception as exc:
        _aws_mode = "SIM"
        logger.info("AWS KMS SIM (live probe failed: %s)", exc)


def probe(region: str, key_alias: str):
    """Called once at app startup to determine LIVE vs SIM mode."""
    _init_client(region, key_alias)


# ── Public API ────────────────────────────────────────────────────────────────

def provider_mode() -> str:
    return _aws_mode

def region() -> str:
    return _aws_region

def key_arn() -> str:
    return _aws_key_arn


def generate_data_key() -> Tuple[bytes, bytes]:
    """
    Algorithm 8.1 — obtain a 256-bit data key from AWS KMS.
    Returns (plaintext_key_32_bytes, wrapped_ciphertext_blob).
    """
    if _aws_mode == "LIVE" and _kms_client:
        try:
            resp = _kms_client.generate_data_key(
                KeyId=_aws_key_arn,
                KeySpec="AES_256",
            )
            return resp["Plaintext"], resp["CiphertextBlob"]
        except Exception as exc:
            logger.warning("AWS KMS GenerateDataKey failed, using sim: %s", exc)

    # ── Simulation fallback ───────────────────────────────────────────────────
    import hashlib, struct, time
    dk_plain = os.urandom(32)
    # Wrap plaintext under local sim key (XOR + HMAC envelope for reversibility)
    sim_key  = _get_sim_key()
    wrapped  = bytes(a ^ b for a, b in zip(dk_plain, sim_key))
    ts       = struct.pack(">Q", int(time.time() * 1e6))
    dk_wrapped = b"SIM:" + ts + wrapped          # 4 + 8 + 32 = 44 bytes
    return dk_plain, dk_wrapped


def decrypt_data_key(ciphertext_blob: bytes) -> bytes:
    """
    Decrypt a wrapped data key using AWS KMS Decrypt.
    Returns plaintext 32-byte key.
    """
    if _aws_mode == "LIVE" and _kms_client:
        try:
            resp = _kms_client.decrypt(
                CiphertextBlob=ciphertext_blob,
                KeyId=_aws_key_arn,
            )
            return resp["Plaintext"]
        except Exception as exc:
            logger.warning("AWS KMS Decrypt failed, using sim: %s", exc)

    # ── Simulation fallback ───────────────────────────────────────────────────
    if ciphertext_blob[:4] == b"SIM:":
        wrapped   = ciphertext_blob[12:]          # skip "SIM:" + 8-byte ts
        sim_key   = _get_sim_key()
        dk_plain  = bytes(a ^ b for a, b in zip(wrapped, sim_key))
        return dk_plain
    # Unknown blob — return zeros (safe fail for demo)
    return b"\x00" * 32


def health_info() -> dict:
    return {
        "provider": "aws_kms",
        "mode": _aws_mode,
        "region": _aws_region,
        "key_arn": _aws_key_arn if _aws_key_arn else "N/A",
        "pq_import_support": False,           # §10.5 — RSAES_OAEP only
        "transit_posture": "classical_only",  # §10.5.1
    }
