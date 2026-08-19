from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database_path: Path
    master_key: bytes
    rotation_seconds: int
    scheduler_enabled: bool
    aws_region: str
    aws_kms_key_id: str

    @classmethod
    def from_env(cls) -> "Settings":
        raw_key = os.getenv("DEMO_MASTER_KEY")
        if not raw_key:
            raise RuntimeError(
                "DEMO_MASTER_KEY is required; generate one with: "
                "python -c \"import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())\""
            )
        try:
            master_key = base64.b64decode(raw_key.encode(), altchars=b"-_", validate=True)
        except Exception as exc:
            raise RuntimeError("DEMO_MASTER_KEY must be URL-safe base64") from exc
        if len(master_key) != 32:
            raise RuntimeError("DEMO_MASTER_KEY must decode to exactly 32 bytes")

        rotation_seconds = int(os.getenv("ROTATION_INTERVAL_SECONDS", "120"))
        if rotation_seconds < 10:
            raise RuntimeError("ROTATION_INTERVAL_SECONDS must be at least 10")
        database_path = Path(os.getenv("DATABASE_PATH", "data/quantum_safe_kms.db"))
        aws_region = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "eu-north-1")).strip()
        aws_kms_key_id = os.getenv("AWS_KMS_KEY_ID", "alias/quantum-safe-kms-demo").strip()
        if not aws_region:
            raise RuntimeError("AWS_REGION is required")
        if not aws_kms_key_id:
            raise RuntimeError("AWS_KMS_KEY_ID is required")
        return cls(
            database_path=database_path,
            master_key=master_key,
            rotation_seconds=rotation_seconds,
            scheduler_enabled=os.getenv("SCHEDULER_ENABLED", "true").lower() in {"1", "true", "yes"},
            aws_region=aws_region,
            aws_kms_key_id=aws_kms_key_id,
        )
