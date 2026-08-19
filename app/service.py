from __future__ import annotations

import json
import uuid
from datetime import timedelta
from typing import Any

from .crypto import HybridCrypto
from .db import Repository, iso, utc_now


def assess_risk(version: dict[str, Any], now: str | None = None) -> tuple[list[str], list[str]]:
    tags: list[str] = []
    reasons: list[str] = []
    state = version.get("state", "ACTIVE")
    classical = bool(version.get("classical_algorithm"))
    pqc = version.get("pqc_kem_algorithm") == "ML-KEM-768"
    providers = version.get("provider_count", 2)
    aws_kms_live = version.get("aws_kms_live", True)
    expired = bool(version.get("expires_at") and version["expires_at"] <= (now or iso()))
    if classical and not pqc:
        tags.append("QUANTUM_VULNERABLE")
        reasons.append("Classical protection is present without ML-KEM-768.")
    if classical and pqc and providers >= 2 and aws_kms_live:
        tags.append("HYBRID_READY")
        reasons.append("The envelope requires live AWS KMS, the Azure extension contribution, and ML-KEM-768.")
    if pqc:
        tags.append("PQC_READY")
        reasons.append("ML-KEM-768 is present; ML-DSA-65 is available for the signature demo.")
    if state in {"REVOKED", "DESTROYED"} or expired or providers < 2 or not aws_kms_live:
        tags.append("NON_COMPLIANT")
        reasons.append("The version is revoked/destroyed, expired, lacks provider coverage, or lacks live AWS KMS.")
    return list(dict.fromkeys(tags)), reasons


class KMSService:
    def __init__(self, repository: Repository, crypto: HybridCrypto, default_rotation_seconds: int):
        self.repository = repository
        self.crypto = crypto
        self.default_rotation_seconds = default_rotation_seconds

    @staticmethod
    def _deadline(seconds: int) -> str:
        return iso(utc_now() + timedelta(seconds=seconds))

    def create_key(self, alias: str, rotation_seconds: int | None = None) -> str:
        alias = alias.strip()
        if not alias or len(alias) > 80:
            raise ValueError("alias must be between 1 and 80 characters")
        interval = int(rotation_seconds or self.default_rotation_seconds)
        if interval < 10:
            raise ValueError("rotation interval must be at least 10 seconds")
        key_id = str(uuid.uuid4())
        self.repository.create_key(key_id, alias, interval, self._deadline(interval))
        try:
            self.rotate(key_id, "INITIAL_CREATE")
        except Exception:
            self.repository.delete_empty_key(key_id)
            raise
        return key_id

    def rotate(self, key_id: str, trigger: str = "MANUAL") -> int:
        key = self.repository.get_key(key_id)
        if not key:
            raise KeyError("key not found")
        interval = int(key["rotation_interval_seconds"])
        material = self.crypto.create_version_material(key_id, self._deadline(max(interval * 3, 3600)))
        return self.repository.add_version(key_id, material, self._deadline(interval), trigger)

    def rotate_due(self) -> list[tuple[str, str]]:
        outcomes: list[tuple[str, str]] = []
        for key_id in self.repository.due_key_ids(iso()):
            try:
                version = self.rotate(key_id, "SCHEDULED")
                outcomes.append((key_id, f"rotated to v{version}"))
            except Exception as exc:
                outcomes.append((key_id, f"failed: {exc}"))
        return outcomes

    def encrypt(self, key_id: str, plaintext: str, aad: str = "") -> str:
        version = self.repository.get_version(key_id)
        if not version:
            raise KeyError("active key version not found")
        return self.crypto.encrypt(version, plaintext, aad)

    def decrypt(self, encoded_envelope: str) -> str:
        from .crypto import unb64

        envelope = json.loads(unb64(encoded_envelope))
        version = self.repository.get_version(envelope["key_id"], int(envelope["key_version"]))
        if not version:
            raise KeyError("referenced immutable version not found")
        return self.crypto.decrypt(version, encoded_envelope)

    def compliance_report(self) -> dict[str, Any]:
        data = self.repository.report_data()
        counts = {tag: 0 for tag in ("QUANTUM_VULNERABLE", "HYBRID_READY", "PQC_READY", "NON_COMPLIANT")}
        violations: list[dict[str, Any]] = []
        for version in data["versions"]:
            providers = version["public_material"].get("providers", [])
            version["provider_count"] = len(providers)
            version["aws_kms_live"] = any(
                item.get("name") == "AWS KMS" and item.get("mode") == "LIVE" for item in providers
            )
            tags, reasons = assess_risk(version)
            version["risk_tags"] = tags
            version["risk_reasons"] = reasons
            for tag in tags:
                counts[tag] += 1
            if "NON_COMPLIANT" in tags or "QUANTUM_VULNERABLE" in tags:
                violations.append(
                    {"key_id": version["key_id"], "version": version["version_number"], "tags": tags, "reasons": reasons}
                )
        data["generated_at"] = iso()
        data["summary"] = {
            "keys": len(data["keys"]),
            "versions": len(data["versions"]),
            "risk_coverage": counts,
            "policy_violations": len(violations),
        }
        data["policy_violations"] = violations
        data["cloud_status"] = {
            "aws_kms": self.crypto.aws_kms.status(),
            "azure_key_vault": self.crypto.azure_kv.status(),
        }
        data["disclaimers"] = [
            "AWS KMS is live and accessed through the EC2 instance role; Azure Key Vault remains a labelled simulation/extension point.",
            "liboqs is a prototyping implementation and this demo does not claim FIPS validation.",
            "QSKMS-AWS-HYBRID-ENVELOPE/v2 and its combiner are custom, non-standardized formats.",
        ]
        return data
