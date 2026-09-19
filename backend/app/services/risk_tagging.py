"""
Risk Tagging Service — per-version quantum-risk classification.
Algorithm 8.4 (Chapter 8.4) and §10.4.

Four tags:
  QUANTUM_VULNERABLE  — classical-only, no ML-KEM
  HYBRID_READY        — classical + ML-KEM-768 + live provider coverage
  PQC_READY           — ML-KEM-768 as primary (combined with HYBRID_READY in report)
  NON_COMPLIANT       — revoked/destroyed/expired/provider-deficient
"""
from datetime import datetime
from sqlalchemy.orm import Session
from app.models import CryptographicKey, KeyVersion, VersionState, QuantumRiskTag, RiskLevel

# Sets for legacy key-level tagging
QUANTUM_VULNERABLE = {"RSA-4096", "ECC-P521", "RSA-2048", "ECC-P256", "ECC-P384"}
WEAK_CLASSICAL     = {"AES-128", "3DES"}
QUANTUM_SAFE       = {
    "ML-KEM-768", "ML-DSA-65", "SLH-DSA",
    "KYBER-1024",  # legacy alias
    "DILITHIUM-5", # legacy alias
    "SPHINCS+",
    "HYBRID-ML-KEM-768-AES-256-GCM",
    "HYBRID-KYBER-AES",
    "HYBRID-DILITHIUM-RSA",
}


class RiskTaggingService:

    def assess_version_risk(self, version: KeyVersion) -> QuantumRiskTag:
        """Per-version risk classification (Algorithm 8.4)."""
        now = datetime.utcnow()

        # NON_COMPLIANT conditions
        if version.state in (VersionState.REVOKED, VersionState.DESTROYED):
            return QuantumRiskTag.NON_COMPLIANT
        if version.expires_at and version.expires_at < now:
            return QuantumRiskTag.NON_COMPLIANT
        if not version.providers:
            return QuantumRiskTag.NON_COMPLIANT

        pqc = (version.pqc_algorithm or "").upper()
        has_pqc = "ML-KEM" in pqc or "KYBER" in pqc

        if not has_pqc:
            return QuantumRiskTag.QUANTUM_VULNERABLE

        # ML-KEM present → HYBRID_READY (report uses HYBRID_READY + PQC_READY together)
        return QuantumRiskTag.HYBRID_READY

    def tag_all_versions(self, db: Session) -> dict:
        """Re-evaluate risk tags for all key versions. Returns summary."""
        versions = db.query(KeyVersion).all()
        summary  = {t.value: 0 for t in QuantumRiskTag}
        for v in versions:
            tag       = self.assess_version_risk(v)
            v.quantum_risk_tag = tag
            summary[tag.value] += 1
        db.commit()
        return {"versions_evaluated": len(versions), "distribution": summary}

    # ── Legacy key-level risk (for old dashboard compatibility) ───────────────

    def evaluate_key_risk(self, key: CryptographicKey) -> RiskLevel:
        now        = datetime.utcnow()
        risk_score = 0

        if key.algorithm in QUANTUM_VULNERABLE:
            risk_score += 40
        elif key.algorithm in WEAK_CLASSICAL:
            risk_score += 60
        elif key.algorithm in QUANTUM_SAFE:
            risk_score += 0

        if key.rotation_due_at and key.rotation_due_at < now:
            days = (now - key.rotation_due_at).days
            risk_score += min(days * 2, 30)

        age = (now - key.created_at).days
        if age > 365:
            risk_score += 20
        elif age > 180:
            risk_score += 10

        if key.rotation_count == 0 and age > 30:
            risk_score += 10

        if key.expires_at:
            days_left = (key.expires_at - now).days
            if days_left < 7:
                risk_score += 25
            elif days_left < 30:
                risk_score += 10

        if risk_score >= 60:
            return RiskLevel.CRITICAL
        elif risk_score >= 40:
            return RiskLevel.HIGH
        elif risk_score >= 20:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def tag_all_keys(self, db: Session) -> dict:
        keys    = db.query(CryptographicKey).all()
        summary = {level.value: 0 for level in RiskLevel}
        for key in keys:
            new_risk       = self.evaluate_key_risk(key)
            key.risk_level = new_risk.value
            summary[new_risk.value] += 1
        db.commit()
        return {"keys_evaluated": len(keys), "risk_distribution": summary}

    def get_high_risk_keys(self, db: Session) -> list:
        return db.query(CryptographicKey)\
                 .filter(CryptographicKey.risk_level.in_(["high", "critical"])).all()

    def quantum_vulnerable_keys(self, db: Session) -> list:
        return db.query(CryptographicKey)\
                 .filter(CryptographicKey.algorithm.in_(list(QUANTUM_VULNERABLE))).all()
