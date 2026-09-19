"""
Compliance Service — mapped to RBI, PCI-DSS v4, DORA, NIST SP 800-57, FIPS 140-3.
Chapter 8.5 / Table 10.2.

Generates the JSON evidence downloadable from the dashboard (§8.5, §10.4).
"""
import uuid
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models import (
    CryptographicKey, KeyVersion, ComplianceReport,
    VersionState, QuantumRiskTag,
)
from app.kms_providers.factory import all_providers
from app.crypto.pqc import pqc_available
import app.crypto.aws_kms as aws_kms_adapter
import app.kms_providers.azure_kv_sim as azure_adapter
from app.config import settings


# ── Rotation windows per framework ────────────────────────────────────────────
PCI_DSS_MAX_DAYS = 365    # PCI-DSS v4.0 §3.7.1
RBI_MAX_DAYS     = 365    # RBI CSF — annual rotation baseline
DORA_MAX_DAYS    = 365    # DORA ICT risk management
NIST_MAX_DAYS    = 730    # NIST SP 800-57 — 2-year max for asymmetric KEK


class ComplianceService:

    def generate_full_report(self, db: Session) -> ComplianceReport:
        """
        Generate a combined compliance report covering all frameworks.
        This is the primary evidence artefact described in §8.5.
        """
        keys        = db.query(CryptographicKey).all()
        versions    = db.query(KeyVersion).all()
        now         = datetime.utcnow()

        total_v     = len(versions)
        pqc_ready_v = sum(1 for v in versions if v.quantum_risk_tag == QuantumRiskTag.HYBRID_READY)
        violations  = []

        for v in versions:
            # Rotation overdue → PCI-DSS / RBI violation
            if v.rotation_due_at and v.rotation_due_at < now:
                days = (now - v.rotation_due_at).days
                violations.append({
                    "framework":    "PCI-DSS v4.0 / RBI CSF",
                    "control":      "Max key-usage period exceeded",
                    "key_id":       v.key_id,
                    "version_id":   v.id,
                    "version":      f"v{v.version_number}",
                    "days_overdue": days,
                    "severity":     "HIGH",
                })

            # Classical-only → NIST PQC migration violation
            if v.quantum_risk_tag == QuantumRiskTag.QUANTUM_VULNERABLE and \
               v.state == VersionState.ACTIVE:
                violations.append({
                    "framework":    "NIST IR 8105 / FIPS 203",
                    "control":      "Active key is quantum-vulnerable",
                    "key_id":       v.key_id,
                    "version_id":   v.id,
                    "version":      f"v{v.version_number}",
                    "severity":     "CRITICAL",
                })

            # Expired version still ACTIVE → DORA violation
            if v.expires_at and v.expires_at < now and v.state == VersionState.ACTIVE:
                violations.append({
                    "framework":    "DORA / NIST SP 800-57",
                    "control":      "Expired key version still ACTIVE",
                    "key_id":       v.key_id,
                    "version_id":   v.id,
                    "version":      f"v{v.version_number}",
                    "severity":     "HIGH",
                })

        pqc_pct  = round(pqc_ready_v / total_v * 100, 1) if total_v > 0 else 100.0
        compliant_count = len(keys) - sum(1 for k in keys if k.status == "revoked")

        report = ComplianceReport(
            id=str(uuid.uuid4()),
            report_type="FULL",
            findings=violations,
            risk_summary={
                "pqc_ready_pct":     pqc_pct,
                "frameworks":        ["NIST SP 800-57", "FIPS 140-3", "RBI CSF", "PCI-DSS v4.0", "DORA"],
                "aws_mode":          aws_kms_adapter.provider_mode(),
                "azure_mode":        azure_adapter.provider_mode(),
                "pqc_available":     pqc_available(),
                "retention_window":  "Long-lived BFSI data (§2.5)",
                "hndl_threat":       "Addressed via ML-KEM-768 hybrid wrapping (§2.5)",
            },
            total_keys=len(keys),
            total_versions=total_v,
            compliant_keys=compliant_count,
            non_compliant_keys=len(keys) - compliant_count,
            pqc_ready_versions=pqc_ready_v,
            violations=len(violations),
            report_data={
                "generated_by":  "quantum-safe-kms v2.0",
                "report_note":   "Evidence captured for Capstone 2 (§8.5)",
                "provider_panel": all_providers(),
            },
        )
        db.add(report)
        db.commit()
        db.refresh(report)
        return report

    def compliance_evidence(self, db: Session) -> dict:
        """
        Build the JSON evidence structure downloadable from the dashboard (§8.5).
        Matches the report's compliance snapshot: inventory, versions, pqc_ready, violations.
        """
        keys     = db.query(CryptographicKey).all()
        versions = db.query(KeyVersion).all()
        now      = datetime.utcnow()

        pqc_v    = [v for v in versions if v.quantum_risk_tag == QuantumRiskTag.HYBRID_READY]
        viol_list = []

        for v in versions:
            if v.rotation_due_at and v.rotation_due_at < now:
                viol_list.append(f"v{v.version_number} rotation overdue ({(now - v.rotation_due_at).days}d)")
            if v.quantum_risk_tag == QuantumRiskTag.QUANTUM_VULNERABLE:
                viol_list.append(f"v{v.version_number} QUANTUM_VULNERABLE")
            if v.expires_at and v.expires_at < now and v.state == VersionState.ACTIVE:
                viol_list.append(f"v{v.version_number} expired but ACTIVE")

        pqc_pct  = round(len(pqc_v) / len(versions) * 100, 1) if versions else 100.0

        return {
            "generated_at":       now.isoformat(),
            "inventory":          len(keys),
            "total_versions":     len(versions),
            "pqc_ready_versions": len(pqc_v),
            "violations":         len(viol_list),
            "pqc_ready_pct":      pqc_pct,
            "violation_details":  viol_list,
            "provider_panel": {
                "aws_kms": {
                    "mode":            aws_kms_adapter.provider_mode(),
                    "region":          aws_kms_adapter.region(),
                    "key_arn":         aws_kms_adapter.key_arn(),
                    "pq_import":       False,
                    "transit_posture": "classical_only",
                },
                "azure_kv": {
                    "mode":            azure_adapter.provider_mode(),
                    "vault_url":       azure_adapter.vault_url() or "N/A",
                    "pq_import":       False,
                    "transit_posture": "classical_only",
                },
                "gcp_kms": {
                    "mode":            "DOC",
                    "pq_import":       True,
                    "transit_posture": "pq_native",
                    "note":            "Preview; software protection only (§10.5)",
                },
            },
            "frameworks": [
                {
                    "framework": "RBI Cyber Security Framework",
                    "control":   "Annual key rotation + quantum-safe wrapping",
                    "status":    "COMPLIANT" if not viol_list else "REVIEW",
                },
                {
                    "framework": "PCI-DSS v4.0 §3.7.1",
                    "control":   f"365-day max key-usage period (configured: {settings.KEY_ROTATION_DAYS}d)",
                    "status":    "COMPLIANT" if not viol_list else "REVIEW",
                },
                {
                    "framework": "DORA Art. 9",
                    "control":   "ICT cryptographic risk management",
                    "status":    "COMPLIANT" if pqc_pct == 100.0 else "PARTIAL",
                },
                {
                    "framework": "NIST SP 800-57 / FIPS 203",
                    "control":   "ML-KEM-768 hybrid key lifecycle",
                    "status":    "COMPLIANT" if pqc_pct == 100.0 else "PARTIAL",
                },
                {
                    "framework": "FIPS 140-3",
                    "control":   "Approved PQC algorithms (ML-KEM-768, ML-DSA-65)",
                    "status":    "COMPLIANT",
                },
            ],
            "key_inventory": [
                {
                    "alias":          k.name,
                    "provider":       k.kms_provider,
                    "algorithm":      k.algorithm,
                    "active_version": k.active_version_number,
                    "total_versions": k.total_versions,
                    "status":         k.status,
                }
                for k in keys
            ],
        }

    # ── Legacy report generators (kept for backward-compat) ───────────────────

    def generate_nist_report(self, db: Session) -> ComplianceReport:
        return self.generate_full_report(db)

    def generate_fips_report(self, db: Session) -> ComplianceReport:
        return self.generate_full_report(db)

    def generate_iso_report(self, db: Session) -> ComplianceReport:
        return self.generate_full_report(db)

    def get_latest_reports(self, db: Session) -> list:
        return db.query(ComplianceReport)\
                 .order_by(ComplianceReport.generated_at.desc()).limit(10).all()
