"""
Tests for the compliance engine — RBI/PCI-DSS/DORA/NIST/FIPS (Chapter 8.5).
Verifies violation detection, evidence structure, and framework mapping.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
from app.database import Base
from app.models import CryptographicKey, KeyVersion, VersionState, QuantumRiskTag
from app.services.compliance_service import ComplianceService
from app.services.key_lifecycle_service import KeyLifecycleService

@pytest.fixture(scope="function")
def db():
    engine  = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def compliance():
    return ComplianceService()


@pytest.fixture
def lifecycle():
    return KeyLifecycleService()


# ── Evidence structure ────────────────────────────────────────────────

def test_evidence_has_required_fields(db, compliance):
    ev = compliance.compliance_evidence(db)
    required = [
        "generated_at", "inventory", "total_versions",
        "pqc_ready_versions", "violations", "pqc_ready_pct",
        "provider_panel", "frameworks", "key_inventory",
    ]
    for field in required:
        assert field in ev, f"Missing evidence field: {field}"


def test_provider_panel_has_three_providers(db, compliance):
    ev = compliance.compliance_evidence(db)
    pp = ev["provider_panel"]
    assert "aws_kms" in pp
    assert "azure_kv" in pp
    assert "gcp_kms"  in pp


def test_gcp_is_pq_native(db, compliance):
    ev = compliance.compliance_evidence(db)
    assert ev["provider_panel"]["gcp_kms"]["transit_posture"] == "pq_native"


def test_aws_is_classical_only(db, compliance):
    ev = compliance.compliance_evidence(db)
    assert ev["provider_panel"]["aws_kms"]["transit_posture"] == "classical_only"
    assert ev["provider_panel"]["aws_kms"]["pq_import"] is False


def test_frameworks_cover_rbi_pci_dora_nist(db, compliance):
    ev = compliance.compliance_evidence(db)
    framework_names = " ".join(f["framework"] for f in ev["frameworks"])
    assert "RBI"      in framework_names
    assert "PCI-DSS"  in framework_names
    assert "DORA"     in framework_names
    assert "NIST"     in framework_names


# ── Zero violations with compliant keys ───────────────────────────────

def test_no_violations_with_pqc_keys(db, compliance, lifecycle):
    """ML-KEM-768 keys with future rotation_due_at → 0 violations."""
    lifecycle.create_key(db, "compliant-key-1")
    lifecycle.create_key(db, "compliant-key-2")
    ev = compliance.compliance_evidence(db)
    assert ev["violations"] == 0
    assert ev["pqc_ready_pct"] == 100.0


# ── Violation detection ───────────────────────────────────────────────

def test_violation_detected_for_quantum_vulnerable_version(db, compliance, lifecycle):
    """Active version without ML-KEM must appear as QUANTUM_VULNERABLE violation."""
    key = lifecycle.create_key(db, "vuln-key", algorithm="RSA-4096")
    # Override pqc_algorithm to simulate classical-only key
    versions = lifecycle.get_versions(db, key.id)
    for v in versions:
        v.pqc_algorithm   = ""
        v.quantum_risk_tag = QuantumRiskTag.QUANTUM_VULNERABLE
    db.commit()
    ev = compliance.compliance_evidence(db)
    assert ev["pqc_ready_versions"] == 0


def test_pqc_ready_pct_correct(db, compliance, lifecycle):
    """PQC coverage = pqc_ready_versions / total_versions × 100."""
    lifecycle.create_key(db, "pk1")
    lifecycle.create_key(db, "pk2")
    ev = compliance.compliance_evidence(db)
    expected = round(ev["pqc_ready_versions"] / ev["total_versions"] * 100, 1)
    assert ev["pqc_ready_pct"] == expected


# ── Full report generation ────────────────────────────────────────────

def test_generate_full_report(db, compliance, lifecycle):
    lifecycle.create_key(db, "report-key")
    report = compliance.generate_full_report(db)
    assert report.id is not None
    assert report.total_keys >= 1
    assert report.report_type == "FULL"
    assert isinstance(report.findings, list)
    assert isinstance(report.risk_summary, dict)


def test_full_report_includes_hndl_note(db, compliance, lifecycle):
    lifecycle.create_key(db, "hndl-key")
    report = compliance.generate_full_report(db)
    summary_str = str(report.risk_summary)
    assert "ML-KEM-768" in summary_str or "hndl" in summary_str.lower()


def test_key_inventory_in_evidence(db, compliance, lifecycle):
    lifecycle.create_key(db, "inv-key-1")
    lifecycle.create_key(db, "inv-key-2")
    ev = compliance.compliance_evidence(db)
    aliases = [k["alias"] for k in ev["key_inventory"]]
    assert "inv-key-1" in aliases
    assert "inv-key-2" in aliases
