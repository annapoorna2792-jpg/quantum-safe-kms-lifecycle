"""
Compliance API Router — updated for Capstone 2.
Wires to the new compliance service (RBI/PCI-DSS/DORA/NIST) and exposes
the audit log endpoint that the dashboard JS queries.
"""
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.schemas import ComplianceReportResponse, AuditLogResponse
from app.services.compliance_service import ComplianceService
from app.services.audit_service      import AuditService

router         = APIRouter()
compliance_svc = ComplianceService()
audit_svc      = AuditService()


# ── Compliance report generation ──────────────────────────────────────

@router.post("/reports/generate", response_model=ComplianceReportResponse)
def generate_report(
    standard: str = Query("FULL", description="FULL | NIST | RBI | PCI-DSS | DORA"),
    db: Session = Depends(get_db),
):
    """Generate a compliance report mapped to RBI, PCI-DSS v4, DORA, NIST SP 800-57."""
    report = compliance_svc.generate_full_report(db)
    return report


@router.get("/reports", response_model=List[ComplianceReportResponse])
def list_reports(db: Session = Depends(get_db)):
    """List the 10 most recent compliance reports."""
    return compliance_svc.get_latest_reports(db)


@router.get("/evidence")
def compliance_evidence(db: Session = Depends(get_db)):
    """JSON evidence structure (§8.5) — inventory, versions, PQC-ready, violations, frameworks."""
    return compliance_svc.compliance_evidence(db)


@router.get("/evidence/download")
def download_evidence(db: Session = Depends(get_db)):
    """Download compliance evidence as JSON attachment."""
    ev = compliance_svc.compliance_evidence(db)
    return JSONResponse(
        content=ev,
        headers={"Content-Disposition": "attachment; filename=compliance_evidence.json"},
    )


@router.get("/summary")
def compliance_summary(db: Session = Depends(get_db)):
    """Quick compliance health summary."""
    ev = compliance_svc.compliance_evidence(db)
    return {
        "inventory":          ev["inventory"],
        "total_versions":     ev["total_versions"],
        "pqc_ready_versions": ev["pqc_ready_versions"],
        "violations":         ev["violations"],
        "pqc_ready_pct":      ev["pqc_ready_pct"],
        "aws_mode":           ev["provider_panel"]["aws_kms"]["mode"],
        "azure_mode":         ev["provider_panel"]["azure_kv"]["mode"],
        "frameworks":         [f["framework"] for f in ev["frameworks"]],
    }


# ── Audit logs (used by dashboard JS /api/v1/compliance/audit) ────────

@router.get("/audit", response_model=List[AuditLogResponse])
def get_audit_logs(
    key_id: str = Query(None),
    action: str = Query(None),
    skip:   int = Query(0, ge=0),
    limit:  int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """Retrieve audit trail with optional key_id / action filters."""
    return audit_svc.get_logs(db, key_id=key_id, action=action, skip=skip, limit=limit)


@router.get("/audit/recent", response_model=List[AuditLogResponse])
def recent_audit(limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db)):
    """Return the N most recent audit events."""
    return audit_svc.get_recent_events(db, limit=limit)
