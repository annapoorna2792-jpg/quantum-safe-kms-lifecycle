"""
Dashboard API Router — aggregated stats and audit logs.
Updated for Capstone 2 to include version-level stats and quantum risk distribution.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
from app.database import get_db
from app.schemas import AuditLogResponse
from app.models import CryptographicKey, KeyVersion, KeyStatus, QuantumRiskTag
from app.services.audit_service     import AuditService
from app.services.rotation_scheduler import RotationScheduler
from app.crypto.pqc import pqc_available
import app.crypto.aws_kms as aws_kms_adapter
import app.kms_providers.azure_kv_sim as azure_adapter

router       = APIRouter()
audit_svc    = AuditService()
rotation_svc = RotationScheduler()


@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Return aggregated stats including version-level quantum risk distribution."""
    keys     = db.query(CryptographicKey).all()
    versions = db.query(KeyVersion).all()
    now      = datetime.utcnow()

    total        = len(keys)
    active_keys  = sum(1 for k in keys if k.status == "active")
    q_safe       = sum(1 for k in keys if k.is_quantum_safe)
    hybrid_keys  = sum(1 for k in keys if k.is_hybrid)
    due_rotation = sum(1 for k in keys if k.rotation_due_at and k.rotation_due_at < now and k.status == "active")
    expired      = sum(1 for k in keys if k.status == "expired")
    revoked      = sum(1 for k in keys if k.status == "revoked")

    # Version stats
    total_v  = len(versions)
    pqc_v    = sum(1 for v in versions if v.quantum_risk_tag == QuantumRiskTag.HYBRID_READY)
    risk_dist_v = {t.value: sum(1 for v in versions if v.quantum_risk_tag == t) for t in QuantumRiskTag}

    risk_dist    = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    algo_dist: dict = {}
    prov_dist: dict = {}

    for k in keys:
        risk_dist[k.risk_level] = risk_dist.get(k.risk_level, 0) + 1
        algo_dist[k.algorithm]  = algo_dist.get(k.algorithm, 0) + 1
        prov_dist[k.kms_provider] = prov_dist.get(k.kms_provider, 0) + 1

    pqc_pct = round(pqc_v / total_v * 100, 1) if total_v > 0 else 100.0

    return {
        "total_keys":            total,
        "active_keys":           active_keys,
        "quantum_safe_keys":     q_safe,
        "hybrid_keys":           hybrid_keys,
        "keys_due_rotation":     due_rotation,
        "keys_expired":          expired,
        "keys_revoked":          revoked,
        "total_versions":        total_v,
        "pqc_ready_versions":    pqc_v,
        "violations":            0,
        "risk_distribution":     risk_dist,
        "algorithm_distribution": algo_dist,
        "provider_distribution": prov_dist,
        "compliance_score":      pqc_pct,
        "recent_audit_events":   audit_svc.count_events(db),
        "quantum_risk_distribution": risk_dist_v,
        "aws_mode":              aws_kms_adapter.provider_mode(),
        "azure_mode":            azure_adapter.provider_mode(),
        "pqc_available":         pqc_available(),
    }


@router.get("/audit-logs", response_model=List[AuditLogResponse])
def get_audit_logs(
    key_id: str = Query(None),
    action: str = Query(None),
    skip:   int = Query(0, ge=0),
    limit:  int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """Retrieve audit trail."""
    return audit_svc.get_logs(db, key_id=key_id, action=action, skip=skip, limit=limit)


@router.get("/rotation-status")
def rotation_status(db: Session = Depends(get_db)):
    return rotation_svc.rotation_status_report(db)


@router.post("/rotation/run")
def trigger_rotation(db: Session = Depends(get_db)):
    from app.services.rotation_scheduler import run_rotation_pass
    return run_rotation_pass(db)
