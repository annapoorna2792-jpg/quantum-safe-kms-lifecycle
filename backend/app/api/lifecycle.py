"""
Lifecycle API Router — full Capstone 2 key lifecycle endpoints.
Chapter 8: create, rotate, revoke, destroy, encrypt, decrypt.
Chapter 8.5: compliance evidence and JSON download.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from app.database import get_db
from app.schemas import (
    KeyCreateRequest, KeyResponse, KeyDetailResponse, KeyVersionResponse,
    KeyRotateRequest, KeyRevokeRequest,
    EncryptRequest, EncryptResponse, DecryptRequest, DecryptResponse,
    ComplianceEvidenceResponse,
)
from app.services.key_lifecycle_service import KeyLifecycleService
from app.services.compliance_service    import ComplianceService
from app.services.rotation_scheduler   import run_rotation_pass, rotation_status_report, scheduler_status

router    = APIRouter()
lifecycle = KeyLifecycleService()
compliance_svc = ComplianceService()


# ── Key creation ──────────────────────────────────────────────────────────────

@router.post("/keys", response_model=KeyResponse, status_code=201)
def create_key(request: KeyCreateRequest, db: Session = Depends(get_db)):
    """Create a logical key + v1 ACTIVE version with hybrid ML-KEM-768 protection."""
    try:
        key = lifecycle.create_key(
            db=db, name=request.name,
            algorithm=request.algorithm,
            kms_provider=request.kms_provider,
            owner=request.owner, environment=request.environment,
            purpose=request.purpose, tags=request.tags,
            rotation_days=request.rotation_days,
        )
        return key
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Key listing / detail ──────────────────────────────────────────────────────

@router.get("/keys", response_model=List[KeyResponse])
def list_keys(
    status:   Optional[str] = Query(None),
    algorithm: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    skip:     int = Query(0, ge=0),
    limit:    int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """List all logical keys with their active version info."""
    return lifecycle.list_keys(db, status=status, algorithm=algorithm,
                               provider=provider, skip=skip, limit=limit)


@router.get("/keys/{key_id}", response_model=KeyDetailResponse)
def get_key(key_id: str, db: Session = Depends(get_db)):
    """Get key detail including all immutable versions."""
    try:
        key = lifecycle.get_key(db, key_id)
        return key
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/keys/by-name/{alias}", response_model=KeyDetailResponse)
def get_key_by_name(alias: str, db: Session = Depends(get_db)):
    """Get key by alias (e.g. 'customer-data')."""
    try:
        return lifecycle.get_key_by_name(db, alias)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ── Version history ───────────────────────────────────────────────────────────

@router.get("/keys/{key_id}/versions", response_model=List[KeyVersionResponse])
def list_versions(key_id: str, db: Session = Depends(get_db)):
    """List all immutable versions for a key (v1…vN)."""
    try:
        lifecycle.get_key(db, key_id)  # validate key exists
        return lifecycle.get_versions(db, key_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ── Rotation (Algorithm 8.3) ──────────────────────────────────────────────────

@router.post("/keys/{key_id}/rotate", response_model=KeyResponse)
def rotate_key(key_id: str, request: KeyRotateRequest, db: Session = Depends(get_db)):
    """
    Manual rotation — create a new immutable version, retire the old one.
    Implements Algorithm 8.3.
    """
    try:
        return lifecycle.rotate_key(db, key_id, reason=request.reason or "Manual rotation")
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/rotate-now")
def rotate_now(db: Session = Depends(get_db)):
    """Trigger an immediate rotation pass for all overdue keys."""
    results = run_rotation_pass(db)
    return {"triggered_at": datetime.utcnow().isoformat(), **results}


@router.get("/rotation-status")
def rotation_status(db: Session = Depends(get_db)):
    """APScheduler status + rotation health."""
    return rotation_status_report(db)


# ── Revoke / Destroy ──────────────────────────────────────────────────────────

@router.post("/keys/{key_id}/revoke", response_model=KeyResponse)
def revoke_key(key_id: str, request: KeyRevokeRequest, db: Session = Depends(get_db)):
    """Revoke the active version of a key (ACTIVE → REVOKED)."""
    try:
        return lifecycle.revoke_key(db, key_id, reason=request.reason)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/keys/{key_id}/versions/{version_id}")
def destroy_version(key_id: str, version_id: str, db: Session = Depends(get_db)):
    """Destroy a REVOKED or RETIRED version (REVOKED/RETIRED → DESTROYED)."""
    try:
        v = lifecycle.destroy_version(db, key_id, version_id)
        return {"destroyed": True, "version_id": v.id, "state": v.state}
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Encrypt / Decrypt (Chapter 9.1 validation) ───────────────────────────────

@router.post("/keys/{key_id}/encrypt")
def encrypt(key_id: str, request: EncryptRequest, db: Session = Depends(get_db)):
    """
    Encrypt plaintext using the active version's v2 hybrid envelope.
    Returns envelope_id for later decryption.
    """
    try:
        result = lifecycle.encrypt(
            db=db, key_id=key_id,
            plaintext=request.plaintext,
            tenant_context=request.tenant_context,
        )
        return result
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/decrypt")
def decrypt(request: DecryptRequest, db: Session = Depends(get_db)):
    """
    Decrypt using the referenced version envelope_id.
    Works for ACTIVE and RETIRED versions (historical ciphertext).
    """
    try:
        return lifecycle.decrypt(db=db, envelope_id=request.envelope_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Compliance evidence (§8.5) ────────────────────────────────────────────────

@router.get("/compliance")
def get_compliance(db: Session = Depends(get_db)):
    """
    Machine-readable compliance evidence (§8.5).
    Covers RBI CSF, PCI-DSS v4, DORA, NIST SP 800-57.
    """
    return compliance_svc.compliance_evidence(db)


@router.get("/compliance/download")
def download_compliance(db: Session = Depends(get_db)):
    """Download compliance evidence as JSON (§8.5)."""
    evidence = compliance_svc.compliance_evidence(db)
    return JSONResponse(
        content=evidence,
        headers={"Content-Disposition": "attachment; filename=compliance_evidence.json"},
    )


@router.post("/compliance/generate-report")
def generate_compliance_report(db: Session = Depends(get_db)):
    """Generate and persist a full compliance report."""
    report = compliance_svc.generate_full_report(db)
    return {
        "report_id":          report.id,
        "generated_at":       report.generated_at.isoformat(),
        "total_keys":         report.total_keys,
        "total_versions":     report.total_versions,
        "pqc_ready_versions": report.pqc_ready_versions,
        "violations":         report.violations,
        "frameworks":         report.risk_summary.get("frameworks", []),
    }
