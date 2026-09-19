"""
Keys API Router — updated for Capstone 2.
Kept for backward-compat; new lifecycle endpoints are in api/lifecycle.py.
Adds /audit endpoint used by the dashboard JS.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.schemas import KeyCreateRequest, KeyResponse, KeyRotateRequest, KeyRevokeRequest, AuditLogResponse
from app.services.key_lifecycle_service import KeyLifecycleService
from app.services.risk_tagging          import RiskTaggingService
from app.services.audit_service         import AuditService

router       = APIRouter()
lifecycle    = KeyLifecycleService()
risk_service = RiskTaggingService()
audit_svc    = AuditService()


@router.post("/", response_model=KeyResponse, status_code=201)
def create_key(request: KeyCreateRequest, db: Session = Depends(get_db)):
    """Create a new cryptographic key (legacy endpoint — prefer /api/v1/lifecycle/keys)."""
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


@router.get("/", response_model=List[KeyResponse])
def list_keys(
    status:    Optional[str] = Query(None),
    algorithm: Optional[str] = Query(None),
    provider:  Optional[str] = Query(None),
    skip:  int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    return lifecycle.list_keys(db, status=status, algorithm=algorithm, provider=provider, skip=skip, limit=limit)


@router.get("/audit", response_model=List[AuditLogResponse])
def get_audit(
    limit: int = Query(20, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """Recent audit events — used by dashboard Recent Activity panel."""
    return audit_svc.get_recent_events(db, limit=limit)


@router.get("/{key_id}", response_model=KeyResponse)
def get_key(key_id: str, db: Session = Depends(get_db)):
    try:
        return lifecycle.get_key(db, key_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/{key_id}/rotate", response_model=KeyResponse)
def rotate_key(key_id: str, request: KeyRotateRequest, db: Session = Depends(get_db)):
    try:
        return lifecycle.rotate_key(db, key_id, reason=request.reason or "Manual rotation")
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{key_id}/revoke", response_model=KeyResponse)
def revoke_key(key_id: str, request: KeyRevokeRequest, db: Session = Depends(get_db)):
    try:
        return lifecycle.revoke_key(db, key_id, reason=request.reason)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/risk/evaluate")
def evaluate_risks(db: Session = Depends(get_db)):
    return risk_service.tag_all_keys(db)


@router.get("/risk/high-risk", response_model=List[KeyResponse])
def high_risk_keys(db: Session = Depends(get_db)):
    return risk_service.get_high_risk_keys(db)


@router.get("/risk/quantum-vulnerable", response_model=List[KeyResponse])
def quantum_vulnerable(db: Session = Depends(get_db)):
    return risk_service.quantum_vulnerable_keys(db)
