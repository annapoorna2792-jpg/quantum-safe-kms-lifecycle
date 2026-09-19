"""
Pydantic schemas — Capstone 2 rebuild.
Covers: key lifecycle, version history, encrypt/decrypt, health, compliance.
"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum


# ── Enums (mirrored from models) ─────────────────────────────────────────────

class VersionStateEnum(str, Enum):
    ACTIVE    = "ACTIVE"
    RETIRED   = "RETIRED"
    REVOKED   = "REVOKED"
    DESTROYED = "DESTROYED"


class QuantumRiskTagEnum(str, Enum):
    QUANTUM_VULNERABLE = "QUANTUM_VULNERABLE"
    HYBRID_READY       = "HYBRID_READY"
    PQC_READY          = "PQC_READY"
    NON_COMPLIANT      = "NON_COMPLIANT"


class TransitPostureEnum(str, Enum):
    classical_only     = "classical_only"
    hybrid_compensated = "hybrid_compensated"
    pq_native          = "pq_native"


# Legacy enums
class KeyStatus(str, Enum):
    ACTIVE   = "active"
    ROTATED  = "rotated"
    REVOKED  = "revoked"
    EXPIRED  = "expired"


class RiskLevel(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


# ── Key Version Schemas ───────────────────────────────────────────────────────

class KeyVersionResponse(BaseModel):
    id:                 str
    key_id:             str
    version_number:     int
    state:              str
    quantum_risk_tag:   str
    transit_posture:    str
    classical_algorithm: str
    pqc_algorithm:      str
    sign_algorithm:     str
    providers:          List[str]
    provider_metadata:  Dict[str, Any]
    provider_modes:     Dict[str, Any]
    created_at:         datetime
    activated_at:       Optional[datetime]
    retired_at:         Optional[datetime]
    revoked_at:         Optional[datetime]
    destroyed_at:       Optional[datetime]
    rotation_due_at:    Optional[datetime]
    expires_at:         Optional[datetime]

    class Config:
        from_attributes = True


# ── Key Schemas ───────────────────────────────────────────────────────────────

class KeyCreateRequest(BaseModel):
    name:          str  = Field(..., min_length=1, max_length=255)
    algorithm:     str  = Field(default="HYBRID-ML-KEM-768-AES-256-GCM")
    kms_provider:  str  = Field(default="aws_kms")
    owner:         Optional[str] = None
    environment:   str  = Field(default="production")
    purpose:       Optional[str] = None
    tags:          Dict[str, str] = Field(default_factory=dict)
    rotation_days: Optional[int]  = Field(default=365, ge=1, le=3650)


class KeyResponse(BaseModel):
    id:                   str
    name:                 str
    algorithm:            str
    key_size:             Optional[int]
    status:               str
    risk_level:           str
    kms_provider:         str
    kms_key_id:           Optional[str]
    public_key:           Optional[str]
    created_at:           datetime
    updated_at:           datetime
    expires_at:           Optional[datetime]
    last_rotated_at:      Optional[datetime]
    rotation_due_at:      Optional[datetime]
    owner:                Optional[str]
    environment:          str
    tags:                 Dict[str, Any]
    purpose:              Optional[str]
    is_quantum_safe:      bool
    is_hybrid:            bool
    rotation_count:       int
    version:              int
    active_version_number: int
    total_versions:       int

    class Config:
        from_attributes = True


class KeyDetailResponse(KeyResponse):
    """Extended response including all immutable versions."""
    versions: List[KeyVersionResponse] = []

    class Config:
        from_attributes = True


class KeyRotateRequest(BaseModel):
    reason: Optional[str] = Field(default="Scheduled rotation")


class KeyRevokeRequest(BaseModel):
    reason: str = Field(..., min_length=1)


# ── Encrypt / Decrypt Schemas ─────────────────────────────────────────────────

class EncryptRequest(BaseModel):
    plaintext:      str  = Field(..., description="UTF-8 plaintext to encrypt")
    tenant_context: str  = Field(default="default-tenant")


class EncryptResponse(BaseModel):
    envelope_id:    str
    key_alias:      str
    version_number: int
    tenant_context: str
    aws_mode:       str
    pqc_available:  bool
    envelope:       Dict[str, Any]
    encrypted_at:   datetime


class DecryptRequest(BaseModel):
    envelope_id: str = Field(..., description="ID of the envelope to decrypt")


class DecryptResponse(BaseModel):
    plaintext:      str
    key_alias:      str
    version_number: int
    tenant_context: str
    decrypted_at:   datetime


# ── Health / Status Schemas ───────────────────────────────────────────────────

class ProviderHealth(BaseModel):
    provider:            str
    mode:                str     # LIVE | SIM | DOC
    region:              Optional[str]
    vault_url:           Optional[str]
    pq_import_support:   bool
    transit_posture:     str


class HealthResponse(BaseModel):
    status:         str              # "ok"
    pqc_available:  bool
    pqc_mode:       str              # "AVAILABLE" | "SIMULATED"
    aws_kms_mode:   str              # "LIVE" | "SIM"
    azure_kv_mode:  str
    gcp_kms_mode:   str              # "DOC"
    region:         str
    key_arn:        str
    timestamp:      datetime
    providers:      Dict[str, Any]


# ── Compliance Schemas ────────────────────────────────────────────────────────

class ComplianceFrameworkResult(BaseModel):
    framework:       str
    standard:        str
    compliant:       bool
    violations:      int
    findings:        List[Dict[str, Any]]
    score:           float


class ComplianceEvidenceResponse(BaseModel):
    generated_at:          datetime
    inventory:             int
    total_versions:        int
    pqc_ready_versions:    int
    violations:            int
    pqc_ready_pct:         float
    provider_panel:        Dict[str, Any]
    frameworks:            List[ComplianceFrameworkResult]
    key_inventory:         List[Dict[str, Any]]


class ComplianceReportResponse(BaseModel):
    id:                 str
    report_type:        str
    generated_at:       datetime
    findings:           List[Dict[str, Any]]
    risk_summary:       Dict[str, Any]
    total_keys:         int
    total_versions:     int
    compliant_keys:     int
    non_compliant_keys: int
    pqc_ready_versions: int
    violations:         int
    report_data:        Dict[str, Any]

    class Config:
        from_attributes = True


# ── Provider Capability Matrix (§10.5) ───────────────────────────────────────

class ProviderCapabilityEntry(BaseModel):
    provider:            str
    mode:                str
    pq_import_support:   bool
    import_methods:      List[str]
    transit_posture:     str
    notes:               str


class ProviderCapabilityMatrix(BaseModel):
    assessed_at: datetime
    providers:   List[ProviderCapabilityEntry]


# ── Audit Log Schemas ─────────────────────────────────────────────────────────

class AuditLogResponse(BaseModel):
    id:            str
    key_id:        Optional[str]
    version_id:    Optional[str]
    action:        str
    actor:         Optional[str]
    timestamp:     datetime
    details:       Dict[str, Any]
    ip_address:    Optional[str]
    success:       bool
    error_message: Optional[str]

    class Config:
        from_attributes = True


# ── Dashboard Schemas ─────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_keys:              int
    active_keys:             int
    quantum_safe_keys:       int
    hybrid_keys:             int
    keys_due_rotation:       int
    keys_expired:            int
    keys_revoked:            int
    total_versions:          int
    pqc_ready_versions:      int
    violations:              int
    risk_distribution:       Dict[str, int]
    algorithm_distribution:  Dict[str, int]
    provider_distribution:   Dict[str, int]
    compliance_score:        float
    recent_audit_events:     int
    quantum_risk_distribution: Dict[str, int]
