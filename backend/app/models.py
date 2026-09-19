"""
Quantum-Safe KMS Data Models — Capstone 2 (report Chapters 7/8).

Immutable key-version model:
  CryptographicKey (logical)  ──< KeyVersion (immutable versions v1…vN)
  Rotation creates a new KeyVersion; old ones become RETIRED but remain
  usable for decryption of historical ciphertext.
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Integer, Text, ForeignKey
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import relationship
from app.database import Base
import enum


# ── Enumerations ──────────────────────────────────────────────────────────────

class VersionState(str, enum.Enum):
    """Lifecycle state machine per §7.3."""
    ACTIVE    = "ACTIVE"     # Current encryption version
    RETIRED   = "RETIRED"    # Superseded; usable for historical decryption
    REVOKED   = "REVOKED"    # Operator-revoked; no further use
    DESTROYED = "DESTROYED"  # Material destroyed; metadata only


class QuantumRiskTag(str, enum.Enum):
    """Quantum-risk classification per Algorithm 8.4 (§8.4)."""
    QUANTUM_VULNERABLE = "QUANTUM_VULNERABLE"   # Classical-only, no ML-KEM
    HYBRID_READY       = "HYBRID_READY"         # Classical + ML-KEM-768 + live provider
    PQC_READY          = "PQC_READY"            # ML-KEM-768 primary
    NON_COMPLIANT      = "NON_COMPLIANT"        # Revoked/expired/provider-deficient


class TransitPosture(str, enum.Enum):
    """Import-channel quantum posture per §10.5."""
    classical_only     = "classical_only"       # AWS/Azure RSA-OAEP import
    hybrid_compensated = "hybrid_compensated"   # Nested compensating envelope §10.6
    pq_native          = "pq_native"            # GCP HPKE/ML-KEM (doc only)


# Legacy enums for API backward-compat
class KeyStatus(str, enum.Enum):
    ACTIVE   = "active"
    ROTATED  = "rotated"
    REVOKED  = "revoked"
    EXPIRED  = "expired"


class RiskLevel(str, enum.Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


# ── Logical Key ───────────────────────────────────────────────────────────────

class CryptographicKey(Base):
    """
    Logical key entity — one logical key maps to many immutable KeyVersion records.
    The 'name' field is the human-readable alias (e.g. 'customer-data').
    """
    __tablename__ = "cryptographic_keys"

    id          = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name        = Column(String(255), nullable=False, unique=True)  # alias
    algorithm   = Column(String(100), nullable=False, default="HYBRID-ML-KEM-768-AES-256-GCM")
    kms_provider = Column(String(50),  nullable=False, default="aws_kms")

    # Metadata
    owner       = Column(String(255), nullable=True)
    environment = Column(String(50),  default="production")
    purpose     = Column(String(255), nullable=True)
    tags        = Column(JSON, default=dict)

    created_at  = Column(DateTime, default=datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Derived / cached fields (updated on each rotation)
    active_version_number = Column(Integer, default=1)
    total_versions        = Column(Integer, default=0)
    is_quantum_safe       = Column(Boolean, default=True)
    is_hybrid             = Column(Boolean, default=True)

    # Legacy fields (kept for API compatibility)
    status          = Column(String(20), default="active")
    risk_level      = Column(String(20), default="low")
    kms_key_id      = Column(String(255), nullable=True)
    public_key      = Column(Text, nullable=True)
    key_size        = Column(Integer, nullable=True)
    expires_at      = Column(DateTime, nullable=True)
    last_rotated_at = Column(DateTime, nullable=True)
    rotation_due_at = Column(DateTime, nullable=True)
    rotation_count  = Column(Integer, default=0)
    version         = Column(Integer, default=1)

    # Relationships
    versions = relationship(
        "KeyVersion", back_populates="key",
        order_by="KeyVersion.version_number",
        cascade="all, delete-orphan",
    )

    def __repr__(self):
        return f"<CryptographicKey alias={self.name} active_v=v{self.active_version_number}>"


# ── Immutable Key Version ─────────────────────────────────────────────────────

class KeyVersion(Base):
    """
    Immutable key version record.  Created by create_key() and rotate_key().
    Never mutated after creation except for state transitions
    (ACTIVE → RETIRED → REVOKED/DESTROYED).
    Implements §7.3 state machine and Algorithm 8.3.
    """
    __tablename__ = "key_versions"

    id             = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    key_id         = Column(String, ForeignKey("cryptographic_keys.id"), nullable=False)
    version_number = Column(Integer, nullable=False)       # v1, v2, v3 …

    # State machine (§7.3)
    state          = Column(String(20), default=VersionState.ACTIVE, nullable=False)

    # Quantum-risk classification (§8.4)
    quantum_risk_tag = Column(String(30), default=QuantumRiskTag.HYBRID_READY, nullable=False)
    transit_posture  = Column(String(30), default=TransitPosture.classical_only, nullable=False)

    # Algorithms in this version
    classical_algorithm = Column(String(50), default="AES-256-GCM")
    pqc_algorithm       = Column(String(50), default="ML-KEM-768")
    sign_algorithm      = Column(String(50), default="ML-DSA-65")

    # Provider information
    providers         = Column(JSON, default=list)   # ["aws_kms", "azure_kv"]
    provider_metadata = Column(JSON, default=dict)   # per-provider ARN/URL
    provider_modes    = Column(JSON, default=dict)   # {"aws_kms": "LIVE", "azure_kv": "SIM"}

    # Hybrid envelope metadata (no plaintext key material)
    envelope_metadata = Column(JSON, default=dict)

    # Saga / multi-provider rotation tracking (§10.9)
    saga_id           = Column(String(50), nullable=True)
    activation_deferred = Column(Boolean, default=False)

    # Lifecycle timestamps
    created_at      = Column(DateTime, default=datetime.utcnow)
    activated_at    = Column(DateTime, nullable=True)
    retired_at      = Column(DateTime, nullable=True)
    revoked_at      = Column(DateTime, nullable=True)
    destroyed_at    = Column(DateTime, nullable=True)
    rotation_due_at = Column(DateTime, nullable=True)
    expires_at      = Column(DateTime, nullable=True)

    # Relationship
    key = relationship("CryptographicKey", back_populates="versions")

    def __repr__(self):
        return f"<KeyVersion key={self.key_id} v{self.version_number} state={self.state}>"


# ── Encrypted Envelope (for encrypt/decrypt demo) ────────────────────────────

class EncryptedEnvelope(Base):
    """
    Stores the full hybrid envelope from an encrypt() call for later decrypt().
    Envelope JSON contains all components except plaintext key material.
    """
    __tablename__ = "encrypted_envelopes"

    id             = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    key_id         = Column(String, nullable=False)
    version_id     = Column(String, nullable=False)
    version_number = Column(Integer, nullable=False)
    tenant_context = Column(String(255), default="default-tenant")
    envelope_json  = Column(JSON, nullable=False)    # full v2 envelope dict
    created_at     = Column(DateTime, default=datetime.utcnow)


# ── Audit Log ─────────────────────────────────────────────────────────────────

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id            = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    key_id        = Column(String, nullable=True)
    version_id    = Column(String, nullable=True)
    action        = Column(String(100), nullable=False)
    actor         = Column(String(255), nullable=True)
    timestamp     = Column(DateTime, default=datetime.utcnow)
    details       = Column(JSON, default=dict)
    ip_address    = Column(String(45), nullable=True)
    success       = Column(Boolean, default=True)
    error_message = Column(Text, nullable=True)


# ── Compliance Report ─────────────────────────────────────────────────────────

class ComplianceReport(Base):
    __tablename__ = "compliance_reports"

    id                 = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    report_type        = Column(String(50), nullable=False)  # NIST | RBI | PCI-DSS | DORA | FULL
    generated_at       = Column(DateTime, default=datetime.utcnow)
    findings           = Column(JSON, default=list)
    risk_summary       = Column(JSON, default=dict)
    total_keys         = Column(Integer, default=0)
    total_versions     = Column(Integer, default=0)
    compliant_keys     = Column(Integer, default=0)
    non_compliant_keys = Column(Integer, default=0)
    pqc_ready_versions = Column(Integer, default=0)
    violations         = Column(Integer, default=0)
    report_data        = Column(JSON, default=dict)
