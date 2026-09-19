# Quantum-Safe KMS — Architecture

## Overview

Quantum-Safe KMS is a post-quantum cryptography Key Management System that supports hybrid encryption (classical + PQC), multi-cloud KMS provider simulation, automated key rotation, risk tagging, and compliance reporting against NIST SP 800-131A, FIPS 140-3, and ISO 27001.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Frontend (SPA)                       │
│   index.html + css/style.css + js/dashboard.js          │
│   Dark Glassmorphism UI · Donut Charts · Key CRUD       │
└─────────────────────┬───────────────────────────────────┘
                      │ HTTP REST (JSON)
                      ▼
┌─────────────────────────────────────────────────────────┐
│                  FastAPI Backend                         │
│  /api/v1/keys   /api/v1/compliance  /api/v1/dashboard   │
└──────┬───────────────┬──────────────────┬───────────────┘
       │               │                  │
       ▼               ▼                  ▼
┌──────────┐   ┌──────────────┐   ┌──────────────┐
│  Crypto  │   │ KMS Provider │   │   Services   │
│  Layer   │   │   Factory    │   │   Layer      │
│          │   │              │   │              │
│classical │   │ AWS  Sim     │   │ Lifecycle    │
│pqc       │   │ Azure Sim    │   │ Rotation     │
│hybrid    │   │ GCP  Sim     │   │ Risk Tagging │
└──────────┘   └──────────────┘   │ Compliance   │
                                  │ Audit        │
                                  └──────┬───────┘
                                         │
                                  ┌──────▼───────┐
                                  │  SQLite / PG │
                                  │  (SQLAlchemy)│
                                  └──────────────┘
```

---

## Layer Descriptions

### Crypto Layer (`app/crypto/`)
| Module | Purpose |
|--------|---------|
| `classical.py` | AES-256-GCM, RSA-4096, ECC-P521 |
| `pqc.py` | Kyber-1024 (KEM), Dilithium-5 (DSA), SPHINCS+ |
| `hybrid.py` | HybridKEM (Kyber+RSA), HybridSignature (Dilithium+RSA) |

PQC modules use `pyoqs` (liboqs Python bindings) when available, falling back to a simulation layer for development.

### KMS Provider Layer (`app/kms_providers/`)
Provider adapters implement the `BaseKMSProvider` ABC. In production, replace simulator implementations with real cloud SDK calls (boto3, azure-keyvault-keys, google-cloud-kms).

### Services Layer (`app/services/`)
| Service | Responsibility |
|---------|---------------|
| `KeyLifecycleService` | Create, rotate, revoke, list keys |
| `RotationScheduler` | Identify overdue keys, run rotation passes |
| `RiskTaggingService` | Score and classify key risk levels |
| `ComplianceService` | Generate NIST / FIPS / ISO reports |
| `AuditService` | Query immutable audit log entries |

### API Layer (`app/api/`)
FastAPI routers mounted at `/api/v1`:
- `keys.py` — CRUD + lifecycle + risk endpoints
- `compliance.py` — report generation and retrieval
- `dashboard.py` — aggregated stats, audit logs, rotation triggers

---

## Data Models

```
CryptographicKey
├── id (UUID)
├── name, algorithm, key_size
├── status (active|inactive|rotated|revoked|expired)
├── risk_level (low|medium|high|critical)
├── kms_provider, kms_key_id
├── public_key (PEM, base64)
├── is_quantum_safe, is_hybrid
├── rotation_count, version
├── created_at, expires_at, rotation_due_at, last_rotated_at
└── tags (JSON), owner, environment, purpose

AuditLog
└── key_id, action, actor, timestamp, details, success

ComplianceReport
└── report_type, findings, risk_summary, compliant/non_compliant counts
```

---

## Security Design Principles

1. **Defense in Depth**: Hybrid mode requires both classical AND PQC to be broken.
2. **Never store plaintext key material**: All key material is encrypted before persistence.
3. **Immutable audit trail**: Audit logs are append-only; no update/delete endpoints.
4. **Principle of Least Privilege**: Each KMS provider operation is scoped to a specific key.
5. **NIST PQC Alignment**: Algorithms follow FIPS 203 (Kyber), FIPS 204 (Dilithium), FIPS 205 (SPHINCS+).
