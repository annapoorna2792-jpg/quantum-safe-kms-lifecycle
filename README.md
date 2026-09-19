# Quantum-Safe KMS

> **Post-Quantum Cryptography Key Management System** — hybrid encryption, multi-cloud KMS simulation, automated key lifecycle, compliance reporting, and a dark glassmorphism dashboard.

---

## Features

- ⚛ **Post-Quantum Algorithms**: CRYSTALS-Kyber-1024 (KEM), CRYSTALS-Dilithium-5 (DSA), SPHINCS+ — all NIST standardized (FIPS 203/204/205)
- ⚡ **Hybrid Mode**: Classical (RSA-4096 / AES-256-GCM) + PQC in tandem — broken only if **both** are compromised
- 🔁 **Key Lifecycle**: Create → Active → Rotate → Revoke → Expire with full audit trail
- 🏦 **Multi-Cloud KMS**: Simulated AWS KMS, Azure Key Vault, GCP Cloud KMS with identical interface
- 🎯 **Risk Tagging**: Automatic scoring (LOW/MEDIUM/HIGH/CRITICAL) based on algorithm, age, and rotation status
- 📋 **Compliance Reports**: NIST SP 800-131A, FIPS 140-3, ISO 27001:2022 Annex A
- 📊 **Dashboard**: Real-time stats, donut charts, audit logs, rotation management

---

## Quick Start

### Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux

pip install -r requirements.txt
cp .env.example .env

uvicorn app.main:app --reload --port 8000
```

API docs: http://localhost:8000/docs

### Frontend

Open `frontend/index.html` directly in your browser, or serve it:

```bash
cd frontend
python -m http.server 3000
# → http://localhost:3000
```

### Docker

```bash
docker-compose up --build
```

---

## Project Structure

```
quantum-safe-kms/
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI entry point
│   │   ├── config.py        # Settings (pydantic-settings)
│   │   ├── database.py      # SQLAlchemy engine & session
│   │   ├── models.py        # ORM models
│   │   ├── schemas.py       # Pydantic schemas
│   │   ├── crypto/          # AES, RSA, Kyber, Dilithium, SPHINCS+, Hybrid
│   │   ├── kms_providers/   # AWS/Azure/GCP simulators + factory
│   │   ├── services/        # Lifecycle, rotation, risk, compliance, audit
│   │   └── api/             # FastAPI routers
│   └── requirements.txt
├── frontend/
│   ├── index.html           # Single-page dashboard
│   ├── css/style.css        # Dark glassmorphism design system
│   └── js/dashboard.js      # API integration + charts
├── tests/
│   ├── test_pqc.py          # Kyber, Dilithium, SPHINCS+ unit tests
│   ├── test_hybrid.py       # HybridKEM + HybridSignature tests
│   └── test_lifecycle.py    # Key lifecycle integration tests
└── docs/
    ├── ARCHITECTURE.md      # System design & layer descriptions
    └── THREAT_MODEL.md      # STRIDE + quantum threat analysis
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/keys/` | Create a new key |
| `GET`  | `/api/v1/keys/` | List keys (filter by status/algo/provider) |
| `GET`  | `/api/v1/keys/{id}` | Get key details |
| `POST` | `/api/v1/keys/{id}/rotate` | Rotate key |
| `POST` | `/api/v1/keys/{id}/revoke` | Revoke key |
| `GET`  | `/api/v1/keys/risk/quantum-vulnerable` | List quantum-vulnerable keys |
| `POST` | `/api/v1/compliance/reports/generate?standard=NIST` | Generate compliance report |
| `GET`  | `/api/v1/dashboard/stats` | Aggregated dashboard statistics |
| `GET`  | `/api/v1/dashboard/audit-logs` | Audit trail |
| `POST` | `/api/v1/dashboard/rotation/run` | Trigger rotation pass |

Full interactive docs at `/docs` (Swagger UI) and `/redoc`.

---

## Running Tests

```bash
cd backend
pytest ../tests/ -v
```

---

## Algorithms Supported

| Algorithm | Type | NIST Standard | Quantum-Safe |
|-----------|------|--------------|-------------|
| KYBER-1024 | KEM | FIPS 203 | ✅ |
| DILITHIUM-5 | DSA | FIPS 204 | ✅ |
| SPHINCS+ | DSA | FIPS 205 | ✅ |
| HYBRID-KYBER-AES | Hybrid KEM | — | ✅ |
| HYBRID-DILITHIUM-RSA | Hybrid DSA | — | ✅ |
| AES-256-GCM | Symmetric | FIPS 197 | ⚠ (Grover) |
| RSA-4096 | Asymmetric | — | ❌ (Shor) |
| ECC-P521 | Asymmetric | — | ❌ (Shor) |

---

## License

MIT
