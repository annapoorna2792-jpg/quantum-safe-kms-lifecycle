"""
FastAPI application entry point — Capstone 2.

Endpoints:
  GET  /healthz              — provider health + PQC status (§8.6)
  GET  /api/v1/...           — lifecycle, compliance, dashboard, keys
  Static files served from /frontend
"""
import logging
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

from app.api import keys, compliance, dashboard
from app.api  import lifecycle as lifecycle_router
from app.database import engine
from app import models
from app.config import settings
from app.crypto.pqc import pqc_available
import app.crypto.aws_kms as aws_kms_adapter
import app.kms_providers.azure_kv_sim as azure_adapter
from app.kms_providers.factory import all_providers

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ── Database init ─────────────────────────────────────────────────────────────
models.Base.metadata.create_all(bind=engine)


# ── Startup / Shutdown ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────────────────────────────────────
    logger.info("=== Quantum-Safe KMS v2.0 starting ===")

    # Probe AWS KMS (Algorithm 8.1)
    aws_kms_adapter.probe(
        region=settings.AWS_REGION,
        key_alias=settings.AWS_KMS_KEY_ALIAS,
    )
    logger.info("AWS KMS mode: %s", aws_kms_adapter.provider_mode())

    # Probe Azure KV (§8.7)
    azure_adapter._get_az_client()
    logger.info("Azure KV mode: %s", azure_adapter.provider_mode())

    # PQC availability
    logger.info("PQC (liboqs) available: %s", pqc_available())

    # Seed demo key (customer-data) if configured
    if settings.SEED_DEMO_KEY:
        _seed_demo_key()

    # Start APScheduler (§8.3)
    from app.services.rotation_scheduler import start_scheduler
    start_scheduler()

    yield

    # ── Shutdown ─────────────────────────────────────────────────────────────
    from app.services.rotation_scheduler import stop_scheduler
    stop_scheduler()
    logger.info("Quantum-Safe KMS shutdown complete")


def _seed_demo_key():
    """Create the 'customer-data' demo key if it doesn't exist."""
    from app.database import SessionLocal
    from app.services.key_lifecycle_service import KeyLifecycleService
    db  = SessionLocal()
    svc = KeyLifecycleService()
    try:
        svc.create_key(
            db=db,
            name=settings.DEFAULT_KEY_ALIAS,
            algorithm="HYBRID-ML-KEM-768-AES-256-GCM",
            kms_provider="aws_kms",
            owner="system",
            environment="production",
            purpose="Demo key for Capstone 2 validation (§8.6)",
            rotation_days=settings.KEY_ROTATION_DAYS,
        )
        logger.info("Demo key '%s' ready", settings.DEFAULT_KEY_ALIAS)
    except Exception as exc:
        logger.debug("Demo key seed: %s", exc)
    finally:
        db.close()


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Quantum-Safe KMS",
    description=(
        "Post-Quantum Key Management System — Capstone 2. "
        "ML-KEM-768 + AWS KMS + Azure Key Vault hybrid key lifecycle "
        "with compliance mapping to RBI, PCI-DSS v4, DORA, NIST SP 800-57."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── /healthz (§8.6 — live provider and PQC health evidence) ──────────────────

@app.get("/healthz", tags=["Health"])
def health_check():
    """
    Live provider and PQC health endpoint.
    Returns: status ok, PQC available, AWS KMS mode, Azure KV mode, region.
    Matches the report's health panel (Fig 8.5, §8.6).
    """
    return {
        "status":        "ok",
        "pqc_available": pqc_available(),
        "pqc_mode":      "AVAILABLE" if pqc_available() else "SIMULATED",
        "aws_kms_mode":  aws_kms_adapter.provider_mode(),
        "azure_kv_mode": azure_adapter.provider_mode(),
        "gcp_kms_mode":  "DOC",
        "region":        aws_kms_adapter.region(),
        "key_arn":       aws_kms_adapter.key_arn() or "N/A",
        "timestamp":     datetime.utcnow().isoformat(),
        "providers":     all_providers(),
    }


@app.get("/health", tags=["Health"])
def health_simple():
    return {"status": "healthy", "service": "quantum-safe-kms", "version": "2.0.0"}


# ── Provider capability matrix (§10.5) ───────────────────────────────────────

@app.get("/api/v1/providers/capability-matrix", tags=["Providers"])
def provider_capability_matrix():
    """
    Table 10.1 equivalent — documents PQ import support per provider.
    AWS: RSAES_OAEP_SHA_256 only (classical_only).
    Azure: RSA-OAEP only (classical_only).
    GCP: HPKE ML-KEM-768 (pq_native, preview, software level only).
    """
    return {
        "assessed_at": datetime.utcnow().isoformat(),
        "providers": [
            {
                "provider":          "aws_kms",
                "mode":              aws_kms_adapter.provider_mode(),
                "pq_import_support": False,
                "import_methods":    ["RSAES_OAEP_SHA_256", "RSA_AES_KEY_WRAP_SHA_256"],
                "transit_posture":   "classical_only",
                "notes":             "RSA symmetric key import only; wrapping method not operator-selectable (§10.5.1)",
            },
            {
                "provider":          "azure_kv",
                "mode":              azure_adapter.provider_mode(),
                "pq_import_support": False,
                "import_methods":    ["RSA-OAEP"],
                "transit_posture":   "classical_only",
                "notes":             "BYOK via RSA-OAEP only; no PQ import option (§10.5)",
            },
            {
                "provider":          "gcp_kms",
                "mode":              "DOC",
                "pq_import_support": True,
                "import_methods":    ["HPKE X-Wing", "ML-KEM-768", "ML-KEM-1024"],
                "transit_posture":   "pq_native",
                "notes":             "Preview; software protection level only; not exercised against live service (§10.5, §11.1)",
            },
        ],
    }


# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(lifecycle_router.router, prefix="/api/v1/lifecycle", tags=["Lifecycle"])
app.include_router(keys.router,       prefix="/api/v1/keys",       tags=["Keys (Legacy)"])
app.include_router(compliance.router, prefix="/api/v1/compliance",  tags=["Compliance"])
app.include_router(dashboard.router,  prefix="/api/v1/dashboard",   tags=["Dashboard"])


# ── Static frontend ───────────────────────────────────────────────────────────
# Mount each sub-folder explicitly so the browser resolves relative paths:
#   css/style.css  →  /css/style.css  ✓
#   js/dashboard.js → /js/dashboard.js ✓

_FRONTEND = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend"))
if os.path.isdir(_FRONTEND):
    _CSS = os.path.join(_FRONTEND, "css")
    _JS  = os.path.join(_FRONTEND, "js")
    if os.path.isdir(_CSS):
        app.mount("/css", StaticFiles(directory=_CSS), name="css")
    if os.path.isdir(_JS):
        app.mount("/js",  StaticFiles(directory=_JS),  name="js")
    # Also keep /static for any other assets
    app.mount("/static", StaticFiles(directory=_FRONTEND), name="static")

    @app.get("/", include_in_schema=False)
    def serve_dashboard():
        return FileResponse(os.path.join(_FRONTEND, "index.html"))
