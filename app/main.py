from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .aws_kms import AwsKmsProvider
from .azure_kv import AzureKeyVaultProvider
from .config import Settings
from .crypto import HybridCrypto, MasterKeyProtector, PQCUnavailable, pqc_status
from .db import Repository
from .service import KMSService


BASE_DIR = Path(__file__).resolve().parent


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    repository = Repository(settings.database_path)
    aws_kms = AwsKmsProvider(settings.aws_region, settings.aws_kms_key_id)
    azure_kv = AzureKeyVaultProvider(settings.azure_vault_url, settings.azure_key_name, settings.azure_tenant_id, settings.azure_client_id, settings.azure_client_secret)
    crypto = HybridCrypto(MasterKeyProtector(settings.master_key), aws_kms, azure_kv)
    service = KMSService(repository, crypto, settings.rotation_seconds)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        scheduler = None
        if settings.scheduler_enabled:
            scheduler = BackgroundScheduler(timezone="UTC")
            scheduler.add_job(
                service.rotate_due,
                "interval",
                seconds=min(30, max(5, settings.rotation_seconds // 4)),
                id="rotation-policy",
                max_instances=1,
                coalesce=True,
            )
            scheduler.start()
        app.state.scheduler = scheduler
        yield
        if scheduler:
            scheduler.shutdown(wait=False)

    app = FastAPI(title="Quantum-Safe Multi-Cloud KMS Demo", version="2.0.0", lifespan=lifespan)
    app.state.repository = repository
    app.state.service = service
    app.state.settings = settings
    templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
    templates.env.filters["loads"] = json.loads
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

    def page(request: Request, name: str, **context):
        return templates.TemplateResponse(
            name,
            {"request": request, "pqc": pqc_status(), "aws_kms": aws_kms.status(), **context},
        )

    def go(path: str, message: str, kind: str = "ok") -> RedirectResponse:
        return RedirectResponse(f"{path}?message={quote(message)}&kind={kind}", status_code=303)

    @app.get("/healthz")
    def health() -> dict:
        pqc = pqc_status()
        kms = aws_kms.status()
        return {
            "status": "ok" if pqc["available"] and kms["available"] else "degraded",
            "database": str(settings.database_path),
            "pqc": pqc,
            "aws_kms": kms,
            "azure_key_vault": azure_kv.status(),
        }

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request, message: str | None = None, kind: str = "ok"):
        report = service.compliance_report()
        return page(request, "dashboard.html", title="Dashboard", report=report, aws_kms=aws_kms.status(), azure_kv=azure_kv.status(), rotation_seconds=settings.rotation_seconds, message=message, kind=kind)

    @app.get("/keys", response_class=HTMLResponse)
    def key_lifecycle(request: Request, message: str | None = None, kind: str = "ok"):
        return page(request, "keys.html", title="Key Lifecycle", keys=repository.list_keys(), versions=repository.list_versions(), default_rotation=settings.rotation_seconds, message=message, kind=kind)

    @app.post("/keys")
    def create_key(alias: str = Form(...), rotation_seconds: int = Form(...)):
        try:
            key_id = service.create_key(alias, rotation_seconds)
            return go("/keys", f"Created {alias} with active version 1 ({key_id[:8]}…).")
        except PQCUnavailable as exc:
            return go("/keys", str(exc), "error")
        except Exception as exc:
            return go("/keys", f"Create failed: {exc}", "error")

    @app.post("/keys/{key_id}/rotate")
    def rotate_key(key_id: str):
        try:
            version = service.rotate(key_id)
            return go("/keys", f"Rotation complete: version {version} is ACTIVE; the prior version is RETIRED.")
        except Exception as exc:
            return go("/keys", f"Rotation failed: {exc}", "error")

    @app.post("/versions/{version_id}/{action}")
    def transition(version_id: int, action: str):
        target = action.upper()
        try:
            repository.transition_version(version_id, target)
            return go("/keys", f"Version {version_id} is now {target}.")
        except Exception as exc:
            return go("/keys", f"Lifecycle action failed: {exc}", "error")

    @app.get("/demo", response_class=HTMLResponse)
    def hybrid_demo(request: Request, message: str | None = None, kind: str = "ok"):
        return page(request, "demo.html", title="Hybrid Demo", keys=repository.list_keys(), message=message, kind=kind, result=None)

    @app.post("/demo/encrypt", response_class=HTMLResponse)
    def encrypt(request: Request, key_id: str = Form(...), plaintext: str = Form(...), aad: str = Form("")):
        try:
            envelope = service.encrypt(key_id, plaintext, aad)
            repository.record_audit(
                "DATA_ENCRYPTED",
                "key",
                key_id,
                {"plaintext_bytes": len(plaintext.encode()), "aws_kms": "LIVE"},
            )
            return page(request, "demo.html", title="Hybrid Demo", keys=repository.list_keys(), result={"envelope": envelope}, message="Encryption succeeded using all classical and PQC components.", kind="ok")
        except Exception as exc:
            return page(request, "demo.html", title="Hybrid Demo", keys=repository.list_keys(), result=None, message=f"Encryption failed: {exc}", kind="error")

    @app.post("/demo/decrypt", response_class=HTMLResponse)
    def decrypt(request: Request, envelope: str = Form(...)):
        try:
            plaintext = service.decrypt(envelope.strip())
            repository.record_audit(
                "DATA_DECRYPTED",
                "envelope",
                "v2",
                {"plaintext_bytes": len(plaintext.encode()), "aws_kms": "LIVE"},
            )
            return page(request, "demo.html", title="Hybrid Demo", keys=repository.list_keys(), result={"plaintext": plaintext, "envelope": envelope}, message="Decryption succeeded using the envelope's immutable key version.", kind="ok")
        except Exception as exc:
            return page(request, "demo.html", title="Hybrid Demo", keys=repository.list_keys(), result={"envelope": envelope}, message=f"Decryption failed: {exc}", kind="error")

    @app.post("/demo/sign", response_class=HTMLResponse)
    def sign(request: Request, message_text: str = Form(...)):
        try:
            package = crypto.sign(message_text)
            repository.record_audit("MESSAGE_SIGNED", "signature", "ephemeral", {"message_bytes": len(message_text.encode())})
            return page(request, "demo.html", title="Hybrid Demo", keys=repository.list_keys(), result={"signature_package": package, "signed_message": message_text}, message="ECDSA and ML-DSA signatures created. Private keys were ephemeral and were never persisted or rendered.", kind="ok")
        except Exception as exc:
            return page(request, "demo.html", title="Hybrid Demo", keys=repository.list_keys(), result=None, message=f"Signing failed: {exc}", kind="error")

    @app.post("/demo/verify", response_class=HTMLResponse)
    def verify(request: Request, message_text: str = Form(...), signature_package: str = Form(...)):
        try:
            verified = crypto.verify(message_text, signature_package.strip())
            repository.record_audit("SIGNATURE_VERIFIED", "signature", "ephemeral", verified)
            return page(request, "demo.html", title="Hybrid Demo", keys=repository.list_keys(), result={"verification": verified, "signature_package": signature_package, "signed_message": message_text}, message="Verification complete. Hybrid succeeds only when both checks pass.", kind="ok" if verified["hybrid"] else "error")
        except Exception as exc:
            return page(request, "demo.html", title="Hybrid Demo", keys=repository.list_keys(), result=None, message=f"Verification failed: {exc}", kind="error")

    @app.get("/compliance", response_class=HTMLResponse)
    def compliance(request: Request):
        return page(request, "compliance.html", title="Compliance", report=service.compliance_report())

    @app.get("/api/compliance.json")
    def compliance_json() -> JSONResponse:
        return JSONResponse(service.compliance_report(), headers={"Content-Disposition": 'attachment; filename="quantum-safe-kms-compliance.json"'})

    return app


app = create_app()
