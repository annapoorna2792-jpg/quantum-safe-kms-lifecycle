"""
APScheduler-based rotation scheduler — Chapter 8.3.
Uses ROTATION_INTERVAL_SECONDS (default 120s for demo, 365 days for production).

Implements Algorithm 8.3: on each tick, rotate all keys whose rotation_due_at has passed.
The saga deferred-activation pattern (§10.9) is used for multi-provider consistency.
"""
import logging
from datetime import datetime
from sqlalchemy.orm import Session
from apscheduler.schedulers.background import BackgroundScheduler
from app.models import CryptographicKey, KeyVersion, KeyStatus, VersionState
from app.services.key_lifecycle_service import KeyLifecycleService
from app.database import SessionLocal
from app.config import settings

logger = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None
_lifecycle = KeyLifecycleService()


def _rotation_job():
    """APScheduler job — rotates all overdue keys."""
    db = SessionLocal()
    try:
        results = run_rotation_pass(db)
        if results["rotated"]:
            logger.info("Scheduler rotated %d key(s): %s", len(results["rotated"]), results["rotated"])
        if results["failed"]:
            logger.error("Scheduler rotation failures: %s", results["failed"])
    except Exception as exc:
        logger.error("Rotation job error: %s", exc)
    finally:
        db.close()


def start_scheduler():
    """Start the APScheduler background scheduler. Called once at app startup."""
    global _scheduler
    if _scheduler and _scheduler.running:
        return

    _scheduler = BackgroundScheduler(daemon=True)
    interval   = settings.ROTATION_INTERVAL_SECONDS
    _scheduler.add_job(
        _rotation_job,
        trigger="interval",
        seconds=interval,
        id="key_rotation",
        name="Key Rotation Scheduler",
        misfire_grace_time=30,
    )
    _scheduler.start()
    logger.info("Rotation scheduler started — interval: %ds", interval)


def stop_scheduler():
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Rotation scheduler stopped")


def next_fire_time() -> str | None:
    if not _scheduler:
        return None
    job = _scheduler.get_job("key_rotation")
    if job and job.next_run_time:
        return job.next_run_time.isoformat()
    return None


def scheduler_status() -> dict:
    running = bool(_scheduler and _scheduler.running)
    return {
        "running":             running,
        "interval_seconds":    settings.ROTATION_INTERVAL_SECONDS,
        "next_fire_time":      next_fire_time(),
        "scheduler_backend":   "APScheduler BackgroundScheduler",
    }


# ── Rotation pass (called by scheduler and manual "Rotate Now") ───────────────

def run_rotation_pass(db: Session) -> dict:
    """
    Rotate all keys whose rotation_due_at has passed.
    Uses the lifecycle service to create immutable new versions.
    """
    now      = datetime.utcnow()
    due_keys = (
        db.query(CryptographicKey)
        .filter(
            CryptographicKey.status == KeyStatus.ACTIVE,
            CryptographicKey.rotation_due_at <= now,
        )
        .all()
    )

    results = {"rotated": [], "failed": [], "skipped": []}

    for key in due_keys:
        try:
            _lifecycle.rotate_key(db, key.id, reason="Automated scheduled rotation (APScheduler)")
            results["rotated"].append({"key_id": key.id, "alias": key.name})
        except Exception as exc:
            results["failed"].append({"key_id": key.id, "alias": key.name, "error": str(exc)})
            logger.error("Failed to rotate key %s: %s", key.name, exc)

    return results


def rotation_status_report(db: Session) -> dict:
    now       = datetime.utcnow()
    total     = db.query(CryptographicKey).count()
    due       = db.query(CryptographicKey).filter(
        CryptographicKey.status == KeyStatus.ACTIVE,
        CryptographicKey.rotation_due_at <= now,
    ).count()
    return {
        "total_keys":             total,
        "keys_due_rotation":      due,
        "rotation_health":        "critical" if due > 0 else "healthy",
        **scheduler_status(),
    }


# ── Legacy class interface (kept for backward-compat) ─────────────────────────

class RotationScheduler:
    def __init__(self):
        self.lifecycle = _lifecycle

    def get_keys_due_for_rotation(self, db: Session):
        now = datetime.utcnow()
        return db.query(CryptographicKey).filter(
            CryptographicKey.status == KeyStatus.ACTIVE,
            CryptographicKey.rotation_due_at <= now,
        ).all()

    def run_rotation_pass(self, db: Session) -> dict:
        return run_rotation_pass(db)

    def rotation_status_report(self, db: Session) -> dict:
        return rotation_status_report(db)
