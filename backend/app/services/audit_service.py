"""
Audit Service: query and expose audit log entries.
"""
from sqlalchemy.orm import Session
from app.models import AuditLog


class AuditService:

    def get_logs(self, db: Session, key_id: str = None, action: str = None,
                 skip: int = 0, limit: int = 100) -> list[AuditLog]:
        q = db.query(AuditLog).order_by(AuditLog.timestamp.desc())
        if key_id:
            q = q.filter(AuditLog.key_id == key_id)
        if action:
            q = q.filter(AuditLog.action == action)
        return q.offset(skip).limit(limit).all()

    def get_recent_events(self, db: Session, limit: int = 20) -> list[AuditLog]:
        return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()

    def count_events(self, db: Session) -> int:
        return db.query(AuditLog).count()

    def get_failed_operations(self, db: Session, limit: int = 50) -> list[AuditLog]:
        return (
            db.query(AuditLog)
            .filter(AuditLog.success == False)  # noqa: E712
            .order_by(AuditLog.timestamp.desc())
            .limit(limit)
            .all()
        )
