from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    return (value or utc_now()).isoformat(timespec="seconds")


class Repository:
    """Small SQLite repository; version activation and retirement are one transaction."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS keys (
                    id TEXT PRIMARY KEY,
                    alias TEXT NOT NULL UNIQUE,
                    rotation_interval_seconds INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    next_rotation_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS key_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id TEXT NOT NULL REFERENCES keys(id),
                    version_number INTEGER NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('ACTIVE','RETIRED','REVOKED','DESTROYED')),
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    retired_at TEXT,
                    revoked_at TEXT,
                    destroyed_at TEXT,
                    classical_algorithm TEXT NOT NULL,
                    pqc_kem_algorithm TEXT NOT NULL,
                    pqc_signature_algorithm TEXT NOT NULL,
                    envelope_format TEXT NOT NULL,
                    public_material TEXT NOT NULL,
                    protected_material TEXT,
                    wrapped_dek TEXT,
                    kem_ciphertext TEXT,
                    risk_tags TEXT NOT NULL,
                    UNIQUE(key_id, version_number)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_version_per_key
                    ON key_versions(key_id) WHERE state = 'ACTIVE';
                CREATE TABLE IF NOT EXISTS rotation_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id TEXT NOT NULL REFERENCES keys(id),
                    old_version INTEGER,
                    new_version INTEGER NOT NULL,
                    trigger TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    details TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS audit_no_update
                    BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS audit_no_delete
                    BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END;
                """
            )

    @staticmethod
    def _rows(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
        return [dict(row) for row in rows]

    @staticmethod
    def _audit(
        db: sqlite3.Connection, action: str, entity_type: str, entity_id: str, details: dict[str, Any]
    ) -> None:
        db.execute(
            "INSERT INTO audit_events(occurred_at,action,entity_type,entity_id,details) VALUES(?,?,?,?,?)",
            (iso(), action, entity_type, entity_id, json.dumps(details, sort_keys=True)),
        )

    def create_key(self, key_id: str, alias: str, rotation_seconds: int, next_rotation_at: str) -> None:
        with self.transaction() as db:
            db.execute(
                "INSERT INTO keys(id,alias,rotation_interval_seconds,created_at,next_rotation_at) VALUES(?,?,?,?,?)",
                (key_id, alias, rotation_seconds, iso(), next_rotation_at),
            )
            self._audit(db, "KEY_CREATED", "key", key_id, {"alias": alias})

    def delete_empty_key(self, key_id: str) -> None:
        with self.transaction() as db:
            count = db.execute("SELECT COUNT(*) FROM key_versions WHERE key_id=?", (key_id,)).fetchone()[0]
            if count == 0:
                db.execute("DELETE FROM keys WHERE id=?", (key_id,))

    def add_version(
        self,
        key_id: str,
        material: dict[str, Any],
        next_rotation_at: str,
        trigger: str,
    ) -> int:
        with self.transaction() as db:
            key = db.execute("SELECT id FROM keys WHERE id=?", (key_id,)).fetchone()
            if not key:
                raise KeyError("key not found")
            current = db.execute(
                "SELECT version_number FROM key_versions WHERE key_id=? AND state='ACTIVE'", (key_id,)
            ).fetchone()
            old_version = current[0] if current else None
            next_version = db.execute(
                "SELECT COALESCE(MAX(version_number),0)+1 FROM key_versions WHERE key_id=?", (key_id,)
            ).fetchone()[0]
            if old_version is not None:
                db.execute(
                    "UPDATE key_versions SET state='RETIRED', retired_at=? WHERE key_id=? AND state='ACTIVE'",
                    (iso(), key_id),
                )
            db.execute(
                """INSERT INTO key_versions(
                       key_id,version_number,state,created_at,expires_at,classical_algorithm,
                       pqc_kem_algorithm,pqc_signature_algorithm,envelope_format,public_material,
                       protected_material,wrapped_dek,kem_ciphertext,risk_tags
                   ) VALUES(?,?,'ACTIVE',?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    key_id,
                    next_version,
                    iso(),
                    material["expires_at"],
                    material["classical_algorithm"],
                    material["pqc_kem_algorithm"],
                    material["pqc_signature_algorithm"],
                    material["envelope_format"],
                    json.dumps(material["public_material"], sort_keys=True),
                    material["protected_material"],
                    material["wrapped_dek"],
                    material["kem_ciphertext"],
                    json.dumps(material["risk_tags"]),
                ),
            )
            db.execute("UPDATE keys SET next_rotation_at=? WHERE id=?", (next_rotation_at, key_id))
            db.execute(
                "INSERT INTO rotation_events(key_id,old_version,new_version,trigger,created_at) VALUES(?,?,?,?,?)",
                (key_id, old_version, next_version, trigger, iso()),
            )
            self._audit(
                db,
                "KEY_ROTATED" if old_version else "VERSION_ACTIVATED",
                "key",
                key_id,
                {
                    "old_version": old_version,
                    "new_version": next_version,
                    "trigger": trigger,
                    "providers": material["public_material"].get("providers", []),
                },
            )
            return next_version

    def transition_version(self, version_id: int, target: str) -> None:
        if target not in {"REVOKED", "DESTROYED"}:
            raise ValueError("only REVOKED or DESTROYED are explicit lifecycle actions")
        with self.transaction() as db:
            row = db.execute("SELECT * FROM key_versions WHERE id=?", (version_id,)).fetchone()
            if not row:
                raise KeyError("version not found")
            if row["state"] == "DESTROYED":
                raise ValueError("destroyed versions are terminal")
            now = iso()
            if target == "REVOKED":
                db.execute(
                    "UPDATE key_versions SET state='REVOKED', revoked_at=?, risk_tags=? WHERE id=?",
                    (now, json.dumps(["NON_COMPLIANT"]), version_id),
                )
            else:
                db.execute(
                    """UPDATE key_versions SET state='DESTROYED', destroyed_at=?, risk_tags=?,
                       protected_material=NULL, wrapped_dek=NULL, kem_ciphertext=NULL WHERE id=?""",
                    (now, json.dumps(["NON_COMPLIANT"]), version_id),
                )
            self._audit(db, f"VERSION_{target}", "version", str(version_id), {"previous": row["state"]})

    def record_audit(self, action: str, entity_type: str, entity_id: str, details: dict[str, Any]) -> None:
        with self.transaction() as db:
            self._audit(db, action, entity_type, entity_id, details)

    def list_keys(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            return self._rows(
                db.execute(
                    """SELECT k.*, COUNT(v.id) AS version_count,
                       MAX(CASE WHEN v.state='ACTIVE' THEN v.version_number END) AS active_version
                       FROM keys k LEFT JOIN key_versions v ON v.key_id=k.id
                       GROUP BY k.id ORDER BY k.created_at DESC"""
                ).fetchall()
            )

    def get_key(self, key_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM keys WHERE id=?", (key_id,)).fetchone()
            return dict(row) if row else None

    def list_versions(self, key_id: str | None = None) -> list[dict[str, Any]]:
        with self.connect() as db:
            if key_id:
                rows = db.execute(
                    "SELECT * FROM key_versions WHERE key_id=? ORDER BY version_number DESC", (key_id,)
                ).fetchall()
            else:
                rows = db.execute("SELECT * FROM key_versions ORDER BY created_at DESC").fetchall()
            return self._rows(rows)

    def get_version(self, key_id: str, version: int | None = None) -> dict[str, Any] | None:
        with self.connect() as db:
            if version is None:
                row = db.execute(
                    "SELECT * FROM key_versions WHERE key_id=? AND state='ACTIVE'", (key_id,)
                ).fetchone()
            else:
                row = db.execute(
                    "SELECT * FROM key_versions WHERE key_id=? AND version_number=?", (key_id, version)
                ).fetchone()
            return dict(row) if row else None

    def due_key_ids(self, now: str) -> list[str]:
        with self.connect() as db:
            return [row[0] for row in db.execute("SELECT id FROM keys WHERE next_rotation_at<=?", (now,))]

    def report_data(self) -> dict[str, Any]:
        with self.connect() as db:
            keys = self._rows(db.execute("SELECT * FROM keys ORDER BY alias").fetchall())
            versions = self._rows(db.execute("SELECT * FROM key_versions ORDER BY key_id,version_number").fetchall())
            rotations = self._rows(db.execute("SELECT * FROM rotation_events ORDER BY id DESC").fetchall())
            audits = self._rows(db.execute("SELECT * FROM audit_events ORDER BY id DESC").fetchall())
        for version in versions:
            version["risk_tags"] = json.loads(version["risk_tags"])
            version["public_material"] = json.loads(version["public_material"])
            version.pop("protected_material", None)
            version.pop("wrapped_dek", None)
            version.pop("kem_ciphertext", None)
        for event in audits:
            event["details"] = json.loads(event["details"])
        return {"keys": keys, "versions": versions, "rotation_events": rotations, "audit_events": audits}
