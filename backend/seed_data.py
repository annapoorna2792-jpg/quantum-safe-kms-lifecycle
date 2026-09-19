"""
seed_data.py  –  Populate the Quantum-Safe KMS database with realistic demo data.
Run from the backend/ directory:
    python seed_data.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import uuid
from datetime import datetime, timedelta
from app.database import SessionLocal, engine
from app import models

models.Base.metadata.create_all(bind=engine)

db = SessionLocal()

# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────
def ago(days=0, hours=0):
    return datetime.utcnow() - timedelta(days=days, hours=hours)

def future(days):
    return datetime.utcnow() + timedelta(days=days)


# ──────────────────────────────────────────────────────────────
# 30 Cryptographic Keys
# ──────────────────────────────────────────────────────────────
KEYS = [
    # ── PQC keys (quantum-safe) ─────────────────────────────
    dict(name="prod-kyber-api-gateway",         algorithm="KYBER-1024",            key_size=1024, kms_provider="aws_sim",   status="active",   risk_level="low",      owner="platform-team",   environment="production",  purpose="API authentication",           is_quantum_safe=True,  is_hybrid=False, created_at=ago(10),  rotation_due_at=future(80),  rotation_count=0),
    dict(name="prod-kyber-database-encryption", algorithm="KYBER-1024",            key_size=1024, kms_provider="azure_sim", status="active",   risk_level="low",      owner="dba-team",        environment="production",  purpose="Database column encryption",   is_quantum_safe=True,  is_hybrid=False, created_at=ago(25),  rotation_due_at=future(65),  rotation_count=1),
    dict(name="prod-dilithium-code-signing",    algorithm="DILITHIUM-5",           key_size=256,  kms_provider="aws_sim",   status="active",   risk_level="low",      owner="devops-team",     environment="production",  purpose="CI/CD pipeline signing",       is_quantum_safe=True,  is_hybrid=False, created_at=ago(5),   rotation_due_at=future(85),  rotation_count=0),
    dict(name="prod-dilithium-firmware-sign",   algorithm="DILITHIUM-5",           key_size=256,  kms_provider="gcp_sim",   status="active",   risk_level="low",      owner="embedded-team",   environment="production",  purpose="Firmware image signing",       is_quantum_safe=True,  is_hybrid=False, created_at=ago(18),  rotation_due_at=future(72),  rotation_count=0),
    dict(name="prod-sphincs-audit-log-sign",    algorithm="SPHINCS+",              key_size=256,  kms_provider="aws_sim",   status="active",   risk_level="low",      owner="security-team",   environment="production",  purpose="Audit log integrity signing",  is_quantum_safe=True,  is_hybrid=False, created_at=ago(3),   rotation_due_at=future(87),  rotation_count=0),
    dict(name="staging-kyber-kem-service",      algorithm="KYBER-1024",            key_size=1024, kms_provider="azure_sim", status="active",   risk_level="low",      owner="api-team",        environment="staging",     purpose="Inter-service key exchange",   is_quantum_safe=True,  is_hybrid=False, created_at=ago(7),   rotation_due_at=future(83),  rotation_count=0),
    dict(name="dev-dilithium-jwt-signing",      algorithm="DILITHIUM-5",           key_size=256,  kms_provider="gcp_sim",   status="inactive", risk_level="low",      owner="backend-team",    environment="development",  purpose="JWT token signing",           is_quantum_safe=True,  is_hybrid=False, created_at=ago(60),  rotation_due_at=future(30),  rotation_count=2),

    # ── Hybrid keys ─────────────────────────────────────────
    dict(name="prod-hybrid-kem-payment-gateway",   algorithm="HYBRID-KYBER-AES",     key_size=1024, kms_provider="aws_sim",   status="active",   risk_level="low",      owner="payments-team",   environment="production",  purpose="Payment data encryption",      is_quantum_safe=True,  is_hybrid=True,  created_at=ago(12),  rotation_due_at=future(78),  rotation_count=1),
    dict(name="prod-hybrid-kem-health-records",    algorithm="HYBRID-KYBER-AES",     key_size=1024, kms_provider="azure_sim", status="active",   risk_level="low",      owner="hipaa-team",      environment="production",  purpose="PHI data encryption",          is_quantum_safe=True,  is_hybrid=True,  created_at=ago(20),  rotation_due_at=future(70),  rotation_count=0),
    dict(name="prod-hybrid-sig-contract-signing",  algorithm="HYBRID-DILITHIUM-RSA", key_size=4096, kms_provider="gcp_sim",   status="active",   risk_level="low",      owner="legal-team",      environment="production",  purpose="Smart contract signing",       is_quantum_safe=True,  is_hybrid=True,  created_at=ago(8),   rotation_due_at=future(82),  rotation_count=0),
    dict(name="prod-hybrid-sig-document-vault",    algorithm="HYBRID-DILITHIUM-RSA", key_size=4096, kms_provider="aws_sim",   status="active",   risk_level="low",      owner="compliance-team", environment="production",  purpose="Document vault signing",       is_quantum_safe=True,  is_hybrid=True,  created_at=ago(35),  rotation_due_at=future(55),  rotation_count=2),
    dict(name="staging-hybrid-kem-auth",           algorithm="HYBRID-KYBER-AES",     key_size=1024, kms_provider="azure_sim", status="active",   risk_level="medium",   owner="auth-team",       environment="staging",     purpose="OAuth2 token encryption",      is_quantum_safe=True,  is_hybrid=True,  created_at=ago(45),  rotation_due_at=future(45),  rotation_count=1),

    # ── Classical AES keys ──────────────────────────────────
    dict(name="prod-aes-s3-backup-encryption",  algorithm="AES-256-GCM",           key_size=256,  kms_provider="aws_sim",   status="active",   risk_level="medium",   owner="infra-team",      environment="production",  purpose="S3 backup encryption",         is_quantum_safe=False, is_hybrid=False, created_at=ago(90),  rotation_due_at=future(0),   rotation_count=3),
    dict(name="prod-aes-secrets-manager",       algorithm="AES-256-GCM",           key_size=256,  kms_provider="azure_sim", status="active",   risk_level="medium",   owner="devops-team",     environment="production",  purpose="Secrets manager master key",   is_quantum_safe=False, is_hybrid=False, created_at=ago(120), rotation_due_at=ago(30),     rotation_count=4),
    dict(name="prod-aes-logs-at-rest",          algorithm="AES-256-GCM",           key_size=256,  kms_provider="gcp_sim",   status="active",   risk_level="medium",   owner="platform-team",   environment="production",  purpose="Log storage encryption",       is_quantum_safe=False, is_hybrid=False, created_at=ago(60),  rotation_due_at=future(30),  rotation_count=2),
    dict(name="staging-aes-cache-encryption",   algorithm="AES-256-GCM",           key_size=256,  kms_provider="aws_sim",   status="active",   risk_level="low",      owner="backend-team",    environment="staging",     purpose="Redis cache encryption",       is_quantum_safe=False, is_hybrid=False, created_at=ago(15),  rotation_due_at=future(75),  rotation_count=0),
    dict(name="dev-aes-test-data",              algorithm="AES-256-GCM",           key_size=256,  kms_provider="gcp_sim",   status="inactive", risk_level="low",      owner="qa-team",         environment="development", purpose="Test data masking",            is_quantum_safe=False, is_hybrid=False, created_at=ago(200), rotation_due_at=ago(110),    rotation_count=5),

    # ── Classical RSA keys (HIGH risk – quantum vulnerable) ─
    dict(name="prod-rsa-legacy-tls",            algorithm="RSA-4096",              key_size=4096, kms_provider="aws_sim",   status="active",   risk_level="high",     owner="networking-team", environment="production",  purpose="Legacy TLS termination",       is_quantum_safe=False, is_hybrid=False, created_at=ago(300), rotation_due_at=ago(210),    rotation_count=6),
    dict(name="prod-rsa-email-encryption",      algorithm="RSA-4096",              key_size=4096, kms_provider="azure_sim", status="active",   risk_level="high",     owner="comms-team",      environment="production",  purpose="S/MIME email encryption",      is_quantum_safe=False, is_hybrid=False, created_at=ago(180), rotation_due_at=ago(90),     rotation_count=3),
    dict(name="prod-rsa-ssh-bastion",           algorithm="RSA-4096",              key_size=4096, kms_provider="gcp_sim",   status="active",   risk_level="high",     owner="sre-team",        environment="production",  purpose="Bastion host SSH key",         is_quantum_safe=False, is_hybrid=False, created_at=ago(400), rotation_due_at=ago(310),    rotation_count=8),
    dict(name="staging-rsa-api-client-cert",    algorithm="RSA-4096",              key_size=4096, kms_provider="aws_sim",   status="rotated",  risk_level="high",     owner="api-team",        environment="staging",     purpose="mTLS client certificates",     is_quantum_safe=False, is_hybrid=False, created_at=ago(150), rotation_due_at=ago(60),     rotation_count=2),
    dict(name="dev-rsa-jwt-legacy",             algorithm="RSA-4096",              key_size=4096, kms_provider="azure_sim", status="revoked",  risk_level="critical", owner="backend-team",    environment="development", purpose="Legacy JWT signing (deprecated)",is_quantum_safe=False, is_hybrid=False, created_at=ago(500), rotation_due_at=ago(410),    rotation_count=9),

    # ── ECC keys (HIGH risk – quantum vulnerable) ───────────
    dict(name="prod-ecc-iot-device-identity",   algorithm="ECC-P521",              key_size=521,  kms_provider="aws_sim",   status="active",   risk_level="high",     owner="iot-team",        environment="production",  purpose="IoT device identity certs",    is_quantum_safe=False, is_hybrid=False, created_at=ago(200), rotation_due_at=ago(110),    rotation_count=4),
    dict(name="prod-ecc-mobile-push-notif",     algorithm="ECC-P521",              key_size=521,  kms_provider="gcp_sim",   status="active",   risk_level="high",     owner="mobile-team",     environment="production",  purpose="APNS/FCM signing",             is_quantum_safe=False, is_hybrid=False, created_at=ago(90),  rotation_due_at=future(0),   rotation_count=2),
    dict(name="prod-ecc-cdn-signing",           algorithm="ECC-P521",              key_size=521,  kms_provider="azure_sim", status="active",   risk_level="high",     owner="cdn-team",        environment="production",  purpose="CloudFront signed URLs",       is_quantum_safe=False, is_hybrid=False, created_at=ago(130), rotation_due_at=ago(40),     rotation_count=3),
    dict(name="staging-ecc-oauth-signing",      algorithm="ECC-P521",              key_size=521,  kms_provider="aws_sim",   status="rotated",  risk_level="medium",   owner="auth-team",       environment="staging",     purpose="OAuth2 PKCE signing",          is_quantum_safe=False, is_hybrid=False, created_at=ago(75),  rotation_due_at=future(15),  rotation_count=1),

    # ── Expired / revoked keys (lifecycle demo) ─────────────
    dict(name="prod-aes-old-archive-enc",       algorithm="AES-256-GCM",           key_size=256,  kms_provider="azure_sim", status="expired",  risk_level="medium",   owner="archive-team",    environment="production",  purpose="Archive storage (expired)",    is_quantum_safe=False, is_hybrid=False, created_at=ago(730), rotation_due_at=ago(640),    rotation_count=10),
    dict(name="prod-rsa-decommissioned-vpn",    algorithm="RSA-4096",              key_size=4096, kms_provider="gcp_sim",   status="revoked",  risk_level="critical", owner="network-team",    environment="production",  purpose="VPN endpoint (decommissioned)",is_quantum_safe=False, is_hybrid=False, created_at=ago(600), rotation_due_at=ago(510),    rotation_count=7),
    dict(name="prod-kyber-rotated-prev",        algorithm="KYBER-1024",            key_size=1024, kms_provider="aws_sim",   status="rotated",  risk_level="low",      owner="platform-team",   environment="production",  purpose="Previous API auth key",        is_quantum_safe=True,  is_hybrid=False, created_at=ago(100), rotation_due_at=ago(10),     rotation_count=1),
    dict(name="prod-hybrid-kem-retired",        algorithm="HYBRID-KYBER-AES",      key_size=1024, kms_provider="azure_sim", status="rotated",  risk_level="low",      owner="payments-team",   environment="production",  purpose="Previous payment enc key",     is_quantum_safe=True,  is_hybrid=True,  created_at=ago(95),  rotation_due_at=ago(5),      rotation_count=1),
    dict(name="prod-ecc-critical-breach",       algorithm="ECC-P521",              key_size=521,  kms_provider="gcp_sim",   status="revoked",  risk_level="critical", owner="security-team",   environment="production",  purpose="Revoked after breach detection",is_quantum_safe=False, is_hybrid=False, created_at=ago(60),  rotation_due_at=ago(55),     rotation_count=0),
    dict(name="dev-rsa-pentest-key",            algorithm="RSA-4096",              key_size=4096, kms_provider="aws_sim",   status="inactive", risk_level="high",     owner="security-team",   environment="development", purpose="Penetration testing",          is_quantum_safe=False, is_hybrid=False, created_at=ago(45),  rotation_due_at=future(45),  rotation_count=0),
]

# ──────────────────────────────────────────────────────────────
# Insert Keys
# ──────────────────────────────────────────────────────────────
inserted_ids = []
existing = db.query(models.CryptographicKey).count()
if existing > 0:
    print(f"INFO: Database already has {existing} keys — collecting existing IDs to seed audit logs.")
    inserted_ids = [row.id for row in db.query(models.CryptographicKey).all()]
else:
    for k in KEYS:
        key_id = str(uuid.uuid4())
        inserted_ids.append(key_id)
        rot_count = k.get("rotation_count", 0)
        db.add(models.CryptographicKey(
            id=key_id,
            name=k["name"],
            algorithm=k["algorithm"],
            key_size=k.get("key_size"),
            status=k["status"],
            risk_level=k["risk_level"],
            kms_provider=k["kms_provider"],
            kms_key_id=f"arn:kms:{k['kms_provider']}:{uuid.uuid4().hex[:12]}",
            created_at=k["created_at"],
            updated_at=k["created_at"],
            expires_at=k["created_at"] + timedelta(days=365),
            last_rotated_at=k["created_at"] + timedelta(days=30) if rot_count > 0 else None,
            rotation_due_at=k["rotation_due_at"],
            owner=k.get("owner"),
            environment=k.get("environment", "production"),
            purpose=k.get("purpose"),
            is_quantum_safe=k.get("is_quantum_safe", False),
            is_hybrid=k.get("is_hybrid", False),
            rotation_count=rot_count,
            version=rot_count + 1,
            active_version_number=rot_count + 1,
            total_versions=rot_count + 1,
            tags={"env": k.get("environment", "production"), "team": k.get("owner", "unknown")},
        ))

    db.commit()
    print(f"Inserted {len(KEYS)} cryptographic keys")

# ──────────────────────────────────────────────────────────────
# Audit Log Events (80 entries)
# ──────────────────────────────────────────────────────────────
ACTIONS = [
    ("CREATE",  True,  "Key created via dashboard",         0),
    ("ENCRYPT", True,  "Data encrypted successfully",       1),
    ("DECRYPT", True,  "Data decrypted successfully",       2),
    ("ROTATE",  True,  "Manual rotation triggered",         5),
    ("ROTATE",  True,  "Scheduled rotation completed",      10),
    ("REVOKE",  True,  "Key revoked by security-team",      20),
    ("ENCRYPT", False, "Decryption failed: key not found",  3),
    ("AUDIT",   True,  "Compliance audit completed",        7),
    ("VERIFY",  True,  "Signature verified",                1),
    ("SIGN",    True,  "Document signed",                   2),
    ("EXPORT",  False, "Export denied: policy violation",   4),
    ("ROTATE",  True,  "Emergency rotation - breach alert", 15),
    ("LIST",    True,  "Key inventory listed",              0),
    ("DECRYPT", False, "Unauthorized access attempt",       8),
    ("UPDATE",  True,  "Key metadata updated",              1),
]

actors = [
    "alice@example.com", "bob@example.com", "ci-pipeline",
    "charlie@example.com", "sre-bot", "compliance-scanner",
    "pentest-automation", "rotation-scheduler", "audit-service",
]

import random
random.seed(42)

audit_logs = []
for i in range(80):
    action, success, detail, _delay = random.choice(ACTIONS)
    key_id = random.choice(inserted_ids)
    ts = ago(days=random.randint(0, 30), hours=random.randint(0, 23))
    audit_logs.append(models.AuditLog(
        id=str(uuid.uuid4()),
        key_id=key_id,
        action=action,
        actor=random.choice(actors),
        timestamp=ts,
        details={"message": detail, "source": "seed_data"},
        ip_address=f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        success=success,
        error_message=None if success else detail,
    ))

db.bulk_save_objects(audit_logs)
db.commit()
print(f"Inserted {len(audit_logs)} audit log events")

# ──────────────────────────────────────────────────────────────
# Compliance Reports (3 standards)
# ──────────────────────────────────────────────────────────────
total = len(KEYS)
pqc_count = sum(1 for k in KEYS if k["is_quantum_safe"])
classical_count = total - pqc_count

reports = [
    models.ComplianceReport(
        id=str(uuid.uuid4()),
        report_type="NIST",
        generated_at=ago(days=7),
        total_keys=total,
        compliant_keys=pqc_count,
        non_compliant_keys=classical_count,
        risk_summary={"compliance_score": round(pqc_count/total*100, 1), "standard": "NIST SP 800-131A"},
        findings=[
            {"finding": "RSA keys must be migrated to PQC", "severity": "HIGH", "count": 6},
            {"finding": "ECC keys vulnerable to Shor's algorithm", "severity": "HIGH", "count": 4},
        ],
        report_data={"generated_by": "seed_data", "version": "1.0"},
    ),
    models.ComplianceReport(
        id=str(uuid.uuid4()),
        report_type="FIPS",
        generated_at=ago(days=3),
        total_keys=total,
        compliant_keys=pqc_count + 4,
        non_compliant_keys=classical_count - 4,
        risk_summary={"compliance_score": round((pqc_count+4)/total*100, 1), "standard": "FIPS 140-3"},
        findings=[
            {"finding": "AES-256-GCM approved for use", "severity": "INFO", "count": 5},
            {"finding": "Rotation overdue for 4 keys", "severity": "MEDIUM", "count": 4},
        ],
        report_data={"generated_by": "seed_data", "version": "1.0"},
    ),
    models.ComplianceReport(
        id=str(uuid.uuid4()),
        report_type="ISO",
        generated_at=ago(days=1),
        total_keys=total,
        compliant_keys=pqc_count + 2,
        non_compliant_keys=classical_count - 2,
        risk_summary={"compliance_score": round((pqc_count+2)/total*100, 1), "standard": "ISO 27001:2022 Annex A"},
        findings=[
            {"finding": "Key rotation policy violated for 6 keys", "severity": "HIGH", "count": 6},
            {"finding": "Revoked keys should be archived", "severity": "LOW", "count": 3},
        ],
        report_data={"generated_by": "seed_data", "version": "1.0"},
    ),
]

db.bulk_save_objects(reports)
db.commit()
print(f"Inserted {len(reports)} compliance reports")

db.close()
print("\nDemo data loaded! Refresh the dashboard at http://localhost:3000")
