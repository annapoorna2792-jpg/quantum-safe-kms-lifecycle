"""
Quantum-Safe KMS — Application Configuration
All tunable parameters are read from environment variables (or .env file).
"""
import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── Application ────────────────────────────────────────────────────────────
    APP_NAME: str = "Quantum-Safe KMS"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False

    # ── Database ───────────────────────────────────────────────────────────────
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./quantum_kms.db")

    # ── Security ───────────────────────────────────────────────────────────────
    SECRET_KEY: str = os.getenv("SECRET_KEY", "changeme-in-production")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # ── Provider mode ──────────────────────────────────────────────────────────
    # "sim" = local simulation only; "auto" = try live, fall back to sim
    PROVIDER_MODE: str = os.getenv("PROVIDER_MODE", "auto")
    DEFAULT_KMS_PROVIDER: str = os.getenv("DEFAULT_KMS_PROVIDER", "aws_kms")

    # ── AWS KMS (Chapter 8.1 — live via EC2 IAM role) ─────────────────────────
    AWS_REGION: str = os.getenv("AWS_REGION", "eu-north-1")
    AWS_KMS_KEY_ALIAS: str = os.getenv("AWS_KMS_KEY_ALIAS", "alias/quantum-safe-kms-demo")
    AWS_KMS_KEY_ID: str = os.getenv("AWS_KMS_KEY_ID", "")

    # ── Azure Key Vault (Chapter 8.7 — live adapter) ──────────────────────────
    AZURE_VAULT_URL: str = os.getenv("AZURE_VAULT_URL", "")
    AZURE_CLIENT_ID: str = os.getenv("AZURE_CLIENT_ID", "")
    AZURE_CLIENT_SECRET: str = os.getenv("AZURE_CLIENT_SECRET", "")
    AZURE_TENANT_ID: str = os.getenv("AZURE_TENANT_ID", "")

    # ── Crypto settings (Chapter 8.2) ─────────────────────────────────────────
    DEFAULT_CLASSICAL_ALGO: str = "AES-256-GCM"
    DEFAULT_PQC_ALGO: str = "ML-KEM-768"        # FIPS 203, NIST Level 3
    DEFAULT_SIGN_ALGO: str = "ML-DSA-65"         # FIPS 204
    HYBRID_MODE: bool = True

    # ── Rotation policy ────────────────────────────────────────────────────────
    KEY_ROTATION_DAYS: int = int(os.getenv("KEY_ROTATION_DAYS", "365"))  # PCI-DSS v4 §3.7.1
    ROTATION_INTERVAL_SECONDS: int = int(os.getenv("ROTATION_INTERVAL_SECONDS", "120"))

    # ── Demo seed ─────────────────────────────────────────────────────────────
    DEFAULT_KEY_ALIAS: str = os.getenv("DEFAULT_KEY_ALIAS", "customer-data")
    SEED_DEMO_KEY: bool = os.getenv("SEED_DEMO_KEY", "true").lower() == "true"

    class Config:
        env_file = ".env"


settings = Settings()
