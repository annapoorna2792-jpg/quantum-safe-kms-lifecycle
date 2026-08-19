# Quantum-Safe Secure Key Lifecycle Management in Multi-Cloud KMS

This FastAPI capstone demonstrates risk-driven immutable key versions, automated rotation, hybrid classical/post-quantum envelope encryption, dual signatures, and compliance evidence.

## Deployment truth

- **AWS KMS is live.** The application calls `DescribeKey`, `GenerateDataKey`, and `Decrypt` in `eu-north-1` through the EC2 instance role.
- **Azure Key Vault is an explicit extension simulation.** No Azure credentials or Azure API calls are used because an Azure account was unavailable for this deployment.
- **PQC is real prototype crypto.** The Docker image builds `liboqs 0.16.0` with ML-KEM-768 and ML-DSA-65.
- The hybrid combiner and `QSKMS-AWS-HYBRID-ENVELOPE/v2` are educational custom formats, not standardized or production-reviewed protocols.

The fixed capstone title remains multi-cloud because the design contains separate provider adapters and a visible Azure extension point, while the implemented reference deployment is AWS.

## What the application demonstrates

- SQLite inventory with immutable numbered versions and `ACTIVE`, `RETIRED`, `REVOKED`, and `DESTROYED` states.
- Atomic rotation: the new version becomes active and the previous version becomes retired.
- Automated APScheduler rotation, plus a **Rotate Now** control.
- Real AWS KMS AES-256 data-key generation and recovery using the EC2 IAM role.
- AES-256-GCM content encryption and AES-256 key wrapping.
- ML-KEM-768 encapsulation/decapsulation and ML-DSA-65 signing/verification through `liboqs-python`.
- ECDSA P-256 plus ML-DSA-65 hybrid-signature verification.
- Compliance JSON containing AWS region, configured KMS alias, resolved key ARN, inventory, algorithms, rotation history, risk tags, and append-only audit events.

## Architecture

```text
Browser / FastAPI dashboard
            |
       Lifecycle service -------- APScheduler rotation policy
            |
      SQLite immutable versions
            |
      Hybrid crypto engine
       /        |         \
AWS KMS LIVE  Azure SIM   liboqs
GenerateDataKey AES-256   ML-KEM-768 / ML-DSA-65
       \        |         /
        HKDF hybrid KEK -> AES-KW(DEK) -> AES-256-GCM(data)
```

For each logical key version, AWS KMS creates a 256-bit data-key contribution. Only the KMS-encrypted ciphertext blob is persisted. The application must call AWS KMS `Decrypt` with the same encryption context before the hybrid key-encryption key can be reconstructed. The Azure extension contribution and ML-KEM private material are sealed locally under `DEMO_MASTER_KEY` for this prototype.

## Required AWS configuration

### KMS key

- Region: `eu-north-1`
- Alias: `alias/quantum-safe-kms-demo`
- Type: symmetric
- Usage: encrypt and decrypt
- State: enabled

### EC2 role permissions

Attach `QuantumSafeKMS-EC2-Role` to the EC2 instance and give it this key-scoped policy, replacing the example ARN if the key changes:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "UseQuantumSafeDemoKey",
      "Effect": "Allow",
      "Action": [
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "kms:GenerateDataKeyWithoutPlaintext",
        "kms:GetKeyRotationStatus"
      ],
      "Resource": "arn:aws:kms:eu-north-1:YOUR_AWS_ACCOUNT_ID:key/YOUR_KMS_KEY_ID"
    }
  ]
}
```

Verify from the EC2 host:

```bash
aws sts get-caller-identity
aws kms describe-key --key-id alias/quantum-safe-kms-demo --region eu-north-1
```

Do not run `aws configure` on EC2. The application uses temporary role credentials.

## EC2 Docker deployment

The default host port is `8001` so an existing Capstone 1 service on port `8000` can continue running.

### 1. Allow containers to receive role credentials

Docker adds a network hop between the container and EC2 instance metadata. In the EC2 console, select the instance and choose **Actions → Instance settings → Modify instance metadata options**. Keep IMDSv2 required and set **Metadata response hop limit** to `2`.

### 2. Copy and enter the project

Upload or clone this directory, then:

```bash
cd quantum-safe-kms-demo
```

### 3. Create the environment file

```bash
umask 077
python3 -c 'import secrets,base64; print("DEMO_MASTER_KEY=" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())' > .env
printf '\nROTATION_INTERVAL_SECONDS=120\nAWS_REGION=eu-north-1\nAWS_KMS_KEY_ID=alias/quantum-safe-kms-demo\nAPP_PORT=8001\n' >> .env
```

Keep this `.env` file with the matching `data/` directory. Changing or losing the master key makes existing versions unrecoverable.

### 4. Build and start

```bash
docker compose up --build -d
docker compose ps
curl -fsS http://127.0.0.1:8001/healthz | python3 -m json.tool
```

The health response must contain:

```json
{
  "status": "ok",
  "pqc": {"available": true},
  "aws_kms": {"available": true, "mode": "LIVE", "region": "eu-north-1"},
  "azure_key_vault": {"available": false, "mode": "SIMULATION"}
}
```

If startup fails:

```bash
docker compose logs --tail=150 quantum-safe-kms
```

### 5. Open the dashboard

Add an inbound security-group rule for TCP `8001` from only your current public IP, then open:

```text
http://EC2_PUBLIC_IP:8001
```

Pages:

- Dashboard: `/`
- Key Lifecycle: `/keys`
- Hybrid Demo: `/demo`
- Compliance: `/compliance`
- Downloadable evidence: `/api/compliance.json`

## Five-minute demonstration

1. On **Dashboard**, show `AWS KMS — LIVE`, the Stockholm region, and the KMS alias. Explain that Azure is an explicit adapter simulation because the account was unavailable.
2. On **Key Lifecycle**, create alias `customer-data` with rotation `120`. This calls AWS KMS `GenerateDataKey` and creates ML-KEM-768 material.
3. On **Hybrid Demo**, encrypt `Harvest report: 42 tonnes` using context `demo-tenant-1`, then decrypt it.
4. Return to **Key Lifecycle**, click **Rotate Now**, and show version 2 as `ACTIVE` and version 1 as `RETIRED`.
5. Decrypt the old version-1 envelope again. The envelope selects the immutable old version, and AWS KMS decrypts that version's stored KMS ciphertext blob.
6. Create and verify both ECDSA P-256 and ML-DSA-65 signatures.
7. On **Compliance**, show the live AWS evidence, algorithm inventory, rotations, risk tags, and append-only audit entries. Download the JSON report.

## Tests

Repository and AWS adapter tests can run without a live cloud account. Native hybrid crypto tests run when matching `liboqs` is installed:

```bash
pytest -q
docker compose config
```

For a container-level native check:

```bash
docker compose run --rm \
  -e SCHEDULER_ENABLED=false \
  quantum-safe-kms python -c 'from app.crypto import pqc_status; assert pqc_status()["available"]; print(pqc_status())'
```

## Configuration

| Variable | Required | Default | Purpose |
|---|---:|---|---|
| `DEMO_MASTER_KEY` | yes | none | URL-safe base64 encoding of exactly 32 random bytes |
| `AWS_REGION` | yes | `eu-north-1` | AWS SDK region |
| `AWS_KMS_KEY_ID` | yes | `alias/quantum-safe-kms-demo` | Live symmetric KMS key alias or ARN |
| `DATABASE_PATH` | no | `/app/data/quantum_safe_kms.db` | SQLite database path |
| `ROTATION_INTERVAL_SECONDS` | no | `120` | Default rotation and scheduler policy; minimum 10 |
| `APP_PORT` | no | `8001` | EC2 host port mapped to container port 8000 |
| `SCHEDULER_ENABLED` | no | `true` | Enables the single-process rotation scheduler |

## Limitations

This is an academic demonstration. It has no user authentication, authorization, CSRF protection, production secret manager, HSM isolation for locally held prototype materials, distributed locking, high availability, rate limiting, or TLS termination. Azure is not live. `liboqs` is a research/prototyping implementation and no FIPS validation is claimed. Do not use the custom hybrid format for production data.
