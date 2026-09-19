# Quantum-Safe KMS — Threat Model

## Scope

This document covers cryptographic and operational threats to the Quantum-Safe KMS system, aligned with STRIDE methodology and NIST SP 800-57.

---

## Threat Actors

| Actor | Motivation | Capability |
|-------|-----------|-----------|
| Nation-state adversary | Harvest-now-decrypt-later | Quantum computers (future) |
| External attacker | Key theft, data exfiltration | Classical compute |
| Malicious insider | Key misuse, unauthorized access | System access |
| Automated attacker | Brute-force, replay attacks | Botnets |

---

## STRIDE Threat Analysis

### Spoofing
- **Threat**: Attacker impersonates a legitimate key consumer.
- **Mitigation**: Authentication tokens + audit logging of all key access.

### Tampering
- **Threat**: Key material modified in transit or at rest.
- **Mitigation**: AES-GCM provides authenticated encryption (AEAD). All key material is integrity-protected.

### Repudiation
- **Threat**: Actor denies performing a key operation.
- **Mitigation**: Immutable audit log with timestamps, actor identity, and operation details.

### Information Disclosure
- **Threat**: Private key material leaked via side-channel or storage breach.
- **Mitigation**: Key material never stored in plaintext. KMS provider holds encrypted blobs. Public keys only exposed via API.

### Denial of Service
- **Threat**: KMS API flooded, making keys unavailable.
- **Mitigation**: Rate limiting (add via API gateway). Health check endpoint for monitoring.

### Elevation of Privilege
- **Threat**: Low-privilege actor accesses or rotates high-value keys.
- **Mitigation**: Role-based access control on API endpoints (implement with OAuth2/JWT).

---

## Quantum Threat Landscape

| Algorithm | Vulnerable to Shor's? | Vulnerable to Grover's? | Migration Path |
|-----------|----------------------|------------------------|----------------|
| RSA-4096  | ✅ Yes (polynomial time) | No | → KYBER-1024 or HYBRID-KYBER-AES |
| ECC-P521  | ✅ Yes (polynomial time) | No | → DILITHIUM-5 |
| AES-256-GCM | No | Partial (128-bit effective) | Acceptable; monitor NIST guidance |
| KYBER-1024 | No | No | Current NIST standard (FIPS 203) |
| DILITHIUM-5 | No | No | Current NIST standard (FIPS 204) |
| SPHINCS+ | No | No | Conservative hash-based (FIPS 205) |

### Harvest-Now-Decrypt-Later (HNDL)
Adversaries may capture encrypted traffic today to decrypt when quantum computers become available (~2030+). **Mitigation**: Migrate all long-lived keys to PQC or hybrid schemes immediately.

---

## Risk Scoring Model

The system scores key risk (0–100) across four dimensions:

| Factor | Max Score | Notes |
|--------|-----------|-------|
| Quantum vulnerability | 40–60 | RSA/ECC = +40; weak classical = +60 |
| Rotation overdue | 0–30 | 2 pts/day overdue, capped at 30 |
| Key age | 0–20 | >180d = +10, >365d = +20 |
| Expiry proximity | 0–25 | <7d = +25, <30d = +10 |

**Risk Thresholds**: LOW (<20) | MEDIUM (20–39) | HIGH (40–59) | CRITICAL (≥60)

---

## Compliance Mapping

| Control | NIST SP 800-131A | FIPS 140-3 | ISO 27001:2022 |
|---------|-----------------|-----------|----------------|
| Algorithm approval | KYBER/DILITHIUM/AES-256 | FIPS 203/204/205 | A.10.1.1 |
| Key rotation | Defined rotation period | Mandatory | A.10.1.2 |
| Audit logging | Required | Required | A.12.4 |
| Key revocation | Immediate on compromise | Required | A.10.1.2 |
| Hybrid transition | Recommended NIST IR 8105 | Transitional | A.10.1.1 |

---

## Residual Risks

1. **Simulation layer**: PQC operations fall back to HMAC-SHA3 simulation on Windows without liboqs. Install `pyoqs` for production.
2. **No HSM integration**: Key material stored in cloud KMS simulations. Add real HSM backend for production.
3. **No authentication layer**: API endpoints are unauthenticated in this demo. Add OAuth2/JWT before deployment.
