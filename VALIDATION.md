# Validation record

Validated on 2026-08-19 before packaging.

- Python source compilation: passed
- Unit tests: 5 passed
- Native ML-KEM/ML-DSA tests: 2 skipped because native `liboqs` is not installed in the packaging workspace
- IAM policy JSON: valid
- Docker Compose YAML: valid
- Jinja templates: valid
- Python dependency consistency check: passed

The Dockerfile builds matching `liboqs 0.16.0` and `liboqs-python 0.16.0`. Run the documented `/healthz` check on EC2 after the Docker build; both `pqc.available` and `aws_kms.available` must be `true` before the capstone demonstration.
