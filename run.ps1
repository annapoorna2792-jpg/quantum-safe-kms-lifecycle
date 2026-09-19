# run.ps1 — start the Quantum-Safe KMS server from the project root
# Usage: .\run.ps1
Set-Location backend
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
