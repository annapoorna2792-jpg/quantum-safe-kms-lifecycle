# ── Stage 1: liboqs builder ───────────────────────────────────────────────────
# Builds liboqs 0.10.1 from source with ML-KEM-768 and ML-DSA-65 support.
# Matches report §6 environment setup.
FROM python:3.12-slim AS liboqs-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build libssl-dev pkg-config git curl \
    && rm -rf /var/lib/apt/lists/*

ARG LIBOQS_VERSION=0.10.1
RUN git clone --depth 1 --branch ${LIBOQS_VERSION} \
    https://github.com/open-quantum-safe/liboqs.git /opt/liboqs

RUN cmake -S /opt/liboqs -B /opt/liboqs/build \
        -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_USE_OPENSSL=ON \
    && cmake --build /opt/liboqs/build \
    && cmake --install /opt/liboqs/build --prefix /usr/local


# ── Stage 2: Python app ───────────────────────────────────────────────────────
FROM python:3.12-slim

# Copy liboqs shared library from builder
COPY --from=liboqs-builder /usr/local /usr/local
RUN ldconfig

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi-dev libssl-dev curl \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies (including pyoqs — liboqs Python binding)
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir pyoqs==0.10.1

# Copy application source
COPY backend/app ./app

# Persistent data volume for SQLite
RUN mkdir -p /app/data
VOLUME ["/app/data"]

# Environment defaults (overridden by docker-compose.yml)
ENV DATABASE_URL=sqlite:////app/data/quantum_kms.db
ENV DEFAULT_KMS_PROVIDER=aws_kms
ENV PROVIDER_MODE=auto
ENV KEY_ROTATION_DAYS=365
ENV ROTATION_INTERVAL_SECONDS=120
ENV SEED_DEMO_KEY=true
ENV DEFAULT_KEY_ALIAS=customer-data
ENV AWS_REGION=eu-north-1

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8001/healthz || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
