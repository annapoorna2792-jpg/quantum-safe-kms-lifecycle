FROM python:3.12-slim-bookworm AS liboqs-build

ARG LIBOQS_VERSION=0.16.0
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake git libssl-dev ninja-build ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "${LIBOQS_VERSION}" https://github.com/open-quantum-safe/liboqs.git /src/liboqs
RUN cmake -S /src/liboqs -B /src/liboqs/build -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_DIST_BUILD=ON \
      -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
    && cmake --build /src/liboqs/build --parallel 2 \
    && cmake --install /src/liboqs/build

FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends curl libgomp1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=liboqs-build /opt/liboqs /usr/local
ENV LD_LIBRARY_PATH=/usr/local/lib \
    OQS_INSTALL_PATH=/usr/local \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYOQS_VERSION=0.16.0 \
    DATABASE_PATH=/app/data/quantum_safe_kms.db \
    ROTATION_INTERVAL_SECONDS=120

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN mkdir -p /app/data && useradd --create-home --uid 1000 appuser && chown -R appuser:appuser /app
USER appuser
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=4s --start-period=20s --retries=4 CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
