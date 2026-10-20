# The one image of the Wave 4 stack; APP_ROLE selects orders-api / catalog-api / cart-worker.
# Built and pushed by `python scripts/deploy_fullstack_apps.py build|deploy ecs`, never by terraform.
# Base image by digest (audit A-I-24), read 2026-10-01; Dependabot (docker) proposes new digests.
FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    OTEL_SDK_DISABLED=true

WORKDIR /app
# requirements.txt carries a hash for every package (compiled from requirements.in), so pip refuses
# anything else (audit A-I-9); wheels only, so no package's setup script runs at install (Sonar S8541, 2026-10-16 -
# every pinned package has a Linux wheel for this Python).
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes --only-binary :all: -r requirements.txt
COPY app.py .

# Numeric, so Kubernetes runAsNonRoot can verify it without an /etc/passwd lookup.
USER 10001
EXPOSE 8080
# Under OpenTelemetry's launcher: its settings come from the OTEL_* environment (k8s/fullstack); with none set it
# exports nothing and the app runs as before.
CMD ["opentelemetry-instrument", "python", "/app/app.py"]
