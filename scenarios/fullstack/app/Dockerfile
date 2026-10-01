# The one image of the Wave 4 stack; APP_ROLE selects orders-api / catalog-api / cart-worker.
# Built and pushed by `python scripts/deploy_fullstack_apps.py build|deploy ecs`, never by terraform.
# Base image by digest (audit A-I-24), read 2026-10-01; Dependabot (docker) proposes new digests.
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
# requirements.txt carries a hash for every package (compiled from requirements.in), so pip refuses
# anything else (audit A-I-9).
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY app.py .

# Numeric, so Kubernetes runAsNonRoot can verify it without an /etc/passwd lookup.
USER 10001
EXPOSE 8080
CMD ["python", "/app/app.py"]
