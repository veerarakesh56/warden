FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WARDEN_MOCK=1

WORKDIR /app

COPY pyproject.toml README.md ./

# The container is a DEPLOYMENT artifact, so it carries the cluster client. The pip package stays
# vendor-free (the k8s client is an optional extra); the image is what runs as the in-cluster Job
# and must be able to read the cluster it is deployed into.
# The anthropic SDK too, so `WARDEN_MOCK=0 ANTHROPIC_API_KEY=... docker compose up` (docker-compose.yml)
# works as documented - it failed on a missing import until 2026-09-25.
# Dependencies first, in their own layer: it is reused until pyproject.toml changes, so a source
# change does not reinstall them (CI builds this image on every push). A stub package lets pip
# resolve the extras; it is removed, and the real package goes in below without touching them.
RUN mkdir -p src/warden && touch src/warden/__init__.py \
    && pip install --no-cache-dir ".[k8s,anthropic]" \
    && pip uninstall -y warden && rm -rf src build

COPY src ./src
RUN pip install --no-cache-dir --no-deps .

# Runs as a non-root user. An incident-response tool that runs as root is its own incident.
RUN useradd --create-home --uid 10001 warden
USER warden

ENTRYPOINT ["warden"]
CMD ["demo"]
