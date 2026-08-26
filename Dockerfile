FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WARDEN_MOCK=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

# The container is a DEPLOYMENT artifact, so it carries the cluster client. The pip package stays
# vendor-free (the k8s client is an optional extra); the image is what runs as the in-cluster Job
# and must be able to read the cluster it is deployed into.
RUN pip install --no-cache-dir ".[k8s]"

# Runs as a non-root user. An incident-response tool that runs as root is its own incident.
RUN useradd --create-home --uid 10001 warden
USER warden

ENTRYPOINT ["warden"]
CMD ["demo"]
