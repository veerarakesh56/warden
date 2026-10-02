# Base images by digest (audit A-I-24): a tag can be moved to other content; a digest cannot.
# Read 2026-10-01 from the registries; Dependabot (docker) proposes new digests.
FROM ghcr.io/astral-sh/uv:0.12.21@sha256:a7aed3216253ee804de3e2d8afa5073baa1a177335345d43845cd4165e43b711 AS uv
# Two stages: the source is copied and installed in `build`; the image is the installed package only - a COPY
# layer keeps every file it copied even if a later RUN deletes it (seventh review, 2026-10-01).
FROM python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b AS build

ENV UV_PROJECT_ENVIRONMENT=/opt/warden \
    UV_PYTHON_DOWNLOADS=never \
    UV_COMPILE_BYTECODE=1 \
    UV_NO_CACHE=1

WORKDIR /app

COPY --from=uv /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src

# The container is a DEPLOYMENT artifact, so it carries the cluster client. The pip package stays
# vendor-free (the k8s client is an optional extra); the image is what runs as the in-cluster Job
# and must be able to read the cluster it is deployed into.
# The anthropic SDK too, so `WARDEN_MOCK=0 ANTHROPIC_API_KEY=... docker compose up` (docker-compose.yml)
# works as documented - it failed on a missing import until 2026-09-25.
# Only what uv.lock lists, every hash verified (audit A-I-9), compiled to bytecode (the container runs with a
# read-only root filesystem, so nothing could compile later). The package is installed into /opt/warden.
RUN uv sync --locked --no-editable --extra k8s --extra anthropic
# Only the shipped kinds of file, compared without letter case (registers R8-O4, R9-O1): the build backend's exclude
# list matches with case, so a local `SECRET.ENV` or `Prod.TFVARS` under src/ would ship. The build fails instead.
COPY scripts/check_package.py ./
RUN /opt/warden/bin/python check_package.py "$(/opt/warden/bin/python -c 'import os, warden; print(os.path.dirname(warden.__file__))')"

FROM python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WARDEN_MOCK=1 \
    PATH=/opt/warden/bin:$PATH
# Neither uv nor the source: only the installed environment.
COPY --from=build /opt/warden /opt/warden

# Runs as a non-root user. An incident-response tool that runs as root is its own incident.
RUN useradd --create-home --uid 10001 warden
USER warden

ENTRYPOINT ["warden"]
CMD ["demo"]
