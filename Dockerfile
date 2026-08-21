FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AEGIS_MOCK=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY fixtures ./fixtures

RUN pip install --no-cache-dir .

# Runs as a non-root user. An incident-response tool that runs as root is its own incident.
RUN useradd --create-home --uid 10001 aegis
USER aegis

ENTRYPOINT ["aegis"]
CMD ["demo"]
