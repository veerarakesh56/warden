# The one image of the Wave 4 stack; APP_ROLE selects orders-api / catalog-api / cart-worker.
# Built and pushed by `python scripts/deploy_fullstack_apps.py build|deploy ecs`, never by terraform.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

# Numeric, so Kubernetes runAsNonRoot can verify it without an /etc/passwd lookup.
USER 10001
EXPOSE 8080
CMD ["python", "/app/app.py"]
