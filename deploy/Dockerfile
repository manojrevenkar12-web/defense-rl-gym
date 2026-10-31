# The environment server: patching and incident-response episodes over HTTP for a training cluster.
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DRG_HOME=/app
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY config ./config
COPY heldout/WRITING_FAMILY.md ./heldout/WRITING_FAMILY.md
RUN pip install --no-cache-dir ".[server]" && useradd --uid 10001 --no-create-home drg
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')"
CMD ["uvicorn", "drg.server.app:app", "--host", "0.0.0.0", "--port", "8080"]
