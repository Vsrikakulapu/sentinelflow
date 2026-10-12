FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY sentinelflow ./sentinelflow
RUN pip install --no-cache-dir . \
    && useradd --system --uid 10001 --no-create-home sentinel

USER sentinel
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=10 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"

CMD ["uvicorn", "sentinelflow.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
