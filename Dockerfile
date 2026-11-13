FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    LAKERA_RED_CA_STORE=/data/ca_store

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py targets.py tls_doctor.py ./
COPY static ./static

RUN useradd --system --uid 10001 runner \
    && mkdir -p /data/ca_store && chown -R runner /data
USER runner

EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/api/config')"

# 0.0.0.0 inside the container only; compose publishes it on the host's loopback.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8090"]
