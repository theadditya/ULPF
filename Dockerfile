# Multi-stage production container for Universal Log Pre-processing Framework (ULPF)
# Designed for high security and air-gapped enterprise deployments.

FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final minimal runtime image
FROM python:3.12-slim AS runner

WORKDIR /app

# Non-root user for cybersecurity compliance
RUN groupadd -r ulpf && useradd -r -g ulpf -u 10001 ulpf

COPY --from=builder /root/.local /home/ulpf/.local
ENV PATH=/home/ulpf/.local/bin:$PATH
ENV PYTHONPATH=/app/src:/home/ulpf/.local/lib/python3.12/site-packages:$PYTHONPATH
ENV PYTHONUNBUFFERED=1

COPY --chown=ulpf:ulpf . /app

USER ulpf

# Expose Web UI / REST API (8000) and Syslog Ingestion (1514)
EXPOSE 8000 1514

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/telemetry')" || exit 1

ENTRYPOINT ["python3", "ulpf"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
