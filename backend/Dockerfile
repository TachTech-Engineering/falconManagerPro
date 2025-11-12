# ---- Base ----
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps (build tools only when needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl \
 && rm -rf /var/lib/apt/lists/*

# Install Python deps first for better layer caching
COPY requirements.txt .
RUN pip install -r requirements.txt

# App code
COPY . .

# Non-root for k8s best practice
RUN useradd -u 10001 -m appuser
USER 10001:10001

EXPOSE 5003

# Gunicorn tuned for API IO + k8s
# - worker tmpfiles disabled, forwards client IPs through proxy, tighter timeouts
CMD ["gunicorn", \
     "--workers=1", \
     "--threads=8", \
     "--worker-class=gthread", \
     "--bind=0.0.0.0:5003", \
     "--timeout=60", \
     "--graceful-timeout=30", \
     "--keep-alive=5", \
     "--access-logfile=-", \
     "--error-logfile=-", \
     "--forwarded-allow-ips=*", \
     "app:app"]
