# QRShield hardened container image (non-root user qrshield, pinned dependencies, offline-capable).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    HOME=/home/qrshield PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK=True

# OpenCV (libGL/glib), Tesseract OCR, and OpenMP system libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
      libgl1 libglib2.0-0 libgomp1 tesseract-ocr \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin qrshield

WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=qrshield:qrshield source/ .
USER qrshield

RUN mkdir -p artifacts && python -c "from qrshield_core.config import Settings; Settings.from_env().ensure_dirs()"
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"
CMD ["uvicorn", "app.asgi:app", "--host", "127.0.0.1", "--port", "8000"]
