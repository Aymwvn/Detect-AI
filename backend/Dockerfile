# DetectAI backend — FastAPI + Uvicorn, non-root runtime user.
#
# NOTE: this Dockerfile has been written carefully but NOT executed/built
# in the environment that produced it (no Docker daemon available there).
# Build and test it yourself before relying on it:
#   docker build -t detectai-backend .
#   docker run --rm -p 8000:8000 --env-file .env detectai-backend

FROM python:3.12-slim AS base

# --- system deps (build-time only where possible) ---------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# --- python deps --------------------------------------------------------
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- app code -----------------------------------------------------------
COPY . .

# --- non-root user (architecture doc section 14: non-root containers) -------
RUN groupadd --gid 1000 detectai && \
    useradd --uid 1000 --gid detectai --shell /bin/bash --create-home detectai && \
    chown -R detectai:detectai /app

USER detectai

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
