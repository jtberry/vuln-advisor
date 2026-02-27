# ── Stage 1: builder ─────────────────────────────────────────────────────────
# Install dependencies into an isolated venv. Only this stage needs pip and
# build tools -- they are NOT copied to the runtime image, reducing image size
# and attack surface (principle of least privilege / minimal footprint).
FROM python:3.12-slim AS builder

WORKDIR /build

# Copy only the requirements files first so Docker can cache this layer.
# If requirements don't change, pip install is skipped on subsequent builds.
COPY requirements.txt requirements-api.txt ./

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir -r requirements.txt -r requirements-api.txt


# ── Stage 2: runtime ─────────────────────────────────────────────────────────
# Lean runtime image: copy the pre-built venv and application source only.
# No pip, no compilers, no build tools in production.
FROM python:3.12-slim AS runtime

WORKDIR /app

# Copy the pre-built venv from the builder stage.
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Disable stdout/stderr buffering so print() and logging output appears
# immediately in container logs (important for debugging and log drivers).
ENV PYTHONUNBUFFERED=1

# Copy application source after deps so code changes don't bust the venv layer.
COPY . .

# Security: run as a non-root user. If this process is ever compromised, the
# attacker has no root privileges inside the container.
RUN useradd --no-create-home --shell /bin/false vulnadvisor \
    && chown -R vulnadvisor:vulnadvisor /app

USER vulnadvisor

EXPOSE 8000

# --proxy-headers: tells uvicorn to trust X-Forwarded-For and X-Forwarded-Proto
# headers from Caddy. Without this, the app sees Caddy's internal IP as the
# client address and all requests appear to come over HTTP (not HTTPS).
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')"]

CMD ["uvicorn", "asgi:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
