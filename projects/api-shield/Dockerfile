# API Shield - Production Dockerfile
# Multi-stage build for minimal image size

# Build stage
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first for better caching
COPY pyproject.toml .
COPY src/ src/
COPY README.md .

# Install package
RUN pip install --no-cache-dir build && \
    python -m build && \
    pip install --no-cache-dir dist/*.whl

# Production stage
FROM python:3.11-slim as production

WORKDIR /app

# Create non-root user
RUN groupadd -r apishield && useradd -r -g apishield apishield

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/api-shield /usr/local/bin/api-shield

# Copy configuration
COPY --chown=apishield:apishield . .

# Switch to non-root user
USER apishield

# Expose ports
EXPOSE 8000 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Default command
CMD ["api-shield", "server", "--host", "0.0.0.0", "--port", "8000"]

# Labels
LABEL org.opencontainers.image.title="API Shield" \
      org.opencontainers.image.description="Real-time API security with ML-powered threat detection" \
      org.opencontainers.image.vendor="API Shield Project" \
      org.opencontainers.image.licenses="Apache-2.0"
