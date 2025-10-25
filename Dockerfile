# Multi-stage build for security and efficiency
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libmagic1 \
    libmagic-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Security scanning stage
FROM python:3.11-slim as security-scan

# Install Trivy for vulnerability scanning
RUN apt-get update && apt-get install -y \
    wget \
    apt-transport-https \
    gnupg \
    lsb-release \
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - \
    && echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y trivy \
    && rm -rf /var/lib/apt/lists/*

# Copy application for scanning
COPY . /app
WORKDIR /app

# Run security scans
RUN echo "🔍 Running security scans..." && \
    trivy fs --exit-code 0 --severity HIGH,CRITICAL . && \
    echo "✅ Security scan completed"

# Production stage
FROM python:3.11-slim as production

# Security: Install only essential packages and clean up
RUN apt-get update && apt-get install -y \
    libmagic1 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && rm -rf /tmp/* /var/tmp/*

# Security: Create non-root user with minimal privileges
RUN groupadd -r appgroup && \
    useradd -r -g appgroup -d /app -s /bin/bash appuser && \
    mkdir -p /app /app/data /app/logs /app/uploads /app/backups /app/certs && \
    chown -R appuser:appgroup /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code with proper ownership
COPY --chown=appuser:appgroup . .

# Security: Set restrictive permissions
RUN chmod 755 /app && \
    chmod 700 /app/data /app/logs /app/uploads /app/backups && \
    chmod 755 /app/src && \
    chmod 644 /app/src/*.py && \
    chmod +x /app/start_secure_backend.py

# Security: Remove any potential sensitive files
RUN find /app -name "*.pyc" -delete && \
    find /app -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Security: Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

# Security: Expose only necessary port
EXPOSE 8000

# Environment variables for security
ENV PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Default command
CMD ["python", "start_secure_backend.py"]
