# A+ System Audit Utility - Docker Image
# Author: Kevin Hormaza
# GitHub: https://github.com/OddSageID

FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    procps \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create output directories
RUN mkdir -p /app/audit_results /app/logs

# Create non-root user for security
RUN useradd -m -u 1000 audituser && \
    chown -R audituser:audituser /app

# Switch to non-root user
USER audituser

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    OUTPUT_DIR=/app/audit_results \
    LOG_LEVEL=INFO

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Volume for audit results
VOLUME ["/app/audit_results", "/app/logs"]

# Default command shows help
CMD ["python", "main.py", "--help"]

# Usage examples:
# Build: docker build -t aplus-audit-utility .
# Run quick audit: docker run --rm -v $(pwd)/results:/app/audit_results aplus-audit-utility python main.py --quick --no-admin
# Run with API key: docker run --rm -e ANTHROPIC_API_KEY=your_key -v $(pwd)/results:/app/audit_results aplus-audit-utility python main.py
# Interactive shell: docker run --rm -it aplus-audit-utility /bin/bash
