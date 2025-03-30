# Multi-stage build with platform-specific configuration
ARG PYTHON_VERSION=3.13-slim

# =========== BUILDER STAGE ===========
FROM --platform=${TARGETPLATFORM} python:${PYTHON_VERSION} AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /build

# Copy package definition files
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Install package and dependencies with pip wheel
RUN pip install --no-cache-dir wheel && \
    pip wheel --no-cache-dir --wheel-dir=/wheels -e .

# =========== FINAL STAGE ===========
FROM --platform=${TARGETPLATFORM} python:${PYTHON_VERSION}

# Set target architecture argument
ARG TARGETPLATFORM
ARG TARGETARCH

# Step 1: Install system packages - keeping all original packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    unzip \
    curl \
    wget \
    less \
    groff \
    jq \
    gnupg \
    tar \
    gzip \
    zip \
    vim \
    net-tools \
    dnsutils \
    openssh-client \
    grep \
    sed \
    gawk \
    findutils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Step 2: Install AWS CLI based on architecture
RUN if [ "${TARGETARCH}" = "arm64" ]; then \
        curl "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o "awscliv2.zip"; \
    else \
        curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"; \
    fi \
    && unzip -q awscliv2.zip \
    && ./aws/install \
    && rm -rf awscliv2.zip aws

# Step 3: Install Session Manager plugin based on architecture
RUN if [ "${TARGETARCH}" = "arm64" ]; then \
        curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_arm64/session-manager-plugin.deb" -o "session-manager-plugin.deb"; \
    else \
        curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb" -o "session-manager-plugin.deb"; \
    fi \
    && dpkg -i session-manager-plugin.deb 2>/dev/null || true \
    && rm session-manager-plugin.deb

# Set up application directory, user, and permissions
RUN mkdir -p /app/logs && chmod 777 /app/logs \
    && useradd -m -s /bin/bash -u 10001 appuser \
    && mkdir -p /home/appuser/.aws \
    && chmod 700 /home/appuser/.aws

WORKDIR /app

# Copy application code
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Copy wheels from builder and install
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels aws-mcp-server && \
    rm -rf /wheels

# Set ownership after all files have been copied
RUN chown -R appuser:appuser /app /home/appuser/.aws

# Switch to non-root user
USER appuser

# Set all environment variables in one layer
ENV HOME="/home/appuser" \
    PATH="/usr/local/bin:/usr/local/aws/v2/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    AWS_MCP_TRANSPORT=stdio

# Add metadata
LABEL maintainer="alexei-led" \
      description="AWS Multi-Command Proxy Server" \
      org.opencontainers.image.source="https://github.com/alexei-led/aws-mcp-server" \
      org.opencontainers.image.version="1.0.0"

# Expose the service port
EXPOSE 8000

# Set command to run the server
ENTRYPOINT ["python", "-m", "aws_mcp_server"]