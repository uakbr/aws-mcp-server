#!/bin/bash
# Script to build multi-architecture Docker images for AWS MCP Server

set -e  # Exit on error

# Default repository name (change as needed)
REPO=${1:-"aws-mcp-server"}
TAG=${2:-"latest"}

# Check if Docker buildx is available
if ! docker buildx version &>/dev/null; then
    echo "Error: Docker buildx is not available"
    echo "Please ensure you're using Docker Desktop >= 2.3 or Docker Engine >= 19.03"
    exit 1
fi

# Check for builder
BUILDER_NAME="multiarch-builder"
if ! docker buildx inspect "$BUILDER_NAME" &>/dev/null; then
    echo "Creating new buildx builder: $BUILDER_NAME"
    docker buildx create --name "$BUILDER_NAME" --use
else
    echo "Using existing buildx builder: $BUILDER_NAME"
    docker buildx use "$BUILDER_NAME"
fi

# Build and push multi-architecture images
echo "Building multi-architecture image for $REPO:$TAG"
echo "Supported architectures: linux/amd64, linux/arm64"

# If pushing to a registry, make sure you're logged in
# docker login

# Build multi-arch image (with --push to push to registry or --load for local use)
docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --tag "$REPO:$TAG" \
    --file deploy/docker/Dockerfile \
    --build-arg TARGETARCH \
    .

echo ""
echo "Build complete!"
echo ""
echo "To push to a registry, run:"
echo "docker buildx build --platform linux/amd64,linux/arm64 -t yourrepo/$REPO:$TAG --file deploy/docker/Dockerfile --push ."
echo ""
echo "For local use, you can build specific platform images:"
echo "docker buildx build --platform linux/amd64 -t $REPO:$TAG-amd64 --file deploy/docker/Dockerfile --load ."
echo "docker buildx build --platform linux/arm64 -t $REPO:$TAG-arm64 --file deploy/docker/Dockerfile --load ."