#!/usr/bin/env bash
# Cross-compile c-toxcore-pq for Windows using Docker
# Usage: ./scripts/build-windows.sh [--no-pq] [--32bit] [--test]
#
# Options:
#   --no-pq    Build without ML-KEM post-quantum crypto (uses stable libsodium)
#   --32bit    Build 32-bit binaries instead of 64-bit
#   --test     Run test suite (requires Wine in container)
#   --help     Show this help message

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DOCKER_DIR="$PROJECT_ROOT/other/docker/windows"
OUTPUT_DIR="$PROJECT_ROOT/_win_build"

# Default options
ENABLE_PQ="true"
ARCH="x86_64"
ENABLE_TEST="false"
IMAGE_TAG="toxcore-pq-win"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-pq)
            ENABLE_PQ="false"
            IMAGE_TAG="toxcore-classical-win"
            shift
            ;;
        --32bit)
            ARCH="i686"
            shift
            ;;
        --test)
            ENABLE_TEST="true"
            shift
            ;;
        --help|-h)
            echo "Cross-compile c-toxcore-pq for Windows using Docker"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-pq    Build without ML-KEM post-quantum crypto"
            echo "  --32bit    Build 32-bit binaries instead of 64-bit"
            echo "  --test     Run test suite (requires Wine)"
            echo "  --help     Show this help message"
            echo ""
            echo "Output: $_win_build/<arch>/"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       c-toxcore-pq Windows Cross-Compile                 ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Configuration:"
echo "  Post-quantum (ML-KEM): $ENABLE_PQ"
echo "  Architecture: $ARCH"
echo "  Run tests: $ENABLE_TEST"
echo "  Output: $OUTPUT_DIR/$ARCH/"
echo ""

# Check Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed or not in PATH${NC}"
    echo "Install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build Docker image
echo -e "${BLUE}Building Docker image...${NC}"
cd "$DOCKER_DIR"

BUILD_ARGS="--build-arg ENABLE_PQ=$ENABLE_PQ"

if [ "$ARCH" = "i686" ]; then
    BUILD_ARGS="$BUILD_ARGS --build-arg SUPPORT_ARCH_i686=true --build-arg SUPPORT_ARCH_x86_64=false"
else
    BUILD_ARGS="$BUILD_ARGS --build-arg SUPPORT_ARCH_i686=false --build-arg SUPPORT_ARCH_x86_64=true"
fi

if [ "$ENABLE_TEST" = "true" ]; then
    BUILD_ARGS="$BUILD_ARGS --build-arg SUPPORT_TEST=true"
fi

docker build $BUILD_ARGS -t "$IMAGE_TAG" .

# Run container to build toxcore
echo ""
echo -e "${BLUE}Cross-compiling toxcore...${NC}"

RUN_ARGS="-e ENABLE_ARCH_i686=$([ "$ARCH" = "i686" ] && echo true || echo false)"
RUN_ARGS="$RUN_ARGS -e ENABLE_ARCH_x86_64=$([ "$ARCH" = "x86_64" ] && echo true || echo false)"

if [ "$ENABLE_TEST" = "true" ]; then
    RUN_ARGS="$RUN_ARGS -e ENABLE_TEST=true -e ALLOW_TEST_FAILURE=true"
fi

docker run \
    $RUN_ARGS \
    -v "$PROJECT_ROOT:/toxcore" \
    -v "$OUTPUT_DIR:/prefix" \
    -t \
    --rm \
    "$IMAGE_TAG"

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ Build complete!${NC}"
echo ""
echo "Output files:"
ls -la "$OUTPUT_DIR/$ARCH/bin/" 2>/dev/null | head -10 || echo "  (check $OUTPUT_DIR/$ARCH/)"
echo ""
echo "Libraries: $OUTPUT_DIR/$ARCH/lib/"
echo "Headers:   $OUTPUT_DIR/$ARCH/include/"
echo "Binaries:  $OUTPUT_DIR/$ARCH/bin/"
