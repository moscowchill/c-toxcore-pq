#!/usr/bin/env bash
# Cross-compile c-toxcore-pq for Windows using MinGW-w64 (no Docker)
# Usage: ./scripts/build-windows-native.sh [--clean] [--deps-only] [--skip-deps]
#
# Requirements: mingw-w64, autoconf, automake, libtool, cmake, git
# Install: sudo apt install mingw-w64 autoconf automake libtool cmake git

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Build configuration
ARCH="x86_64"
TOOLCHAIN="${ARCH}-w64-mingw32"
PREFIX="$PROJECT_ROOT/_win_native/${ARCH}"
DEPS_DIR="$PROJECT_ROOT/_win_deps"
BUILD_DIR="$PROJECT_ROOT/_win_build_native"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Options
CLEAN=false
DEPS_ONLY=false
SKIP_DEPS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN=true
            shift
            ;;
        --deps-only)
            DEPS_ONLY=true
            shift
            ;;
        --skip-deps)
            SKIP_DEPS=true
            shift
            ;;
        --help|-h)
            echo "Cross-compile c-toxcore-pq for Windows using MinGW-w64"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --clean      Clean build directories before building"
            echo "  --deps-only  Only build dependencies, not toxcore"
            echo "  --skip-deps  Skip dependency build (use existing)"
            echo "  --help       Show this help"
            echo ""
            echo "Requirements:"
            echo "  sudo apt install mingw-w64 autoconf automake libtool cmake git"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║    c-toxcore-pq Windows Cross-Compile (No Docker)        ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check requirements
check_requirements() {
    local missing=()

    command -v ${TOOLCHAIN}-gcc >/dev/null || missing+=("mingw-w64")
    command -v autoconf >/dev/null || missing+=("autoconf")
    command -v automake >/dev/null || missing+=("automake")
    command -v libtoolize >/dev/null || missing+=("libtool")
    command -v cmake >/dev/null || missing+=("cmake")
    command -v git >/dev/null || missing+=("git")

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Missing required tools: ${missing[*]}${NC}"
        echo "Install with: sudo apt install ${missing[*]}"
        exit 1
    fi
    echo -e "${GREEN}✓ All build requirements met${NC}"
}

check_requirements

if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}Cleaning build directories...${NC}"
    rm -rf "$PREFIX" "$DEPS_DIR" "$BUILD_DIR"
fi

mkdir -p "$PREFIX"/{bin,lib,include} "$DEPS_DIR" "$BUILD_DIR"

export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"
export CFLAGS="-O2 -fPIC"
export LDFLAGS="-L$PREFIX/lib"
export CPPFLAGS="-I$PREFIX/include"

# ============================================
# Build libsodium with ML-KEM support
# ============================================
build_libsodium() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Building libsodium (git master with ML-KEM-768)...${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    cd "$DEPS_DIR"

    if [ ! -d "libsodium" ]; then
        git clone https://github.com/jedisct1/libsodium.git
    fi

    cd libsodium
    git fetch origin
    git checkout master
    git pull origin master

    # Clean previous build
    git clean -fdx || true

    # Generate configure (autoreconf is more reliable than autogen.sh)
    autoreconf -fi

    ./configure \
        --host="${TOOLCHAIN}" \
        --prefix="$PREFIX" \
        --disable-shared \
        --enable-static \
        --disable-pie

    make -j"$(nproc)"
    make install

    # Verify ML-KEM support
    if grep -q "crypto_kem_mlkem768" "$PREFIX/include/sodium.h" 2>/dev/null; then
        echo -e "${GREEN}✓ libsodium built with ML-KEM-768 support${NC}"
    else
        echo -e "${RED}✗ ML-KEM-768 not found in libsodium!${NC}"
        echo "The libsodium master branch may not include ML-KEM yet."
        exit 1
    fi
}

# ============================================
# Build toxcore
# ============================================
build_toxcore() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Building c-toxcore-pq...${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    cd "$BUILD_DIR"
    rm -rf *

    # Create toolchain file
    cat > mingw-toolchain.cmake << TOOLCHAIN
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_C_COMPILER ${TOOLCHAIN}-gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN}-g++)
set(CMAKE_RC_COMPILER ${TOOLCHAIN}-windres)
set(CMAKE_FIND_ROOT_PATH /usr/${TOOLCHAIN} ${PREFIX})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
TOOLCHAIN

    cmake \
        -DCMAKE_TOOLCHAIN_FILE=mingw-toolchain.cmake \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH="$PREFIX" \
        -DENABLE_SHARED=OFF \
        -DENABLE_STATIC=ON \
        -DBUILD_TOXAV=OFF \
        -DBOOTSTRAP_DAEMON=OFF \
        -DAUTOTEST=OFF \
        -DUNITTEST=OFF \
        "$PROJECT_ROOT"

    make -j"$(nproc)"
    make install

    echo -e "${GREEN}✓ toxcore built successfully${NC}"
}

# ============================================
# Main
# ============================================

if [ "$SKIP_DEPS" != true ]; then
    build_libsodium
fi

if [ "$DEPS_ONLY" = true ]; then
    echo ""
    echo -e "${GREEN}Dependencies built to: $PREFIX${NC}"
    exit 0
fi

build_toxcore

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ Build complete!${NC}"
echo ""
echo "Output directory: $PREFIX"
echo ""
echo "Contents:"
ls -la "$PREFIX/lib/"*.a 2>/dev/null | head -5 || true
ls -la "$PREFIX/bin/"*.exe 2>/dev/null | head -5 || true
echo ""
echo "To use in your project:"
echo "  Headers: $PREFIX/include/"
echo "  Library: $PREFIX/lib/libtoxcore.a"
echo ""
echo "Link with: -ltoxcore -lsodium -lws2_32 -liphlpapi"
