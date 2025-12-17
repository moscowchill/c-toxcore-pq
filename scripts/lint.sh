#!/usr/bin/env bash
# Simple local lint script for c-toxcore-pq
# Usage: ./scripts/lint.sh [--all|--changed|--file <file>] [--fix] [--quick]
#
# Options:
#   --all       Check all source files (default)
#   --changed   Check only git-changed files
#   --file      Check a specific file
#   --fix       Apply automatic fixes where possible
#   --quick     Skip slower tools (infer, etc.)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_ROOT}/_build"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
MODE="all"
FIX=""
QUICK=""
TARGET_FILE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --all)
            MODE="all"
            shift
            ;;
        --changed)
            MODE="changed"
            shift
            ;;
        --file)
            MODE="file"
            TARGET_FILE="$2"
            shift 2
            ;;
        --fix)
            FIX="--fix"
            shift
            ;;
        --quick)
            QUICK="1"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--all|--changed|--file <file>] [--fix] [--quick]"
            echo ""
            echo "Options:"
            echo "  --all       Check all source files (default)"
            echo "  --changed   Check only git-changed files"
            echo "  --file      Check a specific file"
            echo "  --fix       Apply automatic fixes where possible"
            echo "  --quick     Skip slower tools"
            echo ""
            echo "Tools run:"
            echo "  1. clang-tidy   - Code quality and style checks"
            echo "  2. cppcheck     - Static analysis for bugs"
            echo "  3. Unit tests   - Run test suite"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Get list of files to check
get_files() {
    case $MODE in
        all)
            find "$PROJECT_ROOT/toxcore" "$PROJECT_ROOT/toxencryptsave" \
                -maxdepth 1 -name "*.[ch]" 2>/dev/null | sort
            ;;
        changed)
            git -C "$PROJECT_ROOT" diff --name-only --diff-filter=d HEAD | \
                grep -E '\.[ch]$' | \
                while read -r f; do echo "$PROJECT_ROOT/$f"; done
            ;;
        file)
            echo "$TARGET_FILE"
            ;;
    esac
}

FILES=$(get_files)

if [ -z "$FILES" ]; then
    echo -e "${YELLOW}No files to check${NC}"
    exit 0
fi

FILE_COUNT=$(echo "$FILES" | wc -l)
echo -e "${BLUE}Checking $FILE_COUNT file(s)...${NC}"
echo ""

ERRORS=0

# ============================================
# 1. clang-tidy
# ============================================
run_clang_tidy() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Running clang-tidy...${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    if ! command -v clang-tidy &> /dev/null; then
        echo -e "${YELLOW}⚠ clang-tidy not found, skipping${NC}"
        return 0
    fi

    # Ensure compile_commands.json exists
    if [ ! -f "$BUILD_DIR/compile_commands.json" ]; then
        echo "Generating compile_commands.json..."
        cmake -S "$PROJECT_ROOT" -B "$BUILD_DIR" \
            -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
            -DCMAKE_BUILD_TYPE=Debug > /dev/null 2>&1
    fi

    # Simplified checks for local development
    CHECKS="clang-analyzer-*,bugprone-*,performance-*,readability-identifier-naming"
    CHECKS="$CHECKS,-clang-analyzer-nullability.*"
    CHECKS="$CHECKS,-bugprone-easily-swappable-parameters"

    local ct_errors=0
    for f in $FILES; do
        if [ -f "$f" ]; then
            if ! clang-tidy -p "$BUILD_DIR" \
                --checks="$CHECKS" \
                $FIX \
                "$f" 2>/dev/null; then
                ct_errors=$((ct_errors + 1))
            fi
        fi
    done

    if [ $ct_errors -gt 0 ]; then
        echo -e "${RED}✗ clang-tidy found issues in $ct_errors file(s)${NC}"
        return 1
    else
        echo -e "${GREEN}✓ clang-tidy passed${NC}"
        return 0
    fi
}

# ============================================
# 2. cppcheck
# ============================================
run_cppcheck() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Running cppcheck...${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    if ! command -v cppcheck &> /dev/null; then
        echo -e "${YELLOW}⚠ cppcheck not found, skipping${NC}"
        echo "  Install with: sudo apt install cppcheck"
        return 0
    fi

    local cppcheck_errors=""
    cppcheck_errors=$(cppcheck \
        --enable=warning,style,performance,portability \
        --suppress=missingIncludeSystem \
        --suppress=unusedFunction \
        --suppress=unmatchedSuppression \
        --inline-suppr \
        --error-exitcode=1 \
        --quiet \
        -I "$PROJECT_ROOT/toxcore" \
        -I "$PROJECT_ROOT" \
        $FILES 2>&1) || true

    if [ -n "$cppcheck_errors" ]; then
        echo "$cppcheck_errors"
        echo -e "${RED}✗ cppcheck found issues${NC}"
        return 1
    else
        echo -e "${GREEN}✓ cppcheck passed${NC}"
        return 0
    fi
}

# ============================================
# 3. Run tests
# ============================================
run_tests() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Running tests...${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    if [ ! -d "$BUILD_DIR" ]; then
        echo "Build directory not found. Running cmake..."
        cmake -S "$PROJECT_ROOT" -B "$BUILD_DIR" -DAUTOTEST=ON
    fi

    # Build first
    echo "Building..."
    if ! make -C "$BUILD_DIR" -j"$(nproc)" 2>&1 | tail -5; then
        echo -e "${RED}✗ Build failed${NC}"
        return 1
    fi

    # Run PQ crypto tests
    echo ""
    echo "Running PQ crypto tests..."
    if "$BUILD_DIR/auto_tests/auto_crypto_pq_test"; then
        echo -e "${GREEN}✓ PQ crypto tests passed${NC}"
    else
        echo -e "${RED}✗ PQ crypto tests failed${NC}"
        return 1
    fi

    return 0
}

# ============================================
# Main execution
# ============================================
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           c-toxcore-pq Local Lint Script                 ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

run_clang_tidy || ERRORS=$((ERRORS + 1))
run_cppcheck || ERRORS=$((ERRORS + 1))

if [ -z "$QUICK" ]; then
    run_tests || ERRORS=$((ERRORS + 1))
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ $ERRORS check(s) failed${NC}"
    exit 1
fi
