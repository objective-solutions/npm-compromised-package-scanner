#!/bin/sh
set -e

# Colors for output
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

PROJECT_DIR="."
FORCE_LOCK_GENERATION=false
SCANNER_DIR="/app"

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --force-lock-file-generation)
            FORCE_LOCK_GENERATION=true
            ;;
        *)
            PROJECT_DIR="$arg"
            ;;
    esac
done

echo "${BLUE}=== npm-scanner Entrypoint ===${NC}"
echo ""

# Change to project directory
cd "$PROJECT_DIR" || exit 1

# Check if we're in a Node.js project
if [ ! -f "package.json" ]; then
    echo "${RED}Error: package.json not found in $PROJECT_DIR${NC}"
    echo "This doesn't appear to be a Node.js project."
    exit 1
fi

echo "${GREEN}✓ Found package.json${NC}"
echo ""

# Detect which lock file exists
HAS_PACKAGE_LOCK=false
HAS_YARN_LOCK=false
HAS_PNPM_LOCK=false

if [ -f "package-lock.json" ]; then
    HAS_PACKAGE_LOCK=true
    echo "${GREEN}✓ Found package-lock.json (npm)${NC}"
fi

if [ -f "yarn.lock" ]; then
    HAS_YARN_LOCK=true
    echo "${GREEN}✓ Found yarn.lock (yarn)${NC}"
fi

if [ -f "pnpm-lock.yaml" ] || [ -f "pnpm-lock.yml" ]; then
    HAS_PNPM_LOCK=true
    echo "${GREEN}✓ Found pnpm-lock.yaml (pnpm)${NC}"
fi

echo ""

# If lockfiles exist, just run the scanner
if [ "$HAS_PACKAGE_LOCK" = true ] || [ "$HAS_YARN_LOCK" = true ] || [ "$HAS_PNPM_LOCK" = true ]; then
    echo "${GREEN}Lock files detected. Running scanner...${NC}"
    echo ""
    python3 "$SCANNER_DIR/scan_compromised_packages.py"
    exit $?
fi

# No lockfiles found
echo "${RED}✗ No lock files found (package-lock.json, yarn.lock, pnpm-lock.yaml)${NC}"
echo ""
echo "${YELLOW}⚠️  SECURITY WARNING ⚠️${NC}"
echo ""
echo "Lock files are required to scan for compromised packages."
echo "However, generating them requires running package manager commands,"
echo "which could execute malicious code if the project is compromised."
echo ""
echo "${RED}DO NOT run any package manager (npm, yarn, pnpm) in an environment${NC}"
echo "${RED}that could be compromised or on your local machine.${NC}"
echo ""
echo "${YELLOW}If you understand the risks and want to generate lock files${NC}"
echo "${YELLOW}inside this isolated container, use:${NC}"
echo ""
echo "  ${BLUE}docker run --rm -v \$(pwd):/project npm-scanner --force-lock-file-generation${NC}"
echo ""
echo "${YELLOW}This will:${NC}"
echo "  1. Detect the package manager (npm, yarn, pnpm)"
echo "  2. Run 'install' commands ONLY inside this container"
echo "  3. Scan the generated lock files"
echo ""
echo "${YELLOW}Note: Generation may fail if the project has:${NC}"
echo "  - Native dependencies (node-gyp, bcrypt, etc.)"
echo "  - Private npm registries"
echo "  - Git dependencies"
echo "  - Workspace monorepos"
echo "  - Custom build scripts"
echo ""

# Check if user explicitly requested lock file generation
if [ "$FORCE_LOCK_GENERATION" = false ]; then
    exit 1
fi

# User explicitly requested lock file generation
echo "${YELLOW}Proceeding with lock file generation (--force-lock-file-generation flag detected)${NC}"
echo ""

# Check for package-lock.json in package.json engines or packageManager field
PACKAGE_MANAGER=""

# Check packageManager field (npm 7+, yarn 2+, pnpm)
if grep -q '"packageManager"' package.json 2>/dev/null; then
    PACKAGE_MANAGER=$(grep '"packageManager"' package.json | head -1 | sed 's/.*"packageManager"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
fi

# Fallback detection based on what's available
if [ -z "$PACKAGE_MANAGER" ]; then
    # Try pnpm first (if pnpm-lock.yaml exists or pnpm is configured)
    if command -v pnpm >/dev/null 2>&1; then
        PACKAGE_MANAGER="pnpm"
    # Try yarn
    elif command -v yarn >/dev/null 2>&1; then
        PACKAGE_MANAGER="yarn"
    # Default to npm
    else
        PACKAGE_MANAGER="npm"
    fi
fi

echo "${BLUE}Detected package manager: $PACKAGE_MANAGER${NC}"
echo ""

# Generate lockfile based on detected package manager
case "$PACKAGE_MANAGER" in
    pnpm*)
        echo "${YELLOW}Running: pnpm install${NC}"
        if ! command -v pnpm >/dev/null 2>&1; then
            echo "${YELLOW}Installing pnpm...${NC}"
            npm install -g pnpm
        fi
        pnpm install --frozen-lockfile 2>/dev/null || pnpm install
        ;;
    yarn*)
        echo "${YELLOW}Running: yarn install${NC}"
        yarn install --frozen-lockfile 2>/dev/null || yarn install
        ;;
    npm*)
        echo "${YELLOW}Running: npm install${NC}"
        npm install --prefer-offline --no-audit
        ;;
    *)
        echo "${RED}Unknown package manager: $PACKAGE_MANAGER${NC}"
        exit 1
        ;;
esac

INSTALL_EXIT_CODE=$?

echo ""

if [ $INSTALL_EXIT_CODE -eq 0 ]; then
    echo "${GREEN}✓ Lock file generated successfully${NC}"
    echo ""
    echo "${BLUE}Running scanner...${NC}"
    echo ""
    python3 "$SCANNER_DIR/scan_compromised_packages.py"
    exit $?
else
    echo "${RED}✗ Failed to generate lock file${NC}"
    echo ""
    echo "${YELLOW}This could be due to:${NC}"
    echo "  - Network issues"
    echo "  - Missing native build tools"
    echo "  - Private registry authentication"
    echo "  - Incompatible dependencies"
    echo ""
    echo "${YELLOW}To troubleshoot:${NC}"
    echo "  1. Check the error messages above"
    echo "  2. Try running the package manager manually inside the container"
    echo "  3. Ensure the project's dependencies are compatible"
    echo ""
    exit $INSTALL_EXIT_CODE
fi
