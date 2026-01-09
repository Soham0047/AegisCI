#!/usr/bin/env bash
# Check prerequisites for running SecureDev Guardian demos
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "============================================"
echo "SecureDev Guardian Demo - Prerequisites Check"
echo "============================================"
echo ""

MISSING=0

# Python check
echo -n "Python 3.11+: "
if command -v python3 &> /dev/null; then
    PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 11 ]; then
        echo -e "${GREEN}✓ Found Python $PY_VERSION${NC}"
    else
        echo -e "${YELLOW}⚠ Found Python $PY_VERSION (3.11+ recommended)${NC}"
    fi
else
    echo -e "${RED}✗ Not found${NC}"
    MISSING=1
fi

# Git check
echo -n "Git: "
if command -v git &> /dev/null; then
    GIT_VERSION=$(git --version | cut -d' ' -f3)
    echo -e "${GREEN}✓ Found Git $GIT_VERSION${NC}"
else
    echo -e "${RED}✗ Not found${NC}"
    MISSING=1
fi

# Node.js check
echo -n "Node.js 18+: "
if command -v node &> /dev/null; then
    NODE_VERSION=$(node -v | sed 's/v//')
    NODE_MAJOR=$(echo "$NODE_VERSION" | cut -d. -f1)
    if [ "$NODE_MAJOR" -ge 18 ]; then
        echo -e "${GREEN}✓ Found Node.js $NODE_VERSION${NC}"
    else
        echo -e "${YELLOW}⚠ Found Node.js $NODE_VERSION (18+ recommended for TS demo)${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Not found (optional, needed for TS demo and gateway)${NC}"
fi

# npm check
echo -n "npm: "
if command -v npm &> /dev/null; then
    NPM_VERSION=$(npm -v)
    echo -e "${GREEN}✓ Found npm $NPM_VERSION${NC}"
else
    echo -e "${YELLOW}⚠ Not found (optional, needed for TS demo and gateway)${NC}"
fi

# Docker check (optional)
echo -n "Docker: "
if command -v docker &> /dev/null; then
    if docker info &> /dev/null; then
        DOCKER_VERSION=$(docker --version | cut -d' ' -f3 | tr -d ',')
        echo -e "${GREEN}✓ Found Docker $DOCKER_VERSION (accessible)${NC}"
    else
        echo -e "${YELLOW}⚠ Found but not accessible (demos will use local validation)${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Not found (optional, demos will use local validation)${NC}"
fi

# Python venv check
echo -n "Python venv: "
if [ -d ".venv" ]; then
    echo -e "${GREEN}✓ Found .venv directory${NC}"
else
    echo -e "${YELLOW}⚠ Not found (will be created by setup_all.sh)${NC}"
fi

echo ""
echo "============================================"
if [ $MISSING -eq 1 ]; then
    echo -e "${RED}Some required prerequisites are missing.${NC}"
    echo "Please install them and run this script again."
    exit 1
else
    echo -e "${GREEN}All required prerequisites are met!${NC}"
    echo "Run ./demo_pack/scripts/setup_all.sh to set up the demos."
fi
