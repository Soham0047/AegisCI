#!/usr/bin/env bash
# Setup all demos for SecureDev Guardian
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "============================================"
echo "SecureDev Guardian Demo - Full Setup"
echo "============================================"
echo ""

cd "$REPO_ROOT"

# Check prerequisites first
echo "Checking prerequisites..."
"$SCRIPT_DIR/check_prereqs.sh"
echo ""

# Setup Python venv if needed
if [ ! -d ".venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv .venv
fi

echo "Installing Python dependencies..."
source .venv/bin/activate
pip install -q -e . 2>/dev/null || pip install -q -r requirements.txt 2>/dev/null || true
pip install -q pytest 2>/dev/null || true

# Setup gateway if node is available
if command -v npm &> /dev/null; then
    echo "Setting up gateway..."
    cd "$REPO_ROOT/gateway"
    npm install --silent 2>/dev/null || npm install
    npm run build --silent 2>/dev/null || true
    cd "$REPO_ROOT"
fi

# Initialize Python demo repo
echo "Initializing Python demo repo..."
PYTHON_DEMO="$REPO_ROOT/demo_pack/python_demo/demo_repo"
if [ -d "$PYTHON_DEMO/.git" ]; then
    echo "  Python demo repo already initialized"
else
    cd "$PYTHON_DEMO"
    git init -q
    git config user.email "demo@example.com"
    git config user.name "Demo User"
    git add -A
    git commit -q -m "Initial vulnerable code"
    cd "$REPO_ROOT"
fi

# Initialize TS demo repo if npm available
if command -v npm &> /dev/null; then
    echo "Initializing TypeScript demo repo..."
    TS_DEMO="$REPO_ROOT/demo_pack/ts_demo/demo_repo"
    if [ -d "$TS_DEMO/.git" ]; then
        echo "  TS demo repo already initialized"
    else
        cd "$TS_DEMO"
        npm install --silent 2>/dev/null || npm install
        git init -q
        git config user.email "demo@example.com"
        git config user.name "Demo User"
        git add -A
        git commit -q -m "Initial vulnerable code"
        cd "$REPO_ROOT"
    fi
else
    echo "Skipping TS demo setup (npm not available)"
fi

# Create outputs directories
mkdir -p "$REPO_ROOT/demo_pack/python_demo/outputs"
mkdir -p "$REPO_ROOT/demo_pack/ts_demo/outputs"
mkdir -p "$REPO_ROOT/demo_pack/agent_gateway_demo/outputs"
mkdir -p "$REPO_ROOT/demo_pack/python_demo/screenshots"
mkdir -p "$REPO_ROOT/demo_pack/ts_demo/screenshots"
mkdir -p "$REPO_ROOT/demo_pack/agent_gateway_demo/screenshots"

echo ""
echo "============================================"
echo "Setup complete!"
echo ""
echo "Run the demos:"
echo "  ./demo_pack/python_demo/run_demo.sh"
echo "  ./demo_pack/ts_demo/run_demo.sh"
echo "  ./demo_pack/agent_gateway_demo/run_demo.sh"
echo "============================================"
