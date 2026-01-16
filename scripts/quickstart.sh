#!/bin/bash
#
# SecureDev Guardian - Quick Start Script
# ========================================
# One-command setup for new users
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/securedev-guardian/main/scripts/quickstart.sh | bash
#   OR
#   ./scripts/quickstart.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                    ║"
    echo "║   🛡️  SecureDev Guardian - AI-Powered Security Scanner            ║"
    echo "║                                                                    ║"
    echo "║   Quick Start Setup                                                ║"
    echo "║                                                                    ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_prerequisites() {
    echo -e "${YELLOW}📋 Checking prerequisites...${NC}"

    # Check Python
    if command -v python3 &> /dev/null; then
        PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
        PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')

        if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 11 ]; then
            echo -e "   ${GREEN}✓${NC} Python $PY_VERSION"
        else
            echo -e "   ${RED}✗${NC} Python 3.11+ required (found $PY_VERSION)"
            echo ""
            echo "   Install Python 3.11+:"
            echo "     macOS:  brew install python@3.11"
            echo "     Ubuntu: sudo apt install python3.11 python3.11-venv"
            exit 1
        fi
    else
        echo -e "   ${RED}✗${NC} Python 3 not found"
        exit 1
    fi

    # Check Git
    if command -v git &> /dev/null; then
        echo -e "   ${GREEN}✓${NC} Git $(git --version | cut -d' ' -f3)"
    else
        echo -e "   ${RED}✗${NC} Git not found"
        exit 1
    fi

    # Check Git LFS (optional but recommended)
    if command -v git-lfs &> /dev/null; then
        echo -e "   ${GREEN}✓${NC} Git LFS installed"
    else
        echo -e "   ${YELLOW}!${NC} Git LFS not installed (models may not download)"
        echo "     Install: brew install git-lfs (macOS) or apt install git-lfs (Ubuntu)"
    fi

    echo ""
}

setup_environment() {
    echo -e "${YELLOW}🔧 Setting up environment...${NC}"

    # Create virtual environment if not exists
    if [ ! -d ".venv" ]; then
        echo "   Creating virtual environment..."
        python3 -m venv .venv
    fi

    # Activate
    source .venv/bin/activate
    echo -e "   ${GREEN}✓${NC} Virtual environment activated"

    # Upgrade pip
    pip install --upgrade pip -q
    echo -e "   ${GREEN}✓${NC} pip upgraded"

    echo ""
}

install_package() {
    echo -e "${YELLOW}📦 Installing SecureDev Guardian...${NC}"

    # Install the package
    pip install -e . -q
    echo -e "   ${GREEN}✓${NC} Core package installed"

    # Install scanners
    pip install bandit semgrep -q
    echo -e "   ${GREEN}✓${NC} Security scanners installed (bandit, semgrep)"

    echo ""
}

install_ml_dependencies() {
    echo -e "${YELLOW}🧠 Installing ML dependencies...${NC}"

    # Install PyTorch and ML libraries
    pip install torch tree-sitter tree-sitter-languages -q 2>/dev/null || {
        echo -e "   ${YELLOW}!${NC} Some ML dependencies may require manual installation"
    }
    echo -e "   ${GREEN}✓${NC} ML libraries installed"

    echo ""
}

verify_models() {
    echo -e "${YELLOW}🔍 Verifying ML models...${NC}"

    MODEL_DIR="artifacts/dl"

    if [ -d "$MODEL_DIR" ]; then
        # Check for model files
        if [ -f "$MODEL_DIR/gnn_enhanced.pt" ] || [ -f "$MODEL_DIR/transformer_enhanced.pt" ]; then
            echo -e "   ${GREEN}✓${NC} ML models found in $MODEL_DIR"
            ls -lh $MODEL_DIR/*.pt 2>/dev/null | awk '{print "      " $9 " (" $5 ")"}'
        else
            echo -e "   ${YELLOW}!${NC} ML models not found - they may be Git LFS files"
            echo "      Run: git lfs pull"
        fi
    else
        echo -e "   ${YELLOW}!${NC} Models directory not found"
    fi

    echo ""
}

verify_installation() {
    echo -e "${YELLOW}✅ Verifying installation...${NC}"

    # Check guardian CLI
    if command -v guardian &> /dev/null; then
        VERSION=$(guardian version 2>/dev/null | head -1 || echo "installed")
        echo -e "   ${GREEN}✓${NC} Guardian CLI: $VERSION"
    else
        echo -e "   ${YELLOW}!${NC} Guardian not in PATH. Activate venv: source .venv/bin/activate"
    fi

    # Run check
    echo ""
    echo -e "${YELLOW}🔧 Running system check...${NC}"
    guardian check 2>/dev/null || echo "   Run 'guardian check' after activating venv"

    echo ""
}

print_success() {
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                    ║"
    echo "║   ✅ Installation Complete!                                        ║"
    echo "║                                                                    ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "${CYAN}📖 Quick Start Guide:${NC}"
    echo ""
    echo "   # Activate the environment (required for each new terminal)"
    echo "   source .venv/bin/activate"
    echo ""
    echo "   # Create a configuration file"
    echo "   guardian init"
    echo ""
    echo "   # Scan your code for vulnerabilities"
    echo "   guardian scan --base-ref main"
    echo ""
    echo "   # Run a comprehensive scan (all scanners)"
    echo "   guardian scan --comprehensive"
    echo ""
    echo "   # See all options"
    echo "   guardian --help"
    echo ""
    echo -e "${CYAN}📚 Documentation:${NC} https://github.com/YOUR_USERNAME/securedev-guardian"
    echo ""
}

# Main
main() {
    print_banner
    check_prerequisites
    setup_environment
    install_package
    install_ml_dependencies
    verify_models
    verify_installation
    print_success
}

# Run
main "$@"
