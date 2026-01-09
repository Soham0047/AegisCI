#!/bin/bash
# SecureDev Guardian Installation Script
# ======================================
# This script installs the Guardian CLI and its dependencies.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║              SecureDev Guardian Installation                   ║"
echo "║         AI-Powered Security Scanner & Patcher                  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check Python version
check_python() {
    echo -e "${YELLOW}Checking Python version...${NC}"
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        PYTHON_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
        PYTHON_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
        
        if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 11 ]; then
            echo -e "${GREEN}✓ Python $PYTHON_VERSION found${NC}"
            return 0
        else
            echo -e "${RED}✗ Python 3.11+ required (found $PYTHON_VERSION)${NC}"
            echo "Please install Python 3.11 or higher:"
            echo "  - macOS: brew install python@3.11"
            echo "  - Ubuntu: sudo apt install python3.11"
            exit 1
        fi
    else
        echo -e "${RED}✗ Python 3 not found${NC}"
        exit 1
    fi
}

# Check for pipx (recommended) or pip
check_pipx() {
    if command -v pipx &> /dev/null; then
        echo -e "${GREEN}✓ pipx found (recommended for CLI tools)${NC}"
        return 0
    else
        echo -e "${YELLOW}! pipx not found, will use pip instead${NC}"
        return 1
    fi
}

# Install using pipx (isolated environment)
install_with_pipx() {
    echo -e "\n${YELLOW}Installing with pipx...${NC}"
    pipx install .
    echo -e "${GREEN}✓ Guardian installed with pipx${NC}"
}

# Install using pip
install_with_pip() {
    echo -e "\n${YELLOW}Installing with pip...${NC}"
    
    # Check if we're in a virtual environment
    if [ -n "$VIRTUAL_ENV" ]; then
        echo "Installing in virtual environment: $VIRTUAL_ENV"
        pip install .
    else
        echo -e "${YELLOW}Warning: Installing globally. Consider using a virtual environment.${NC}"
        pip install --user .
    fi
    
    echo -e "${GREEN}✓ Guardian installed with pip${NC}"
}

# Install scanner tools
install_scanners() {
    echo -e "\n${YELLOW}Installing security scanners...${NC}"
    
    # Bandit
    if ! command -v bandit &> /dev/null; then
        echo "Installing Bandit..."
        pip install bandit
    else
        echo -e "${GREEN}✓ Bandit already installed${NC}"
    fi
    
    # Semgrep
    if ! command -v semgrep &> /dev/null; then
        echo "Installing Semgrep..."
        pip install semgrep
    else
        echo -e "${GREEN}✓ Semgrep already installed${NC}"
    fi
}

# Verify installation
verify_installation() {
    echo -e "\n${YELLOW}Verifying installation...${NC}"
    
    if command -v guardian &> /dev/null; then
        GUARDIAN_VERSION=$(guardian version 2>/dev/null || echo "installed")
        echo -e "${GREEN}✓ Guardian CLI installed successfully${NC}"
    else
        echo -e "${YELLOW}! Guardian may need to be added to PATH${NC}"
        echo "  Try adding ~/.local/bin to your PATH:"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
}

# Main installation
main() {
    check_python
    
    if check_pipx; then
        install_with_pipx
    else
        install_with_pip
    fi
    
    install_scanners
    verify_installation
    
    echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════════╗"
    echo "║                 Installation Complete!                         ║"
    echo "╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Get started with:"
    echo "  guardian --help              # Show all commands"
    echo "  guardian check               # Verify tools are installed"
    echo "  guardian init                # Create configuration file"
    echo "  guardian scan --base-ref main    # Scan for vulnerabilities"
    echo ""
    echo "Documentation: https://github.com/yourusername/securedev-guardian"
}

# Handle command line arguments
case "${1:-install}" in
    install)
        main
        ;;
    uninstall)
        echo -e "${YELLOW}Uninstalling Guardian...${NC}"
        if command -v pipx &> /dev/null; then
            pipx uninstall securedev-guardian || pip uninstall securedev-guardian -y
        else
            pip uninstall securedev-guardian -y
        fi
        echo -e "${GREEN}✓ Guardian uninstalled${NC}"
        ;;
    *)
        echo "Usage: $0 [install|uninstall]"
        exit 1
        ;;
esac
