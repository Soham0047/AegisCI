#!/bin/bash
#
# SecureDev Guardian - GitHub Setup Script
# Prepares the repository for GitHub hosting
#
# Usage: ./scripts/setup_for_github.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "=============================================="
echo "🚀 SecureDev Guardian - GitHub Setup"
echo "=============================================="
echo ""

# Check if git is initialized
if [[ ! -d ".git" ]]; then
    echo "⚠️  Git not initialized. Initializing..."
    git init
    git add -A
    git commit -m "Initial commit"
fi

# Check current size
SIZE=$(du -sh . 2>/dev/null | cut -f1)
echo "📦 Current project size: $SIZE"
echo ""

# ============================================
# 1. Check if Git LFS is needed
# ============================================
echo "📋 Checking model file sizes..."

LARGE_FILES=$(find artifacts/dl -name "*.pt" -size +50M 2>/dev/null || true)
if [[ -n "$LARGE_FILES" ]]; then
    echo ""
    echo "⚠️  Large model files detected (>50MB):"
    echo "$LARGE_FILES" | while read f; do
        size=$(du -h "$f" 2>/dev/null | cut -f1)
        echo "   - $f ($size)"
    done
    echo ""
    
    # Check if Git LFS is installed
    if command -v git-lfs &> /dev/null; then
        echo "✅ Git LFS is installed"
        
        read -p "Would you like to set up Git LFS for large models? (y/n) " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            git lfs install
            git lfs track "artifacts/dl/*.pt"
            git add .gitattributes
            echo "✅ Git LFS configured for *.pt files"
        fi
    else
        echo "⚠️  Git LFS is NOT installed."
        echo "   For large files, consider:"
        echo "   1. Install Git LFS: brew install git-lfs (macOS)"
        echo "   2. Or exclude models from git and host separately"
    fi
else
    echo "✅ No large model files detected"
fi

echo ""

# ============================================
# 2. Verify .gitignore
# ============================================
echo "📋 Checking .gitignore..."

if [[ -f ".gitignore" ]]; then
    echo "✅ .gitignore exists"
else
    echo "⚠️  No .gitignore found!"
fi

# ============================================
# 3. Check for sensitive files
# ============================================
echo ""
echo "📋 Checking for sensitive files..."

SENSITIVE_PATTERNS=(".env" "*.pem" "*.key" "*_rsa" "*credentials*")
FOUND_SENSITIVE=false

for pattern in "${SENSITIVE_PATTERNS[@]}"; do
    files=$(find . -name "$pattern" -not -path "./.git/*" -not -path "./.venv/*" 2>/dev/null || true)
    if [[ -n "$files" ]]; then
        echo "⚠️  Found sensitive file pattern '$pattern':"
        echo "$files" | head -3
        FOUND_SENSITIVE=true
    fi
done

if [[ "$FOUND_SENSITIVE" == "false" ]]; then
    echo "✅ No sensitive files detected"
fi

# ============================================
# 4. Summary
# ============================================
echo ""
echo "=============================================="
echo "✅ Setup Check Complete!"
echo "=============================================="
echo ""
echo "📝 Next steps to host on GitHub:"
echo ""
echo "   1. Create a GitHub repository:"
echo "      gh repo create securedev-guardian --public"
echo ""
echo "   2. Add all files and commit:"
echo "      git add -A"
echo "      git commit -m 'chore: production release'"
echo ""
echo "   3. Push to GitHub:"
echo "      git branch -M main"
echo "      git remote add origin https://github.com/YOUR_USERNAME/securedev-guardian.git"
echo "      git push -u origin main"
echo ""
echo "   4. Create a release:"
echo "      git tag -a v1.0.0 -m 'Release v1.0.0'"
echo "      git push origin v1.0.0"
echo ""
echo "=============================================="
