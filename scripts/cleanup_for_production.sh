#!/bin/bash
#
# SecureDev Guardian - Production Cleanup Script
# This script removes unnecessary files and prepares the repo for GitHub hosting
#
# Usage: ./scripts/cleanup_for_production.sh [--dry-run]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

DRY_RUN=false
if [[ "$1" == "--dry-run" ]]; then
    DRY_RUN=true
    echo "🔍 DRY RUN MODE - No files will be deleted"
fi

cd "$PROJECT_ROOT"

echo "=============================================="
echo "🧹 SecureDev Guardian - Production Cleanup"
echo "=============================================="
echo ""

# Calculate initial size
INITIAL_SIZE=$(du -sh . 2>/dev/null | cut -f1)
echo "📦 Initial project size: $INITIAL_SIZE"
echo ""

# Function to remove with logging
remove_path() {
    local path="$1"
    local description="$2"
    
    if [[ -e "$path" ]]; then
        size=$(du -sh "$path" 2>/dev/null | cut -f1 || echo "0")
        if $DRY_RUN; then
            echo "  [DRY-RUN] Would remove: $path ($size) - $description"
        else
            echo "  🗑️  Removing: $path ($size) - $description"
            rm -rf "$path"
        fi
    fi
}

# ============================================
# 1. Remove duplicate/old model artifacts
# ============================================
echo "📁 Cleaning model artifacts..."

# Keep only artifacts/dl/ which has production models
remove_path "artifacts/models/vertex" "Old Vertex AI training runs"
remove_path "artifacts/models/datasets" "Training datasets (not needed for inference)"
remove_path "artifacts/models/transformer_enhanced.pt" "Duplicate transformer model"
remove_path "artifacts/models/gnn_enhanced.pt" "Duplicate GNN model"
remove_path "artifacts/models/ensemble_enhanced.pt" "Duplicate ensemble model"
remove_path "artifacts/models/metrics" "Training metrics (already in dl/)"
remove_path "artifacts/models/pipeline_results.json" "Duplicate results"
remove_path "artifacts/models/transformer_test_metrics.json" "Test metrics"

remove_path "artifacts/backup" "Old backup artifacts"
remove_path "artifacts/cloud_models" "Cloud training artifacts"

# ============================================
# 2. Remove test/demo scan outputs
# ============================================
echo "📁 Cleaning test scan outputs..."

remove_path "artifacts/cli_demo_scan" "CLI demo scan output"
remove_path "artifacts/cli_demo_scan_git" "CLI git demo output"
remove_path "artifacts/cli_pipeline_test" "Pipeline test output"
remove_path "artifacts/cli_repo_scan" "Repo scan test output"
remove_path "artifacts/cli_repo_scan2" "Repo scan test output"
remove_path "artifacts/cli_repo_scan_full" "Full scan test output"
remove_path "artifacts/cli_repo_scan_full2" "Full scan test output"
remove_path "artifacts/cli_repo_scan_max" "Max scan test output"
remove_path "artifacts/demo_repo_git" "Demo repo git output"

# ============================================
# 3. Remove temporary/job files
# ============================================
echo "📁 Cleaning temporary files..."

remove_path "artifacts/jobs" "Celery job artifacts"
remove_path "artifacts/patch_v1" "Old patch artifacts"
remove_path "artifacts/validation" "Validation artifacts"
remove_path "artifacts/rag_store.db" "RAG store database"
remove_path "artifacts/training.log" "Training log"
remove_path "artifacts/pr_report.json" "PR report (temporary)"
remove_path "artifacts/pr_report_test.json" "Test PR report"
remove_path "artifacts/graph_coverage_report.json" "Graph coverage report"

# ============================================
# 4. Remove test data repos (large clones)
# ============================================
echo "📁 Cleaning test data repos..."

# These are cloned repos used for testing, not needed for distribution
remove_path "data/repos/slm-agent" "Large test repo (1.6GB)"
remove_path "data/repos/next.js-canary" "Next.js clone (225MB)"
remove_path "data/repos/CarCare-Copilot-main" "Test repo (207MB)"
remove_path "data/repos/multilingual-translator" "Test repo (181MB)"
remove_path "data/repos/django-main" "Django clone (60MB)"
remove_path "data/repos/Moodify-main" "Test repo (59MB)"
remove_path "data/repos/CS160-Group6-MeltMonitor-main" "Test repo (50MB)"
remove_path "data/repos/fastapi-master" "FastAPI clone (33MB)"
remove_path "data/repos/AI-Text-Summarizer-App-main" "Test repo (27MB)"

# Keep smaller repos for demos if desired, or remove all:
# remove_path "data/repos" "All test repos"

# ============================================
# 5. Remove Python cache and build artifacts
# ============================================
echo "📁 Cleaning Python cache..."

find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
find . -type f -name "*.pyo" -delete 2>/dev/null || true

remove_path "securedev_guardian.egg-info" "Egg info"
remove_path ".coverage" "Coverage data"

# ============================================
# 6. Remove large datasets (can be regenerated)
# ============================================
echo "📁 Cleaning large datasets..."

# These can be regenerated with the data pipeline
remove_path "datasets/ts" "TypeScript dataset (75MB)"
remove_path "datasets/python" "Python dataset (regeneratable)"

# ============================================
# 7. Clean test artifacts
# ============================================
echo "📁 Cleaning test artifacts..."

remove_path "frontend/test-results" "Playwright test results"
remove_path "report_test.json" "Test report JSON"
remove_path "report_test.md" "Test report markdown"
remove_path "report.json" "Root report JSON"
remove_path "report.md" "Root report markdown"

# ============================================
# 8. Optional: Remove venv/node_modules (comment if needed)
# ============================================
# Uncomment these for maximum cleanup (users will need to reinstall)
# echo "📁 Cleaning virtual environments..."
# remove_path ".venv" "Python virtual environment"
# remove_path "frontend/node_modules" "Frontend node_modules"
# remove_path "gateway/node_modules" "Gateway node_modules"

echo ""
echo "=============================================="

if $DRY_RUN; then
    echo "🔍 DRY RUN COMPLETE - Run without --dry-run to delete files"
else
    # Calculate final size
    FINAL_SIZE=$(du -sh . 2>/dev/null | cut -f1)
    echo "✅ Cleanup Complete!"
    echo "📦 Final project size: $FINAL_SIZE (was $INITIAL_SIZE)"
fi

echo "=============================================="
echo ""
echo "📝 Next steps:"
echo "   1. Review changes with 'git status'"
echo "   2. Update .gitignore if needed"
echo "   3. Commit: git add -A && git commit -m 'chore: production cleanup'"
echo "   4. Push to GitHub"
echo ""
