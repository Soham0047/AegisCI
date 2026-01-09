# SecureDev Guardian Makefile
# ============================
# Quick commands for development and CLI usage

.PHONY: venv install install-dev api web gateway scan scan-ci lint-py format-py format-py-check typecheck test \
	test-fast test-js-scripts build-dataset lint-js format-js format-check-js lint format check \
	build publish clean help

BASE ?= main

# Default target - show help
help:
	@echo "SecureDev Guardian - Available Commands"
	@echo "========================================"
	@echo ""
	@echo "Setup:"
	@echo "  make venv             Create virtual environment"
	@echo "  make install          Install dependencies"
	@echo "  make install-dev      Install with dev dependencies"
	@echo ""
	@echo "Development:"
	@echo "  make api              Start FastAPI backend"
	@echo "  make web              Start Next.js frontend"
	@echo "  make gateway          Start Express gateway"
	@echo ""
	@echo "Testing:"
	@echo "  make test             Run all tests"
	@echo "  make test-fast        Run tests without slow tests"
	@echo "  make check            Full check (lint + typecheck + test)"
	@echo ""
	@echo "CLI:"
	@echo "  make scan             Run security scan"
	@echo "  make scan-ci          Run scan with CI settings"
	@echo "  make guardian-check   Verify CLI installation"
	@echo ""
	@echo "Build:"
	@echo "  make build            Build distribution packages"
	@echo "  make publish          Publish to PyPI"
	@echo "  make clean            Clean build artifacts"

venv:
	@echo "Creating virtual environment in .venv..."
	python -m venv .venv
	@echo "Upgrading pip..."
	.venv/bin/python -m pip install -U pip
	@echo "Installing Python dev dependencies..."
	.venv/bin/python -m pip install -e ".[dev]"

install:
	@echo "Installing Python dev dependencies..."
	python -m pip install -U pip
	python -m pip install -e ".[dev]"
	@echo "✓ Guardian installed. Run 'guardian --help' to get started."

install-dev: install
	pre-commit install
	@echo "✓ Development environment ready."

api:
	@echo "Starting FastAPI backend (reload enabled)..."
	uvicorn backend.main:app --reload --port 8000

web:
	@echo "Starting Next.js dev server..."
	cd frontend && npm install && npm run dev

gateway:
	@echo "Starting gateway dev server..."
	cd gateway && npm install && npm run dev

scan:
	@echo "Running guardian scan against base ref: $(BASE)"
	guardian scan --base-ref $(BASE)

scan-ci:
	@echo "Running guardian scan with CI settings..."
	guardian scan --base-ref $(BASE) --fail-on high --json

guardian-check:
	@echo "Verifying Guardian CLI installation..."
	guardian check

guardian-init:
	@echo "Initializing Guardian configuration..."
	guardian init

lint-py:
	@echo "Running ruff lint..."
	python -m ruff check .

format-py:
	@echo "Formatting Python with ruff..."
	python -m ruff format .

format-py-check:
	@echo "Checking Python formatting with ruff..."
	python -m ruff format --check .

typecheck:
	@echo "Running mypy..."
	python -m mypy guardian backend scripts

test:
	@echo "Running pytest..."
	pytest

test-js-scripts:
	@echo "Running JS script tests..."
	node --test scripts/comment_updater_dryrun.test.js

build-dataset:
	@echo "Building datasets from data/repos..."
	python scripts/build_dataset.py --repos-dir data/repos --out-dir datasets --languages python,ts --validate

lint-js:
	@echo "Running frontend lint..."
	npm --prefix frontend run lint
	@echo "Running gateway lint..."
	npm --prefix gateway run lint

format-js:
	@echo "Formatting frontend with prettier..."
	npm --prefix frontend run format
	@echo "Formatting gateway with prettier..."
	npm --prefix gateway run format

format-check-js:
	@echo "Checking frontend formatting with prettier..."
	npm --prefix frontend run format:check
	@echo "Checking gateway formatting with prettier..."
	npm --prefix gateway run format:check

lint:
	@echo "Running lint and format checks..."
	@$(MAKE) lint-py lint-js format-py-check format-check-js

format:
	@echo "Formatting Python and JS/TS..."
	@$(MAKE) format-py format-js

check:
	@echo "Running full check (lint, typecheck, tests)..."
	@$(MAKE) lint typecheck test

test-fast:
	@echo "Running fast tests (skipping slow)..."
	pytest -m "not slow"

# Build & Publish
build: clean
	@echo "Building distribution packages..."
	pip install build
	python -m build
	@echo "✓ Built packages in dist/"

publish: build
	@echo "Publishing to PyPI..."
	pip install twine
	twine upload dist/*

clean:
	@echo "Cleaning build artifacts..."
	rm -rf build/ dist/ *.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	rm -rf htmlcov/ .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "✓ Cleaned."

# Docker shortcuts
docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f
