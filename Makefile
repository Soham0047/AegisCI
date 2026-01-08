.PHONY: venv install api web gateway scan lint-py format-py format-py-check typecheck test \
	test-js-scripts build-dataset lint-js format-js format-check-js lint format check

BASE ?= main

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
