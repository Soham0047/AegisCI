# Contributing to SecureDev Guardian

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+ (for frontend/gateway)
- Docker & Docker Compose (optional, for containerized deployment)

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/Soham0047/AegisCI.git
   cd securedev-guardian
   ```

2. **Create virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Download ML models** (if not using Git LFS)
   ```bash
   # Models are stored in artifacts/dl/
   # If using Git LFS, they download automatically
   # Otherwise, download from releases
   ```

5. **Verify installation**
   ```bash
   guardian --help
   guardian check
   ```

## 📁 Project Structure

```
securedev-guardian/
├── guardian/           # CLI application
│   ├── cli.py         # Main CLI entry point
│   ├── scanners/      # Security scanners
│   └── config.py      # Configuration
├── ml/                # Machine learning pipeline
│   ├── inference.py   # Model inference
│   ├── models/        # Model architectures
│   └── train_*.py     # Training scripts
├── backend/           # FastAPI backend service
├── frontend/          # Next.js dashboard
├── gateway/           # API gateway
├── artifacts/dl/      # Production ML models
└── tests/             # Test suite
```

## 🧪 Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=guardian --cov=ml

# Run specific test file
pytest tests/test_cli.py -v
```

## 📝 Code Style

We use the following tools for code quality:

- **Black** for Python formatting
- **Ruff** for linting
- **MyPy** for type checking
- **Prettier** for JS/TS formatting

```bash
# Format code
black guardian/ ml/ backend/
ruff check --fix guardian/ ml/ backend/

# Type check
mypy guardian/ ml/
```

## 🔄 Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests: `pytest`
5. Commit with clear messages: `git commit -m "feat: add new scanner"`
6. Push to your fork: `git push origin feature/your-feature`
7. Open a Pull Request

### Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `style:` Code style changes (formatting)
- `refactor:` Code refactoring
- `test:` Adding tests
- `chore:` Maintenance tasks

## 🏗️ Architecture

### ML Pipeline

The ML pipeline uses a multi-model ensemble approach:

1. **Transformer Model** - Token-based classification
2. **GNN Model** - Graph-based code analysis (best performer)
3. **Ensemble** - Combines both with learned weights

Models are stored in `artifacts/dl/` and loaded lazily during inference.

### Scanners

Built-in security scanners:
- **Bandit** - Python security analysis
- **Semgrep** - Multi-language patterns
- **Secrets** - Hardcoded credentials
- **Patterns** - Dangerous code patterns
- **Dependencies** - Vulnerable packages

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.
