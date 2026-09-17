# Contributing to agent-guard

Thank you for your interest in contributing to **agent-guard**! We welcome community contributions, from bug fixes and documentation improvements to new features and policy evaluators.

This document provides guidelines and instructions for setting up your development environment, running tests, and submitting pull requests.

---

## Code of Conduct

We are committed to providing a welcoming, inclusive, and harassment-free experience for everyone. Please be respectful and constructive in all interactions.

---

## Getting Started

### Prerequisites
- **Python:** Version `>= 3.10`
- **Git:** Installed and configured
- A virtual environment manager (e.g., standard library `venv`, `conda`, or `poetry`)

### 1. Fork and Clone the Repository
1. Fork the repository on GitHub to your own account.
2. Clone your fork locally:
   ```bash
   git clone https://github.com/<your-username>/agent-guard.git
   cd agent-guard
   ```

### 2. Set Up a Virtual Environment
Create and activate an isolated Python environment:

**On Linux/macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**On Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install in Editable Mode with Dev Dependencies
Install the package in development mode along with testing and linting tools:

```bash
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

This installs `agent-guard` along with optional development dependencies (`pytest>=7.0`, `ruff>=0.4`).

---

## Running Tests

We use `pytest` for unit and integration testing.

- **Run all tests:**
  ```bash
  pytest
  ```
- **Run tests with verbose output:**
  ```bash
  pytest -v
  ```
- **Run a specific test file:**
  ```bash
  pytest tests/test_evaluator.py
  ```

Ensure all tests pass before submitting a Pull Request.

---

## Running the CLI Locally

Because you installed the project in editable mode (`pip install -e .`), the `agent-guard` command points directly to your local development code:

```bash
# Verify the CLI works
agent-guard --help

# Test a sample check command
agent-guard init sample-agent
```

Alternatively, you can run the CLI module directly:
```bash
python -m src.main --help
```

---

## Code Style and Quality

We use [Ruff](https://github.com/astral-sh/ruff) for linting and formatting.

- **Check for lint errors:**
  ```bash
  ruff check .
  ```
- **Automatically format code:**
  ```bash
  ruff format .
  ```

Please make sure your changes conform to the existing code standards (line length 100, clean imports, Python 3.10+ modern syntax).

---

## Submitting a Pull Request (PR)

1. **Create a topic branch:**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```
2. **Make your changes:**
   - Keep your changes focused and minimal.
   - Add unit tests for any new features or bug fixes.
   - Update documentation or README if you modified CLI flags or policy schema.
3. **Run tests and linter:**
   ```bash
   pytest
   ruff check .
   ```
4. **Commit your changes:**
   Write clear, concise commit messages (preferring [Conventional Commits](https://www.conventionalcommits.org/)):
   ```bash
   git commit -m "feat: add support for environment variable resolution in policies"
   ```
5. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```
6. **Open a Pull Request:**
   Go to the [agent-guard repository](https://github.com/yunaremaia/agent-guard) and open a PR against the `main` branch. Provide a clear description of what the PR does, linking any relevant issue (e.g., `Fixes #32`).

---

## Reporting Issues

If you find a bug or have a feature suggestion:
1. Search [existing issues](https://github.com/yunaremaia/agent-guard/issues) to avoid duplicates.
2. Open a new issue with a clear, descriptive title.
3. Include:
   - Steps to reproduce the bug.
   - Expected behavior vs. actual behavior.
   - Python version and OS environment.
   - Minimal policy YAML and command snippet if applicable.
