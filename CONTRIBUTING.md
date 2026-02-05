# Contributing to Rootly MCP Server

## Submitting Changes

1. Fork the repository and create a feature branch
2. Make your changes with clear, atomic commits
3. Open a Pull Request with a description that clearly explains:
   - What the change does
   - Why it's needed
   - Any breaking changes or migration steps

## Developer Setup

### Prerequisites
- Python 3.12 or higher
- [`uv`](https://github.com/astral-sh/uv) for dependency management

### 1. Set Up Virtual Environment

Create and activate a virtual environment:

```bash
uv venv .venv
source .venv/bin/activate  # Always activate before running scripts
```

### 2. Install Dependencies

Install all project dependencies:

```bash
uv pip install .
```

To add new dependencies during development:
```bash
uv pip install <package>
```

### 3. Set Up Git Hooks (Recommended)

Install pre-commit hooks to automatically run linting and tests before commits:

```bash
./scripts/setup-hooks.sh
```

This ensures code quality by running:
- Ruff linting
- Pyright type checking
- Unit tests

### 4. Verify Installation

The server should now be ready to use with your MCP-compatible editor.

Additional testing tools are available in the `tests/` directory.
