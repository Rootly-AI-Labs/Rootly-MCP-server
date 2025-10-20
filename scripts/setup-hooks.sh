#!/bin/bash
# Setup git hooks for this repository
# Run this script after cloning: ./scripts/setup-hooks.sh

set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

echo "🔧 Setting up git hooks..."

# Create pre-commit hook
cat > "$HOOKS_DIR/pre-commit" << 'EOF'
#!/bin/bash
# Pre-commit hook to run linting and type checking
# This ensures code quality before committing

set -e

echo "🔍 Running pre-commit checks..."
echo ""

# 1. Ruff linting
echo "📝 Checking code style with ruff..."
if ! uv run ruff check .; then
    echo "❌ Ruff linting failed!"
    echo "💡 Try running: uv run ruff check . --fix"
    exit 1
fi
echo "✅ Ruff passed!"
echo ""

# 2. Pyright type checking
echo "🔍 Running type checks with pyright..."
if ! uv run pyright; then
    echo "❌ Type checking failed!"
    echo "💡 Fix type errors or add type: ignore comments"
    exit 1
fi
echo "✅ Pyright passed!"
echo ""

# 3. Run unit tests (quick check)
echo "🧪 Running unit tests..."
if ! uv run pytest tests/unit/ -q --tb=line; then
    echo "❌ Tests failed!"
    echo "💡 Fix failing tests before committing"
    exit 1
fi
echo "✅ Tests passed!"
echo ""

echo "✅ All pre-commit checks passed! Proceeding with commit..."
exit 0
EOF

chmod +x "$HOOKS_DIR/pre-commit"

echo "✅ Git hooks installed successfully!"
echo ""
echo "The following checks will run before every commit:"
echo "  1. Ruff linting"
echo "  2. Pyright type checking"
echo "  3. Unit tests"
echo ""
echo "To skip hooks (not recommended): git commit --no-verify"
