# Contributing to Dobby Routes

## Development Setup

```bash
git clone https://github.com/helixzz/dobby-routes.git
cd dobby-routes
pip install -e ".[dev]"
```

This installs the package in editable mode with all dev dependencies (pytest, pytest-mock, ruff).

## Running Tests

```bash
pytest             # run all 97 tests
pytest -v          # verbose output
pytest tests/test_parser.py  # run a specific module
```

All tests run offline — HTTP calls are mocked. No network access required.

## Code Quality

Lint and format checks are enforced in CI. Run them locally before pushing:

```bash
ruff check .          # lint (import sorting, unused imports, style)
ruff format .         # auto-format
ruff check --fix .    # auto-fix lint issues where possible
```

Configuration lives in `pyproject.toml` under `[tool.ruff]`:
- Line length: 100
- Target: Python 3.9
- Rules: E (pycodestyle), F (pyflakes), W (warnings), I (isort)

## Project Structure

```
src/dobby_routes/
├── cli.py         # CLI entry point — orchestrates the full pipeline
├── fetcher.py     # HTTP layer — downloads with retry + concurrent fetching
├── parser.py      # Parsing layer — APNIC delegated format + CIDR lists
├── optimizer.py   # Core logic — merge, optimize, complement via netaddr IPSet
└── output.py      # Output layer — writes 3 route table files

tests/
├── conftest.py        # Shared test fixtures
├── test_cli.py        # CLI integration tests (mocked HTTP)
├── test_fetcher.py    # Fetcher unit tests (retry, concurrency)
├── test_optimizer.py  # Optimizer unit tests (merge, complement, annotate)
├── test_output.py     # Output writer tests
└── test_parser.py     # Parser unit tests (APNIC + CIDR)
```

## Commit Message Style

Follow conventional commits:

```
feat: add IPv6 support to parser
fix: handle APNIC entries with zero count
refactor: extract retry logic into helper
test: add edge cases for CIDR overflow
docs: update AGENTS.md with new conventions
style: fix ruff lint violations
ci: add Python 3.13 to test matrix
data: update route tables 2025-04-15
```

## Adding a New Operator

1. Add the URL to `fetcher.GITHUB_OPERATOR_URLS`
2. Add the ASN/name mapping to `optimizer.OPERATOR_INFO`
3. Add a test in `tests/test_optimizer.py` for the new annotation
4. Run `pytest` and `ruff check .` to verify

## Adding a New Output Format

1. Add a new writer function in `output.py` following the existing pattern
2. Wire it into `cli.py`'s `_run()` function
3. Add tests in `tests/test_output.py`

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes
3. Ensure `pytest` passes (97+ tests)
4. Ensure `ruff check .` and `ruff format --check .` pass
5. Push and open a PR against `main`
6. CI will run tests on Python 3.9–3.12 and lint checks automatically
