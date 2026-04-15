HANDOFF CONTEXT
===============

USER REQUESTS (AS-IS)
---------------------
- "Please analyze the project repository status and sync with remote GitHub repo if needed."
- "Please further analyze the code repository and the design documents (markdown files) and see if anything can be improved or optimized."
- "I want you to implement all suggested improvements. Please coordinate and perform the changes, do quality check after each tier of change, then finally sync repository with remote end."
- "Looks like there are errors on test & lint on GitHub: https://github.com/helixzz/dobby-routes/actions/runs/24463222357/job/71482994719 . Please investigate and see what should we do?"
- "Great job. Please save context accordingly and create CONTRIBUTING.md and CHANGELOG.md based on project tracking."

GOAL
----
All implementation work is complete. The project is fully synced with remote, CI is green, and documentation is up to date.

WORK COMPLETED
--------------
- I synced the local repo with origin/main (3 commits behind from automated data updates)
- I analyzed and discarded an incorrect local change to cli.py (passed list[str] where IPSet expected)
- I ran a comprehensive 3-agent parallel analysis: code quality, test coverage gaps, project infrastructure
- I implemented all improvements in 3 tiers with quality gates after each:
  - TIER 1 (High Impact): retry with backoff in fetcher.py, concurrent operator fetching via ThreadPoolExecutor, parser hardening (IP validation, count bounds, overflow clamping), CLI test suite (15 tests), CI test+lint workflow
  - TIER 2 (Quality): narrowed bare except catches to specific types in optimizer.py and cli.py, shared timestamp for output files, removed redundant os.makedirs from output.py, added ruff config to pyproject.toml
  - TIER 3 (Polish): pyproject classifiers/keywords, optimizer sort optimization (avoid re-parsing CIDRs), CI workflow fix (pip install -e instead of PYTHONPATH hack), conftest.py shared fixtures, dynamic User-Agent from importlib.metadata
- I fixed CI lint failure: 22 ruff violations (import sorting, unused imports, ambiguous variable names, long lines, formatting)
- I updated AGENTS.md with current state (88 tests, CI/CD docs, new conventions)
- I created CONTRIBUTING.md and CHANGELOG.md

CURRENT STATE
-------------
- Branch: main at commit aaf075a, pushed and synced with origin/main
- Tests: 88/88 passing
- Lint: ruff check and ruff format both clean
- CI: test.yml (Python 3.9-3.12 matrix + lint) and update-routes.yml (daily cron)
- CONTRIBUTING.md and CHANGELOG.md are written but not yet committed

PENDING TASKS
-------------
- Commit and push AGENTS.md + CONTRIBUTING.md + CHANGELOG.md (in progress)
- No other pending work

KEY FILES
---------
- src/dobby_routes/cli.py - CLI entry point, orchestrates full pipeline
- src/dobby_routes/fetcher.py - HTTP layer with retry and concurrent fetching
- src/dobby_routes/parser.py - APNIC/CIDR parsing with input validation
- src/dobby_routes/optimizer.py - Route merging, complement, annotation via netaddr
- src/dobby_routes/output.py - File writers with shared timestamp support
- tests/test_cli.py - CLI integration tests (15 tests, mocked HTTP)
- tests/conftest.py - Shared test fixtures
- .github/workflows/test.yml - CI test+lint workflow
- .github/workflows/update-routes.yml - Daily route generation workflow
- pyproject.toml - Package config with ruff/pytest settings

IMPORTANT DECISIONS
-------------------
- Chose retry with exponential backoff (1s, 2s, 4s) over circuit breaker pattern for simplicity
- Used ThreadPoolExecutor(max_workers=4) for concurrent operator fetching instead of asyncio
- Narrowed exception handling to specific types rather than adding catch-all fallback
- Made output timestamp a parameter with fallback to datetime.now() for backward compatibility
- Used importlib.metadata.version() with graceful fallback to "dev" for uninstalled packages
- Chose ruff over black+flake8+isort for unified linting/formatting

EXPLICIT CONSTRAINTS
--------------------
- Python >=3.9 required (uses builtin generics like list[str], dict[str, list[str]])
- No docstrings policy: code is self-documenting; comments only where algorithm is non-obvious
- Error handling: invalid CIDRs/lines are warned and skipped, never crash the pipeline
- Specific exception types only (no bare except Exception)
- ruff enforced in CI: line-length 100, rules E/F/W/I

CONTEXT FOR CONTINUATION
------------------------
- The project has no venv locally; tests run via PYTHONPATH=src python3 -m pytest
- pip3 is available but pip install -e . fails on the system Python 3.9.6 due to old setuptools; use PYTHONPATH=src for local dev
- gh CLI is not installed on this machine; GitHub API access requires webfetch workaround
- The Node.js 20 deprecation warnings in CI are cosmetic and can be resolved by updating to actions/checkout@v5 and actions/setup-python@v6 when available
- output/*.txt files are tracked by CI (not gitignored) — they're auto-updated by the daily cron workflow
