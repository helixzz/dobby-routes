# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-04-16

### Added
- Non-routable IPv4 filtering: all IANA special-purpose, multicast, and reserved ranges are excluded from route tables
- `NON_ROUTABLE_RANGES` constant in `optimizer.py` with 18 CIDR blocks covering RFC 1918, RFC 6598 (CGNAT), RFC 1122 (loopback), RFC 3927 (link-local), RFC 5737 (documentation), RFC 5771 (multicast), RFC 1112 (reserved), and more
- `filter_non_routable()` function removes private/reserved ranges from merged routes
- `ROUTABLE_UNIVERSE` constant: `0.0.0.0/0` minus all non-routable ranges
- 9 new tests for non-routable filtering (RFC 1918, CGNAT, loopback, link-local, multicast, reserved, documentation nets, complement exclusion, routable universe integrity)

### Changed
- `compute_complement()` now subtracts from `ROUTABLE_UNIVERSE` instead of `0.0.0.0/0`, ensuring inverse route tables never contain private/reserved ranges
- `cli.py` pipeline applies `filter_non_routable()` after merge, before optimize/annotate/complement
- Forward routes are defensively filtered to catch upstream data errors from APNIC or GitHub sources

## [0.1.1] - 2026-04-15

### Added
- Retry with exponential backoff for HTTP fetches (3 attempts, 1s/2s/4s waits)
- Concurrent operator fetching via `ThreadPoolExecutor` (4 workers)
- Input validation in `apnic_entry_to_cidrs()`: rejects invalid IPs, zero/negative counts, clamps IPv4 overflow
- CLI test suite: 15 tests covering argument parsing, skip modes, e2e pipeline, error paths, exit codes
- Parser edge case tests: invalid IP, zero count, negative count, overflow clamping
- Fetcher retry tests: connection error recovery, retry exhaustion, HTTP error retry
- Output timestamp test: verifies shared timestamp across all three files
- CI test+lint workflow (`.github/workflows/test.yml`): Python 3.9–3.12 matrix, ruff lint and format checks
- Shared test fixtures in `tests/conftest.py`
- Ruff configuration in `pyproject.toml` (line-length 100, isort, pyflakes, pycodestyle)
- Package classifiers and keywords in `pyproject.toml`
- Dynamic User-Agent from package metadata with graceful fallback
- CONTRIBUTING.md and CHANGELOG.md

### Changed
- `fetch_operator()` raises `ValueError` instead of catch-and-reraise `KeyError`
- `cli.py` catches `(requests.RequestException, ValueError, OSError)` instead of bare `Exception`
- `optimizer.py` catches `(ValueError, TypeError, AddrFormatError)` instead of bare `Exception`
- Output writers accept optional `timestamp` parameter; `cli.py` passes a shared timestamp
- Removed redundant `os.makedirs()` from output writers (handled once in `cli.py`)
- Removed unused `cidr_merge` import from `optimizer.py`
- `annotate_routes()` sorts by `IPNetwork` objects directly instead of re-parsing strings
- CI update-routes workflow uses `pip install -e .` and `dobby-routes` CLI instead of `PYTHONPATH` hack
- Updated AGENTS.md with current test count (88), CI/CD docs, and new conventions

### Fixed
- Ruff lint violations: import sorting, unused imports, ambiguous variable names, long lines

## [0.1.0] - 2026-04-13

### Added
- Initial release
- APNIC delegated file parsing with IPv4 support
- GitHub operator IP list fetching (China Telecom, China Unicom, China Mobile, CERNET)
- chnroutes2 BGP feed integration
- Route merging and optimization via netaddr `IPSet`
- Complement route table generation (inverse of forward routes)
- Operator annotation system with ASN labels
- CLI with `--output-dir`, `--skip-github`, `--skip-apnic`, `-v` flags
- Three output files: annotated, optimized, and inverse route tables
- Daily route table generation via GitHub Actions
- Nightly releases with attached route table files
- `data` branch with latest pre-built route tables
- 64 unit tests with full HTTP mocking
- Type hints on all public functions
- README.md with installation, usage, and data source documentation
- AGENTS.md with architecture and technical decision documentation
