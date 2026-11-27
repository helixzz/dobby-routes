# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.4.1] - 2026-11-27

### Added
- Curated US-specialized routing table support via `--us-special-dir` and `us_special/asns.txt` (seeded with `AS399358` Anthropic / Claude), generating `us_routes.txt` and `us_routes6.txt` from live BGP prefixes and optional local CIDRs without pulling in shared CDNs
- `parse_asn_list()`, `load_asn_file()`, and `write_custom_routes()` helpers plus 2 new unit/integration tests (191 tests total)

### Changed
- Scheduled workflow (`.github/workflows/update-routes.yml`) now builds and publishes `us_routes.txt` and `us_routes6.txt` to `main`, `data` branch, and Nightly Releases

## [0.4.0] - 2026-11-27

### Added
- Official AWS China (`cn-north-1` / `cn-northwest-1`) IPv4 and IPv6 source via `--aws-cn` (`ip-ranges.amazonaws.com/ip-ranges.json`), closing gaps for non-APNIC Chinese cloud allocations
- Defensive overseas protection via `--protect-overseas`, subtracting official Cloudflare (`ips-v4`/`ips-v6`) and Google (`goog.json`) overseas IP ranges
- China Science and Technology Network (`cstnet`, AS7497) added to GitHub IPv4 and IPv6 operator sources and annotations
- Global real-time BGP integration via `--bgp` (`bgp.tools/table.txt` and `bgp.tools/asns.csv`):
  - Enriches generic `# CN` annotations in `cn_routes_annotated.txt` and `cn_routes6_annotated.txt` with real BGP origin ASNs and organization names
  - Generates provably optimal lossless BGP-minimized tables (`cn_routes_bgp.txt`, `cn_routes_bgp_inverse.txt`, `cn_routes6_bgp.txt`, `cn_routes6_bgp_inverse.txt`) that bridge unannounced gaps for 40%–92% smaller BGP/router prefix counts while preserving 100% accuracy for all active global BGP prefixes and local allowlists/denylists
- Built-in canary IP validation (`--verify-canaries`) and relative baseline drift guardrail (`--baseline-stats` + `--max-drift-pct`) in `validator.py`, failing closed before writing any output files
- Multi-format router/proxy exports via `--formats bird,routeros,nftables,singbox` under `<output-dir>/formats/` (BIRD2 prefix sets, RouterOS `.rsc` address-lists, nftables sets, sing-box v3 rule-set JSON)
- 20 new unit and integration tests covering AWS/Google/BGP parsing, lossless BGP minimization, BGP ASN annotation enrichment, canary & drift validators, extra export formats, and CLI integration (189 tests total)

### Changed
- Updated User-Agent to include the repository URL (`dobby-routes/<version> (+https://github.com/helixzz/dobby-routes)`) for upstream compliance
- Upgraded scheduled workflow (`.github/workflows/update-routes.yml`) to run every 6 hours (`17 */6 * * *` UTC) with `--aws-cn`, `--protect-overseas`, `--bgp`, `--verify-canaries`, `--max-drift-pct 15`, and `--formats bird,routeros,nftables,singbox`

## [0.3.0] - 2026-11-27

### Added
- Opt-in IPv6 route table generation via `--ipv6`, producing `cn_routes6.txt`, `cn_routes6_annotated.txt`, and `cn_routes6_inverse.txt` from APNIC delegated IPv6 allocations and `gaoyifan/china-operator-ip` IPv6 lists
- `NON_ROUTABLE_RANGES_V6`, `NON_ROUTABLE_SET_V6`, `ROUTABLE_UNIVERSE_V6` (`2000::/3` minus IANA IPv6 special-purpose blocks), `filter_non_routable_v6()`, and `compute_complement_v6()` in `optimizer.py`
- Reviewed IPv6 scope enforcement (`REVIEWED_CIDR_SOURCE_SCOPES_V6`) for Telegram's official CIDR source when `--ipv6` is enabled
- Fail-closed publish guardrails: `--min-routes`, `--min-inverse-routes`, `--min-ipv6-routes`, `--min-ipv6-inverse-routes` (validated before writing output files), plus automatic fail-closed checks when any enabled remote source returns zero usable CIDRs
- Optional `--stats-json <path>` flag and `write_stats()` writer for machine-readable run statistics
- Real content-based diff detection (ignoring header timestamps), daily diff summary tables in Release Notes / GitHub Actions Job Summary, and 30-day nightly release retention pruning in `.github/workflows/update-routes.yml`
- 25 new unit and integration tests covering IPv6 parsing/optimization/CLI, disjoint operator annotation, APNIC status validation, smart HTTP 4xx retries, guardrails, and stats output (169 tests total)

### Changed
- `merge_routes()` now batch-constructs `netaddr.IPSet` from validated networks instead of incremental per-CIDR `.add()`, delivering ~400x faster route merging (from ~74s to <0.2s in daily CI)
- `annotate_routes()` now partitions merged routes into strictly disjoint CIDRs with deterministic multi-operator labels (e.g. `AS4134/AS4812 China Telecom, AS9808 China Mobile`) instead of emitting overlapping duplicates
- `parse_apnic_delegated()` now explicitly accepts only `allocated` and `assigned` statuses and supports `ip_version=6`
- `fetch_url()` no longer retries non-transient HTTP 4xx errors (still retries 408, 429, 5xx, and transport errors); `fetch_all_operators()` returns deterministic key order
- `output.py` writers now explicitly specify `encoding="utf-8"` and support IPv6 headers via `ip_version`
- CI workflows upgraded to `actions/checkout@v7` and `actions/setup-python@v7` (Node.js 24 native), test matrix updated to Python 3.10–3.13 (Ubuntu 26.04 drops EOL Python 3.9), and daily schedule shifted to `17 1 * * *` UTC to avoid midnight queue congestion

### Fixed
- Fixed nightly Release Notes displaying `cn_routes.txt` count instead of the actual `cn_routes_annotated.txt` count
- Prevented empty daily commits and releases when only the UTC header timestamp changed

## [0.2.0] - 2026-04-16

### Added
- Non-routable IPv4 filtering: all IANA special-purpose, multicast, and reserved ranges are excluded from route tables
- `NON_ROUTABLE_RANGES` constant in `optimizer.py` with 18 CIDR blocks covering RFC 1918, RFC 6598 (CGNAT), RFC 1122 (loopback), RFC 3927 (link-local), RFC 5737 (documentation), RFC 5771 (multicast), RFC 1112 (reserved), and more
- `filter_non_routable()` function removes private/reserved ranges from merged routes
- `ROUTABLE_UNIVERSE` constant: `0.0.0.0/0` minus all non-routable ranges
- 9 new tests for non-routable filtering (RFC 1918, CGNAT, loopback, link-local, multicast, reserved, documentation nets, complement exclusion, routable universe integrity)
- Repository-local `allowlists/` and `denylists/` directories with `--allowlist-dir` and `--denylist-dir` overrides for IPv4 route additions and exclusions
- Strict HTTPS `@include <URL>` directives for local route files, with non-recursive parsing, redirect rejection, response size limits, and IPv6 skipping
- Telegram's official CIDR source in `denylists/telegram.txt` for automatic IPv4 deny routing
- A reviewed Telegram IPv4 scope that fails closed when the upstream source returns an unapproved route

### Changed
- `compute_complement()` now subtracts from `ROUTABLE_UNIVERSE` instead of `0.0.0.0/0`, ensuring inverse route tables never contain private/reserved ranges
- `cli.py` pipeline applies `filter_non_routable()` after merge, before optimize/annotate/complement
- Forward routes are defensively filtered to catch upstream data errors from APNIC or GitHub sources
- Local allowlists are merged with remote routes before denylists are subtracted; final routes now drive optimized, annotated, and inverse outputs
- Operator annotations are intersected with final routes, preventing denied or non-routable operator CIDRs from appearing in annotated output
- Scheduled route generation passes explicit workspace paths for output, allowlists, and denylists
- `fetch_chnroutes2()` now uses SukkaW's optimized chnroutes2 endpoint first and falls back to Misaka's original source only if the primary fetch fails

### Fixed
- Route output files now sorted numerically by IP address instead of lexicographically (e.g. `2.x` before `10.x`)
- Nightly release workflow now correctly deletes the date-specific tag before re-creating, fixing same-day manual re-trigger failures

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
