# AGENTS.md — Dobby Routes

## Project Overview

**Dobby Routes** is a Python CLI tool that generates optimized China mainland IP route tables by fetching and merging data from APNIC (authoritative RIR) and GitHub-hosted open source IP lists.

**Tech Stack**: Python 3.9+, netaddr, requests
**Entry Point**: `src/dobby_routes/cli.py` → `main()`
**Package**: installed via `pip install -e .`, exposes `dobby-routes` CLI command

## Architecture

```
src/dobby_routes/
├── cli.py         # CLI entry point — orchestrates the full pipeline
├── fetcher.py     # HTTP layer — downloads raw data from APNIC + GitHub
├── parser.py      # Parsing layer — APNIC delegated format + CIDR lists
├── optimizer.py   # Core logic — merge, optimize, complement via netaddr IPSet
└── output.py      # Output layer — writes 3 route table files
```

### Data Flow

```
fetcher (HTTP GET)
    → parser (raw text → structured data)
        → optimizer (merge/dedup/annotate/complement)
            → output (write 3 files)
```

### Module Responsibilities

| Module | Responsibility | Key Dependencies |
|--------|---------------|------------------|
| `fetcher.py` | Download raw data from URLs, retry with backoff, concurrent fetching | `requests`, `concurrent.futures` |
| `parser.py` | Parse APNIC delegated format, validate CIDRs and IP ranges | `ipaddress` (stdlib) |
| `optimizer.py` | Merge routes, compute complement, annotate with operator info | `netaddr` (IPSet, IPNetwork) |
| `output.py` | Write formatted output files with shared timestamp | `datetime` |
| `cli.py` | Wire everything together, handle CLI args and logging | `argparse`, `logging`, `requests` |

## Key Data Sources

- **APNIC**: `delegated-apnic-latest` — pipe-separated, fields: `registry|cc|type|start|value|date|status`
  - `value` is address COUNT (not prefix length). Convert via `summarize_address_range()`.
  - Non-power-of-2 counts produce multiple CIDRs.
- **GitHub (gaoyifan/china-operator-ip)**: `ip-lists` branch — one CIDR per line, per-operator files
- **GitHub (misakaio/chnroutes2)**: aggregated China CIDRs from BGP feeds

## Key Technical Decisions

1. **netaddr over ipaddress** — `IPSet` provides set operations (difference for complement), O(n log n) merge, O(1) membership testing
2. **APNIC count → CIDR** — uses `ipaddress.summarize_address_range()` to correctly handle non-power-of-2 address counts
3. **Annotation strategy** — operator-specific CIDRs matched by IPSet membership; unmatched routes labeled "CN"
4. **Non-routable filtering** — all IANA special-purpose, multicast, and reserved IPv4 ranges (RFC 1918, RFC 6598, RFC 5771, etc.) are excluded from both forward and inverse route tables. Complement is computed against a routable-only universe.
5. **Complement** — `ROUTABLE_UNIVERSE - forward_routes` (excludes private/reserved ranges)

## Output Files

| File | Content | Use Case |
|------|---------|----------|
| `cn_routes_annotated.txt` | CIDR + `# ASN Operator` comments | Human-readable reference |
| `cn_routes.txt` | Optimized CIDRs only | Automation / routing software |
| `cn_routes_inverse.txt` | Complement of forward routes | Bypass routing (route non-CN traffic) |

## Testing

```bash
pytest                # 97 tests, all offline (HTTP mocked)
pytest -v             # verbose output
pytest tests/test_parser.py   # run specific module tests
```

Tests cover: CLI integration (argument parsing, skip modes, error paths, e2e pipeline), APNIC parsing (including invalid IPs, count bounds, overflow), CIDR merging, complement computation, non-routable filtering (RFC 1918, CGNAT, multicast, reserved), output formatting (shared timestamps), fetcher retry logic and concurrent fetching, URL validation.

## Future Extension Points

- **IPv6 support**: Parser already uses `ipaddress` which supports IPv6. Extend `parse_apnic_delegated()` to accept `ipv6` type, use `IPv6Network`/`IPv6Address`. `netaddr.IPSet` handles IPv6 natively. Output files could use `6` suffix (e.g., `cn_routes6.txt`).
- **Additional operators**: Add entries to `fetcher.GITHUB_OPERATOR_URLS` and `optimizer.OPERATOR_INFO`.
- **Output formats**: `output.py` can be extended with new writers (JSON, BIRD config, RouterOS script, etc.).
- **Caching**: `fetcher.py` could cache downloads to avoid re-fetching during development.

## Conventions

- **Logging**: `logging.getLogger(__name__)` per module, output to stderr
- **Error handling**: Invalid CIDRs/lines are warned and skipped, never crash the pipeline; specific exception types only (no bare `except Exception`)
- **Type hints**: All public functions have type annotations
- **No docstrings**: Code is self-documenting; comments only where algorithm is non-obvious
- **Linting**: `ruff check .` and `ruff format .` enforced in CI; config in `pyproject.toml`
- **Network resilience**: `fetcher.fetch_url()` retries 3 times with exponential backoff; operator fetches run concurrently via `ThreadPoolExecutor`
- **Output consistency**: All three output files share a single UTC timestamp generated in `cli.py`

## CI/CD

- **Test & Lint** (`.github/workflows/test.yml`): Runs on push/PR to main. Python 3.9–3.12 matrix for tests; ruff lint and format checks.
- **Update Route Tables** (`.github/workflows/update-routes.yml`): Daily cron at 00:00 UTC. Generates route tables, commits to main, updates `data` branch, creates nightly release with attached files.
