# AGENTS.md — Dobby Routes

## Project Overview

**Dobby Routes** is a Python CLI tool that generates optimized China mainland IP route tables by fetching and merging data from APNIC (authoritative RIR) and GitHub-hosted open source IP lists.

**Tech Stack**: Python 3.9+, netaddr, requests
**Entry Point**: `src/dobby_routes/cli.py` → `main()`
**Package**: installed via `pip install -e .`, exposes `dobby-routes` CLI command
**Version**: maintained in `pyproject.toml` `[project].version`

## Architecture

```
src/dobby_routes/
├── cli.py         # CLI entry point — orchestrates the full pipeline
├── fetcher.py     # HTTP layer — downloads raw data from APNIC, GitHub, AWS, Cloudflare, Google, bgp.tools
├── parser.py      # Parsing layer — APNIC delegated, CIDR lists, AWS/Google JSON, bgp.tools table/ASNs
├── optimizer.py   # Core logic — merge, optimize, complement, BGP minimization, ASN enrichment
├── validator.py   # Quality guardrails — canary IP assertions and baseline drift checks
└── output.py      # Output layer — route tables, stats JSON, BIRD/RouterOS/nftables/sing-box writers
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
  - Only `allocated` and `assigned` statuses are accepted.
  - For IPv4, `value` is address COUNT (not prefix length); converted via `summarize_address_range()`. Non-power-of-2 counts produce multiple CIDRs.
  - For IPv6 (`--ipv6`), `value` is the prefix length directly.
- **GitHub (gaoyifan/china-operator-ip)**: `ip-lists` branch — one CIDR per line, per-operator IPv4 and IPv6 files plus `china6.txt`
- **chnroutes2**: SukkaW optimized chnroutes2 CIDRs (`chnroutes2.cdn.skk.moe`) as primary; falls back to `misakaio/chnroutes2` if the optimized source cannot be fetched

## Key Technical Decisions

1. **netaddr over ipaddress** — batch `IPSet(networks)` provides fast O(n log n) merge, set operations (difference for complement), and IPv4/IPv6 support
2. **APNIC count → CIDR** — uses `ipaddress.summarize_address_range()` to correctly handle non-power-of-2 IPv4 address counts, and prefix length directly for IPv6
3. **Annotation strategy** — `annotate_routes()` partitions merged routes into strictly disjoint CIDRs with deterministic multi-operator labels (`", ".join(...)`); unmatched routes labeled `"CN"`
4. **Non-routable filtering** — all IANA special-purpose, multicast, and reserved IPv4 ranges (`NON_ROUTABLE_RANGES`) and non-global/special IPv6 ranges (`NON_ROUTABLE_RANGES_V6` outside/within `2000::/3`) are excluded from both forward and inverse route tables
5. **Complement** — `ROUTABLE_UNIVERSE - forward_routes` for IPv4 and `ROUTABLE_UNIVERSE_V6 - forward_routes_v6` for IPv6
6. **Guardrails** — enabled remote sources fail closed if they yield zero usable CIDRs; optional `--min-*` flags enforce minimum route counts before any output file is written

## Output Files

| File | Content | Use Case |
|------|---------|----------|
| `cn_routes_annotated.txt` | Disjoint IPv4 CIDR + `# ASN Operator` comments | Human-readable reference |
| `cn_routes.txt` | Optimized IPv4 CIDRs only | Automation / routing software |
| `cn_routes_inverse.txt` | Complement of IPv4 forward routes | Bypass routing (route non-CN traffic) |
| `cn_routes6_annotated.txt` | Disjoint IPv6 CIDR + `# ASN Operator` comments (`--ipv6`) | Human-readable IPv6 reference |
| `cn_routes6.txt` | Optimized IPv6 CIDRs only (`--ipv6`) | IPv6 automation / BGP |
| `cn_routes6_inverse.txt` | Complement of IPv6 forward routes (`--ipv6`) | IPv6 bypass routing |

## Testing

```bash
pytest                # 191 tests, all offline (HTTP mocked)
pytest -v             # verbose output
pytest tests/test_parser.py   # run specific module tests
```

Tests cover: CLI integration (argument parsing, skip modes, IPv6 dual-stack pipeline, guardrails, stats JSON, error paths, e2e pipeline), APNIC parsing (status validation, IPv4 count bounds/overflow, IPv6 prefix lengths), batch CIDR merging, disjoint operator annotation, IPv4 & IPv6 complement computation and non-routable filtering, output formatting (shared timestamps, UTF-8, IPv6 headers, stats JSON), fetcher smart retry logic (no retry on non-transient 4xx, retry on 429/5xx) and concurrent fetching, URL validation.

## Future Extension Points

- **Additional operators**: Add entries to `fetcher.GITHUB_OPERATOR_URLS` / `GITHUB_OPERATOR_URLS_V6` and `optimizer.OPERATOR_INFO`.
- **Output formats**: `output.py` can be extended with new writers (BIRD config, RouterOS script, nftables, sing-box/Clash rule-set, etc.).
- **Caching**: `fetcher.py` could cache downloads on disk to avoid re-fetching during local development.

## Development Rules

### Mandatory on Every Change

1. **Run `pytest`** — all tests must pass before committing
2. **Run `ruff check .` and `ruff format --check .`** — lint and format must be clean
3. **Update `CHANGELOG.md`** — every user-facing or behavioral change gets an entry under the current version's `Added`, `Changed`, or `Fixed` section
4. **Bump version in `pyproject.toml`** — when releasing a new version, bump `[project].version` and add a new section in `CHANGELOG.md`; keep both in sync
5. **Commit with conventional prefix** — `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `style:`, `ci:`, `chore:`, `data:`

### Code Quality Rules

- **No bare `except Exception`** — catch specific types only (e.g., `(ValueError, TypeError, AddrFormatError)`)
- **No type suppressions** — never use `# type: ignore`, `cast(Any, ...)`, or equivalent unless absolutely unavoidable
- **No docstrings** — code is self-documenting; comments only where the algorithm is non-obvious or for RFC/standard references
- **Type hints** — all public functions must have type annotations
- **Line length** — 100 characters max (enforced by ruff)
- **Import order** — enforced by ruff isort rules (`I001`)

### IP Routing Correctness (CRITICAL)

- **All route tables are Internet-only** — no private, reserved, multicast, or special-purpose IPv4 ranges may appear in any output file
- **Non-routable ranges** are defined in `optimizer.NON_ROUTABLE_RANGES` with RFC references; update this list if IANA publishes new special-purpose allocations
- **Forward routes are defensively filtered** — even though APNIC shouldn't allocate private space, `filter_non_routable()` is applied after merge to catch upstream data errors
- **Complement uses `ROUTABLE_UNIVERSE`** not `0.0.0.0/0` — this ensures the inverse table never includes private ranges
- **IP sorting must be numeric** — sort by `IPNetwork` objects, never by string (lexicographic sort puts `10.x` before `2.x`)

### Error Handling

- Invalid CIDRs/lines are warned via `logger.warning()` and skipped — never crash the pipeline
- `fetcher.fetch_url()` retries 3 times with exponential backoff (1s, 2s, 4s)
- `cli.py main()` catches `(requests.RequestException, ValueError, OSError)` — not bare `Exception`
- Parser validates IP format, count bounds, and IPv4 overflow before producing CIDRs

### Output Consistency

- All three output files share a single UTC timestamp generated once in `cli.py` and passed to writers
- Output writers do NOT create directories — `cli.py` handles `os.makedirs()` once
- Route counts in file headers must match the actual number of data lines

### CI/CD Caveats

- **Test & Lint** (`.github/workflows/test.yml`): Runs on push/PR to main. Python 3.10–3.13 matrix for tests (Ubuntu 26.04 runner no longer ships EOL Python 3.9); ruff lint and format checks. Uses `actions/checkout@v7` and `actions/setup-python@v7` (Node.js 24 native).
- **Update Route Tables** (`.github/workflows/update-routes.yml`): Runs every 6 hours (`17 */6 * * *` UTC). Generates IPv4 + IPv6 + BGP-minimized route tables and `formats/{bird,routeros,nftables,singbox}` with `--ipv6`, `--aws-cn`, `--protect-overseas`, `--bgp`, `--verify-canaries`, minimum route counts, and ±15% baseline drift guardrails; ignores timestamp-only diffs, commits to `main`, updates `data` branch, creates nightly release with diff summary, and prunes nightly releases older than 30 days.
- **Nightly release tags** use `nightly-${DATE}` format; same-day re-triggers delete the existing tag/release before re-creating
- **`output/*.txt` files are tracked in git** — they are auto-updated by the daily cron workflow, not gitignored

## Conventions

- **Logging**: `logging.getLogger(__name__)` per module, output to stderr
- **Linting**: `ruff check .` and `ruff format .` enforced in CI; config in `pyproject.toml`
- **Network resilience**: `fetcher.fetch_url()` retries 3 times with exponential backoff; operator fetches run concurrently via `ThreadPoolExecutor`
- **User-Agent**: dynamically derived from package metadata via `importlib.metadata.version()` with fallback to `"dobby-routes/dev"`
