import argparse
import logging
import os
import sys
from datetime import datetime, timezone

import requests
from netaddr import IPSet

from .fetcher import (
    REVIEWED_CIDR_SOURCE_SCOPES,
    fetch_all_operators,
    fetch_apnic,
    fetch_chnroutes2,
    fetch_cidr_source,
)
from .optimizer import (
    annotate_routes,
    compute_complement,
    filter_non_routable,
    merge_routes,
    optimize_routes,
)
from .output import write_annotated, write_complement, write_optimized
from .parser import (
    apnic_entry_to_cidrs,
    load_cidr_directory,
    parse_apnic_delegated,
    parse_cidr_list,
)

logger = logging.getLogger(__name__)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dobby-routes",
        description="Generate China mainland IP route tables",
    )
    parser.add_argument(
        "--output-dir",
        default="./output",
        help="output directory (default: ./output)",
    )
    parser.add_argument(
        "--allowlist-dir",
        default="./allowlists",
        help="directory of local IPv4 routes to include (default: ./allowlists)",
    )
    parser.add_argument(
        "--denylist-dir",
        default="./denylists",
        help="directory of local IPv4 routes to exclude (default: ./denylists)",
    )
    parser.add_argument(
        "--skip-github",
        action="store_true",
        help="skip GitHub data sources",
    )
    parser.add_argument(
        "--skip-apnic",
        action="store_true",
        help="skip APNIC data source",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable debug logging",
    )
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    try:
        _run(args)
    except KeyboardInterrupt:
        logger.info("Interrupted")
        sys.exit(130)
    except (requests.RequestException, ValueError, OSError) as e:
        logger.error("Fatal: %s", e)
        sys.exit(1)


def _run(args: argparse.Namespace) -> None:
    apnic_cidrs: list[str] = []
    operator_cidrs: dict[str, list[str]] = {}
    extra_cidrs: list[str] = []
    allowlist_cidrs = _load_cidr_sources(args.allowlist_dir)
    denylist_cidrs = _load_cidr_sources(args.denylist_dir)
    logger.info("Allowlists: %d CIDRs", len(allowlist_cidrs))
    logger.info("Denylists: %d CIDRs", len(denylist_cidrs))

    if not args.skip_apnic:
        logger.info("Fetching APNIC delegated data...")
        raw_apnic = fetch_apnic()
        entries = parse_apnic_delegated(raw_apnic)
        for entry in entries:
            apnic_cidrs.extend(apnic_entry_to_cidrs(entry))
        logger.info("APNIC: %d entries -> %d CIDRs", len(entries), len(apnic_cidrs))

    if not args.skip_github:
        logger.info("Fetching GitHub operator data...")
        raw_operators = fetch_all_operators()
        for name, text in raw_operators.items():
            cidrs = parse_cidr_list(text)
            operator_cidrs[name] = cidrs
            logger.info("  %s: %d CIDRs", name, len(cidrs))

        logger.info("Fetching chnroutes2 data...")
        raw_chnroutes2 = fetch_chnroutes2()
        extra_cidrs = parse_cidr_list(raw_chnroutes2)
        logger.info("  chnroutes2: %d CIDRs", len(extra_cidrs))

    all_cidr_lists = [apnic_cidrs, extra_cidrs, allowlist_cidrs]
    for cidrs in operator_cidrs.values():
        all_cidr_lists.append(cidrs)

    if not any(all_cidr_lists):
        logger.error("No positive routes loaded. Use a remote source or an allowlist.")
        sys.exit(1)

    logger.info("Merging and optimizing routes...")
    positive_routes = merge_routes(all_cidr_lists)
    deny_routes = merge_routes([denylist_cidrs])
    final_routes = filter_non_routable(positive_routes - deny_routes)
    logger.info(
        "Positive: %d routes, denied: %d routes, final: %d routes",
        sum(1 for _ in positive_routes.iter_cidrs()),
        sum(1 for _ in deny_routes.iter_cidrs()),
        sum(1 for _ in final_routes.iter_cidrs()),
    )
    optimized = optimize_routes(final_routes)
    logger.info("Optimized: %d routes", len(optimized))

    logger.info("Generating annotated routes...")
    annotated = annotate_routes(operator_cidrs, final_routes)

    logger.info("Computing complement routes...")
    complement = compute_complement(final_routes)
    logger.info("Complement: %d routes", len(complement))

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    annotated_path = os.path.join(output_dir, "cn_routes_annotated.txt")
    optimized_path = os.path.join(output_dir, "cn_routes.txt")
    complement_path = os.path.join(output_dir, "cn_routes_inverse.txt")

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    write_annotated(annotated_path, annotated, timestamp)
    write_optimized(optimized_path, optimized, timestamp)
    write_complement(complement_path, complement, timestamp)

    logger.info("Done. Output written to %s/", output_dir)
    logger.info("  %s (%d routes)", annotated_path, len(annotated))
    logger.info("  %s (%d routes)", optimized_path, len(optimized))
    logger.info("  %s (%d routes)", complement_path, len(complement))


def _load_cidr_sources(directory: str) -> list[str]:
    sources = load_cidr_directory(directory)
    cidrs = list(sources.cidrs)
    for url in sources.urls:
        included_cidrs = parse_cidr_list(fetch_cidr_source(url), source=url)
        if not included_cidrs:
            raise ValueError(f"CIDR source contains no usable IPv4 CIDRs: {url}")
        reviewed_scope = REVIEWED_CIDR_SOURCE_SCOPES.get(url)
        if reviewed_scope is not None and IPSet(included_cidrs) - IPSet(reviewed_scope):
            raise ValueError(f"CIDR source contains routes outside reviewed scope: {url}")
        cidrs.extend(included_cidrs)
    return cidrs


if __name__ == "__main__":
    main()
