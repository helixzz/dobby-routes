import argparse
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional

import requests
from netaddr import IPSet

from .fetcher import (
    REVIEWED_CIDR_SOURCE_SCOPES,
    REVIEWED_CIDR_SOURCE_SCOPES_V6,
    fetch_all_operators,
    fetch_all_operators_v6,
    fetch_apnic,
    fetch_china_v6,
    fetch_chnroutes2,
    fetch_cidr_source,
)
from .optimizer import (
    annotate_routes,
    compute_complement,
    compute_complement_v6,
    filter_non_routable,
    filter_non_routable_v6,
    merge_routes,
    optimize_routes,
)
from .output import write_annotated, write_complement, write_optimized, write_stats
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
        help="directory of local routes to include (default: ./allowlists)",
    )
    parser.add_argument(
        "--denylist-dir",
        default="./denylists",
        help="directory of local routes to exclude (default: ./denylists)",
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
        "--ipv6",
        action="store_true",
        help="also generate IPv6 route tables (cn_routes6*.txt)",
    )
    parser.add_argument(
        "--min-routes",
        type=int,
        default=0,
        help="minimum required IPv4 forward routes guardrail (0 disables)",
    )
    parser.add_argument(
        "--min-inverse-routes",
        type=int,
        default=0,
        help="minimum required IPv4 inverse routes guardrail (0 disables)",
    )
    parser.add_argument(
        "--min-ipv6-routes",
        type=int,
        default=0,
        help="minimum required IPv6 forward routes guardrail (0 disables)",
    )
    parser.add_argument(
        "--min-ipv6-inverse-routes",
        type=int,
        default=0,
        help="minimum required IPv6 inverse routes guardrail (0 disables)",
    )
    parser.add_argument(
        "--stats-json",
        default=None,
        help="optional path to write run statistics as JSON",
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


def _validate_threshold(name: str, actual: int, minimum: int) -> None:
    if minimum < 0:
        raise ValueError(f"{name} must be non-negative: {minimum}")
    if minimum > 0 and actual < minimum:
        raise ValueError(f"{name} guardrail failed: got {actual}, expected at least {minimum}")


def _run(args: argparse.Namespace) -> None:
    enable_ipv6 = bool(getattr(args, "ipv6", False))
    min_routes = int(getattr(args, "min_routes", 0))
    min_inverse_routes = int(getattr(args, "min_inverse_routes", 0))
    min_ipv6_routes = int(getattr(args, "min_ipv6_routes", 0))
    min_ipv6_inverse_routes = int(getattr(args, "min_ipv6_inverse_routes", 0))
    stats_json: Optional[str] = getattr(args, "stats_json", None)

    for label, value in (
        ("--min-routes", min_routes),
        ("--min-inverse-routes", min_inverse_routes),
        ("--min-ipv6-routes", min_ipv6_routes),
        ("--min-ipv6-inverse-routes", min_ipv6_inverse_routes),
    ):
        if value < 0:
            raise ValueError(f"{label} must be non-negative: {value}")

    include_cache: dict[str, str] = {}

    apnic_cidrs: list[str] = []
    operator_cidrs: dict[str, list[str]] = {}
    extra_cidrs: list[str] = []
    allowlist_cidrs = _load_cidr_sources(
        args.allowlist_dir, ip_version=4, include_cache=include_cache
    )
    denylist_cidrs = _load_cidr_sources(
        args.denylist_dir, ip_version=4, include_cache=include_cache
    )
    logger.info("Allowlists: %d CIDRs", len(allowlist_cidrs))
    logger.info("Denylists: %d CIDRs", len(denylist_cidrs))

    raw_apnic: Optional[str] = None
    if not args.skip_apnic:
        logger.info("Fetching APNIC delegated data...")
        raw_apnic = fetch_apnic()
        entries = parse_apnic_delegated(raw_apnic, ip_version=4)
        for entry in entries:
            apnic_cidrs.extend(apnic_entry_to_cidrs(entry))
        if not apnic_cidrs:
            raise ValueError("APNIC source returned no usable IPv4 CIDRs")
        logger.info("APNIC: %d entries -> %d CIDRs", len(entries), len(apnic_cidrs))

    if not args.skip_github:
        logger.info("Fetching GitHub operator data...")
        raw_operators = fetch_all_operators()
        for name, text in raw_operators.items():
            cidrs = parse_cidr_list(text, source=f"github:{name}", ip_version=4)
            if not cidrs:
                raise ValueError(f"GitHub operator source returned no usable IPv4 CIDRs: {name}")
            operator_cidrs[name] = cidrs
            logger.info("  %s: %d CIDRs", name, len(cidrs))

        logger.info("Fetching chnroutes2 data...")
        raw_chnroutes2 = fetch_chnroutes2()
        extra_cidrs = parse_cidr_list(raw_chnroutes2, source="chnroutes2", ip_version=4)
        if not extra_cidrs:
            raise ValueError("chnroutes2 source returned no usable IPv4 CIDRs")
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

    _validate_threshold("IPv4 forward routes", len(optimized), min_routes)
    _validate_threshold("IPv4 inverse routes", len(complement), min_inverse_routes)

    optimized_v6: list[str] = []
    annotated_v6: list[tuple[str, str]] = []
    complement_v6: list[str] = []

    if enable_ipv6:
        optimized_v6, annotated_v6, complement_v6 = _build_ipv6_routes(
            args=args,
            raw_apnic=raw_apnic,
            include_cache=include_cache,
            min_ipv6_routes=min_ipv6_routes,
            min_ipv6_inverse_routes=min_ipv6_inverse_routes,
        )

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    annotated_path = os.path.join(output_dir, "cn_routes_annotated.txt")
    optimized_path = os.path.join(output_dir, "cn_routes.txt")
    complement_path = os.path.join(output_dir, "cn_routes_inverse.txt")

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    write_annotated(annotated_path, annotated, timestamp, ip_version=4)
    write_optimized(optimized_path, optimized, timestamp, ip_version=4)
    write_complement(complement_path, complement, timestamp, ip_version=4)

    logger.info("Done. Output written to %s/", output_dir)
    logger.info("  %s (%d routes)", annotated_path, len(annotated))
    logger.info("  %s (%d routes)", optimized_path, len(optimized))
    logger.info("  %s (%d routes)", complement_path, len(complement))

    stats: dict[str, object] = {
        "timestamp_utc": timestamp,
        "ipv4": {
            "forward": len(optimized),
            "annotated": len(annotated),
            "inverse": len(complement),
            "addresses": int(final_routes.size),
        },
    }

    if enable_ipv6:
        annotated_v6_path = os.path.join(output_dir, "cn_routes6_annotated.txt")
        optimized_v6_path = os.path.join(output_dir, "cn_routes6.txt")
        complement_v6_path = os.path.join(output_dir, "cn_routes6_inverse.txt")
        write_annotated(annotated_v6_path, annotated_v6, timestamp, ip_version=6)
        write_optimized(optimized_v6_path, optimized_v6, timestamp, ip_version=6)
        write_complement(complement_v6_path, complement_v6, timestamp, ip_version=6)
        logger.info("  %s (%d routes)", annotated_v6_path, len(annotated_v6))
        logger.info("  %s (%d routes)", optimized_v6_path, len(optimized_v6))
        logger.info("  %s (%d routes)", complement_v6_path, len(complement_v6))
        stats["ipv6"] = {
            "forward": len(optimized_v6),
            "annotated": len(annotated_v6),
            "inverse": len(complement_v6),
        }

    if stats_json:
        stats_parent = os.path.dirname(os.path.abspath(stats_json))
        os.makedirs(stats_parent, exist_ok=True)
        write_stats(stats_json, stats)
        logger.info("  %s (stats)", stats_json)


def _build_ipv6_routes(
    args: argparse.Namespace,
    raw_apnic: Optional[str],
    include_cache: dict[str, str],
    min_ipv6_routes: int,
    min_ipv6_inverse_routes: int,
) -> tuple[list[str], list[tuple[str, str]], list[str]]:
    apnic_cidrs_v6: list[str] = []
    operator_cidrs_v6: dict[str, list[str]] = {}
    extra_cidrs_v6: list[str] = []

    allowlist_cidrs_v6 = _load_cidr_sources(
        args.allowlist_dir, ip_version=6, include_cache=include_cache
    )
    denylist_cidrs_v6 = _load_cidr_sources(
        args.denylist_dir, ip_version=6, include_cache=include_cache
    )
    logger.info("IPv6 Allowlists: %d CIDRs", len(allowlist_cidrs_v6))
    logger.info("IPv6 Denylists: %d CIDRs", len(denylist_cidrs_v6))

    if not args.skip_apnic and raw_apnic is not None:
        entries_v6 = parse_apnic_delegated(raw_apnic, ip_version=6)
        for entry in entries_v6:
            apnic_cidrs_v6.extend(apnic_entry_to_cidrs(entry))
        if not apnic_cidrs_v6:
            raise ValueError("APNIC source returned no usable IPv6 CIDRs")
        logger.info("APNIC IPv6: %d entries -> %d CIDRs", len(entries_v6), len(apnic_cidrs_v6))

    if not args.skip_github:
        logger.info("Fetching GitHub IPv6 operator data...")
        raw_operators_v6 = fetch_all_operators_v6()
        for name, text in raw_operators_v6.items():
            cidrs = parse_cidr_list(text, source=f"github:{name}6", ip_version=6)
            if not cidrs:
                raise ValueError(f"GitHub operator source returned no usable IPv6 CIDRs: {name}")
            operator_cidrs_v6[name] = cidrs
            logger.info("  %s6: %d CIDRs", name, len(cidrs))

        logger.info("Fetching GitHub china6 data...")
        raw_china_v6 = fetch_china_v6()
        extra_cidrs_v6 = parse_cidr_list(raw_china_v6, source="github:china6", ip_version=6)
        if not extra_cidrs_v6:
            raise ValueError("GitHub china6 source returned no usable IPv6 CIDRs")
        logger.info("  china6: %d CIDRs", len(extra_cidrs_v6))

    all_cidr_lists_v6 = [apnic_cidrs_v6, extra_cidrs_v6, allowlist_cidrs_v6]
    for cidrs in operator_cidrs_v6.values():
        all_cidr_lists_v6.append(cidrs)

    if not any(all_cidr_lists_v6):
        raise ValueError("No positive IPv6 routes loaded. Use a remote source or an allowlist.")

    logger.info("Merging and optimizing IPv6 routes...")
    positive_v6 = merge_routes(all_cidr_lists_v6)
    deny_v6 = merge_routes([denylist_cidrs_v6])
    final_v6 = filter_non_routable_v6(positive_v6 - deny_v6)
    optimized_v6 = optimize_routes(final_v6)
    logger.info("Optimized IPv6: %d routes", len(optimized_v6))

    logger.info("Generating annotated IPv6 routes...")
    annotated_v6 = annotate_routes(operator_cidrs_v6, final_v6)

    logger.info("Computing complement IPv6 routes...")
    complement_v6 = compute_complement_v6(final_v6)
    logger.info("Complement IPv6: %d routes", len(complement_v6))

    _validate_threshold("IPv6 forward routes", len(optimized_v6), min_ipv6_routes)
    _validate_threshold("IPv6 inverse routes", len(complement_v6), min_ipv6_inverse_routes)

    return optimized_v6, annotated_v6, complement_v6


def _load_cidr_sources(
    directory: str,
    ip_version: int = 4,
    include_cache: Optional[dict[str, str]] = None,
) -> list[str]:
    sources = load_cidr_directory(directory, ip_version=ip_version)
    cidrs = list(sources.cidrs)
    reviewed_scopes = (
        REVIEWED_CIDR_SOURCE_SCOPES_V6 if ip_version == 6 else REVIEWED_CIDR_SOURCE_SCOPES
    )
    for url in sources.urls:
        if include_cache is not None and url in include_cache:
            raw_body = include_cache[url]
        else:
            raw_body = fetch_cidr_source(url)
            if include_cache is not None:
                include_cache[url] = raw_body
        included_cidrs = parse_cidr_list(raw_body, source=url, ip_version=ip_version)
        if not included_cidrs:
            if ip_version == 4:
                raise ValueError(f"CIDR source contains no usable IPv4 CIDRs: {url}")
            logger.info("CIDR source contains no IPv6 CIDRs; skipping for IPv6: %s", url)
            continue
        reviewed_scope = reviewed_scopes.get(url)
        if reviewed_scope is not None and IPSet(included_cidrs) - IPSet(reviewed_scope):
            raise ValueError(f"CIDR source contains routes outside reviewed scope: {url}")
        cidrs.extend(included_cidrs)
    return cidrs


if __name__ == "__main__":
    main()
