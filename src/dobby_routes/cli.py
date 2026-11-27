import argparse
import json
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
    fetch_aws_ip_ranges,
    fetch_bgp_asns,
    fetch_bgp_table,
    fetch_china_v6,
    fetch_chnroutes2,
    fetch_cidr_source,
    fetch_cloudflare_v4,
    fetch_cloudflare_v6,
    fetch_google_ip_ranges,
)
from .optimizer import (
    ROUTABLE_UNIVERSE,
    ROUTABLE_UNIVERSE_V6,
    annotate_routes,
    compute_complement,
    compute_complement_v6,
    enrich_annotations_with_bgp,
    filter_non_routable,
    filter_non_routable_v6,
    merge_routes,
    minimize_routed_cidrs,
    optimize_routes,
)
from .output import (
    SUPPORTED_FORMATS,
    write_annotated,
    write_bgp_routes,
    write_bird_prefix_set,
    write_complement,
    write_nftables_set,
    write_optimized,
    write_routeros_address_list,
    write_singbox_ruleset,
    write_stats,
)
from .parser import (
    apnic_entry_to_cidrs,
    load_cidr_directory,
    parse_apnic_delegated,
    parse_aws_ip_ranges,
    parse_bgp_asns,
    parse_bgp_table,
    parse_cidr_list,
    parse_google_ip_ranges,
)
from .validator import (
    DEFAULT_CANARIES_V4_CN,
    DEFAULT_CANARIES_V4_FOREIGN,
    DEFAULT_CANARIES_V6_CN,
    DEFAULT_CANARIES_V6_FOREIGN,
    validate_canaries,
    validate_drift,
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
        "--aws-cn",
        action="store_true",
        help="include official AWS China (cn-*) IP ranges",
    )
    parser.add_argument(
        "--protect-overseas",
        action="store_true",
        help="defensively exclude official Cloudflare and Google overseas IP ranges",
    )
    parser.add_argument(
        "--bgp",
        action="store_true",
        help="use bgp.tools global BGP table for ASN enrichment and lossless BGP-minimized tables",
    )
    parser.add_argument(
        "--verify-canaries",
        action="store_true",
        help="validate generated tables against built-in CN and overseas canary IPs",
    )
    parser.add_argument(
        "--baseline-stats",
        default=None,
        help="optional path to previous stats JSON for drift guardrail",
    )
    parser.add_argument(
        "--max-drift-pct",
        type=float,
        default=0.0,
        help="maximum allowed relative drift percentage vs --baseline-stats (0 disables)",
    )
    parser.add_argument(
        "--formats",
        default="",
        help=(
            "comma-separated extra export formats under <output-dir>/formats/ "
            f"({','.join(SUPPORTED_FORMATS)})"
        ),
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


def _parse_formats(raw_formats: str) -> list[str]:
    if not raw_formats.strip():
        return []
    formats: list[str] = []
    for item in raw_formats.split(","):
        fmt = item.strip().lower()
        if not fmt:
            continue
        if fmt not in SUPPORTED_FORMATS:
            raise ValueError(
                f"Unsupported format {fmt!r}; expected one of: {', '.join(SUPPORTED_FORMATS)}"
            )
        if fmt not in formats:
            formats.append(fmt)
    return formats


def _run(args: argparse.Namespace) -> None:
    enable_ipv6 = bool(getattr(args, "ipv6", False))
    enable_aws_cn = bool(getattr(args, "aws_cn", False))
    protect_overseas = bool(getattr(args, "protect_overseas", False))
    enable_bgp = bool(getattr(args, "bgp", False))
    verify_canaries = bool(getattr(args, "verify_canaries", False))
    baseline_stats_path: Optional[str] = getattr(args, "baseline_stats", None)
    max_drift_pct = float(getattr(args, "max_drift_pct", 0.0))
    formats = _parse_formats(str(getattr(args, "formats", "") or ""))
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
    if max_drift_pct < 0:
        raise ValueError(f"--max-drift-pct must be non-negative: {max_drift_pct}")

    include_cache: dict[str, str] = {}

    apnic_cidrs: list[str] = []
    operator_cidrs: dict[str, list[str]] = {}
    extra_cidrs: list[str] = []
    aws_cidrs_v4: list[str] = []
    overseas_deny_v4: list[str] = []
    raw_aws: Optional[str] = None
    raw_google: Optional[str] = None

    allowlist_cidrs = _load_cidr_sources(
        args.allowlist_dir, ip_version=4, include_cache=include_cache
    )
    denylist_cidrs = _load_cidr_sources(
        args.denylist_dir, ip_version=4, include_cache=include_cache
    )
    logger.info("Allowlists: %d CIDRs", len(allowlist_cidrs))
    logger.info("Denylists: %d CIDRs", len(denylist_cidrs))

    if enable_aws_cn:
        logger.info("Fetching AWS China IP ranges...")
        raw_aws = fetch_aws_ip_ranges()
        aws_cidrs_v4 = parse_aws_ip_ranges(raw_aws, ip_version=4)
        if not aws_cidrs_v4:
            raise ValueError("AWS China source returned no usable IPv4 CIDRs")
        logger.info("  aws-cn IPv4: %d CIDRs", len(aws_cidrs_v4))

    if protect_overseas:
        logger.info("Fetching overseas protection ranges (Cloudflare, Google)...")
        cf_v4 = parse_cidr_list(fetch_cloudflare_v4(), source="cloudflare:v4", ip_version=4)
        if not cf_v4:
            raise ValueError("Cloudflare IPv4 source returned no usable CIDRs")
        raw_google = fetch_google_ip_ranges()
        google_v4 = parse_google_ip_ranges(raw_google, ip_version=4)
        if not google_v4:
            raise ValueError("Google IPv4 source returned no usable CIDRs")
        overseas_deny_v4 = cf_v4 + google_v4
        logger.info(
            "  overseas protection IPv4: %d Cloudflare + %d Google CIDRs",
            len(cf_v4),
            len(google_v4),
        )

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

    all_cidr_lists = [apnic_cidrs, extra_cidrs, aws_cidrs_v4, allowlist_cidrs]
    for cidrs in operator_cidrs.values():
        all_cidr_lists.append(cidrs)

    if not any(all_cidr_lists):
        logger.error("No positive routes loaded. Use a remote source or an allowlist.")
        sys.exit(1)

    logger.info("Merging and optimizing routes...")
    positive_routes = merge_routes(all_cidr_lists)
    allow_routes_v4 = merge_routes([allowlist_cidrs])
    deny_routes_v4 = merge_routes([denylist_cidrs, overseas_deny_v4])
    final_routes = filter_non_routable(positive_routes - deny_routes_v4)
    logger.info(
        "Positive: %d routes, denied: %d routes, final: %d routes",
        sum(1 for _ in positive_routes.iter_cidrs()),
        sum(1 for _ in deny_routes_v4.iter_cidrs()),
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

    final_v6 = IPSet()
    allow_routes_v6 = IPSet()
    deny_routes_v6 = IPSet()
    optimized_v6: list[str] = []
    annotated_v6: list[tuple[str, str]] = []
    complement_v6: list[str] = []

    if enable_ipv6:
        (
            final_v6,
            allow_routes_v6,
            deny_routes_v6,
            optimized_v6,
            annotated_v6,
            complement_v6,
        ) = _build_ipv6_routes(
            args=args,
            raw_apnic=raw_apnic,
            raw_aws=raw_aws,
            raw_google=raw_google,
            enable_aws_cn=enable_aws_cn,
            protect_overseas=protect_overseas,
            include_cache=include_cache,
            min_ipv6_routes=min_ipv6_routes,
            min_ipv6_inverse_routes=min_ipv6_inverse_routes,
        )

    bgp_fwd_v4: list[str] = []
    bgp_inv_v4: list[str] = []
    bgp_fwd_v6: list[str] = []
    bgp_inv_v6: list[str] = []

    if enable_bgp:
        logger.info("Fetching global BGP table and ASN metadata from bgp.tools...")
        raw_bgp_table = fetch_bgp_table()
        raw_bgp_asns = fetch_bgp_asns()
        bgp_v4_entries, bgp_v6_entries = parse_bgp_table(raw_bgp_table)
        asn_names = parse_bgp_asns(raw_bgp_asns)
        if not bgp_v4_entries:
            raise ValueError("BGP table source returned no usable IPv4 prefixes")
        logger.info(
            "BGP loaded: %d IPv4 prefixes, %d IPv6 prefixes, %d ASNs",
            len(bgp_v4_entries),
            len(bgp_v6_entries),
            len(asn_names),
        )

        logger.info("Enriching IPv4 annotations with BGP origin ASNs...")
        annotated = enrich_annotations_with_bgp(annotated, bgp_v4_entries, asn_names)

        active_v4 = filter_non_routable(merge_routes([[cidr for cidr, _ in bgp_v4_entries]]))
        required_cn_v4 = filter_non_routable((final_routes & active_v4) | allow_routes_v4) - (
            deny_routes_v4
        )
        required_foreign_v4 = filter_non_routable((active_v4 - final_routes) | deny_routes_v4)
        bgp_fwd_v4 = minimize_routed_cidrs(required_cn_v4, required_foreign_v4, ROUTABLE_UNIVERSE)
        bgp_inv_v4 = minimize_routed_cidrs(required_foreign_v4, required_cn_v4, ROUTABLE_UNIVERSE)
        logger.info(
            "BGP-minimized IPv4: %d forward, %d inverse",
            len(bgp_fwd_v4),
            len(bgp_inv_v4),
        )

        if enable_ipv6:
            if not bgp_v6_entries:
                raise ValueError("BGP table source returned no usable IPv6 prefixes")
            logger.info("Enriching IPv6 annotations with BGP origin ASNs...")
            annotated_v6 = enrich_annotations_with_bgp(annotated_v6, bgp_v6_entries, asn_names)

            active_v6 = filter_non_routable_v6(merge_routes([[cidr for cidr, _ in bgp_v6_entries]]))
            required_cn_v6 = (
                filter_non_routable_v6((final_v6 & active_v6) | allow_routes_v6) - deny_routes_v6
            )
            required_foreign_v6 = filter_non_routable_v6((active_v6 - final_v6) | deny_routes_v6)
            bgp_fwd_v6 = minimize_routed_cidrs(
                required_cn_v6, required_foreign_v6, ROUTABLE_UNIVERSE_V6
            )
            bgp_inv_v6 = minimize_routed_cidrs(
                required_foreign_v6, required_cn_v6, ROUTABLE_UNIVERSE_V6
            )
            logger.info(
                "BGP-minimized IPv6: %d forward, %d inverse",
                len(bgp_fwd_v6),
                len(bgp_inv_v6),
            )

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
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
        stats["ipv6"] = {
            "forward": len(optimized_v6),
            "annotated": len(annotated_v6),
            "inverse": len(complement_v6),
        }
    if enable_bgp:
        stats["ipv4_bgp"] = {
            "forward": len(bgp_fwd_v4),
            "inverse": len(bgp_inv_v4),
        }
        if enable_ipv6:
            stats["ipv6_bgp"] = {
                "forward": len(bgp_fwd_v6),
                "inverse": len(bgp_inv_v6),
            }

    if verify_canaries:
        validate_canaries(
            final_routes,
            merge_routes([complement]),
            DEFAULT_CANARIES_V4_CN,
            DEFAULT_CANARIES_V4_FOREIGN,
            table_name="IPv4",
        )
        if enable_ipv6:
            validate_canaries(
                final_v6,
                merge_routes([complement_v6]),
                DEFAULT_CANARIES_V6_CN,
                DEFAULT_CANARIES_V6_FOREIGN,
                table_name="IPv6",
            )
        if enable_bgp:
            validate_canaries(
                merge_routes([bgp_fwd_v4]),
                merge_routes([bgp_inv_v4]),
                DEFAULT_CANARIES_V4_CN,
                DEFAULT_CANARIES_V4_FOREIGN,
                table_name="IPv4 BGP",
            )
            if enable_ipv6:
                validate_canaries(
                    merge_routes([bgp_fwd_v6]),
                    merge_routes([bgp_inv_v6]),
                    DEFAULT_CANARIES_V6_CN,
                    DEFAULT_CANARIES_V6_FOREIGN,
                    table_name="IPv6 BGP",
                )

    if baseline_stats_path and max_drift_pct > 0:
        if os.path.isfile(baseline_stats_path):
            with open(baseline_stats_path, encoding="utf-8") as f:
                baseline_stats = json.load(f)
            if not isinstance(baseline_stats, dict):
                raise ValueError(f"Invalid baseline stats JSON: {baseline_stats_path}")
            validate_drift(stats, baseline_stats, max_drift_pct)
        else:
            logger.info(
                "Baseline stats file not found; skipping drift check: %s",
                baseline_stats_path,
            )

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    annotated_path = os.path.join(output_dir, "cn_routes_annotated.txt")
    optimized_path = os.path.join(output_dir, "cn_routes.txt")
    complement_path = os.path.join(output_dir, "cn_routes_inverse.txt")

    write_annotated(annotated_path, annotated, timestamp, ip_version=4)
    write_optimized(optimized_path, optimized, timestamp, ip_version=4)
    write_complement(complement_path, complement, timestamp, ip_version=4)

    logger.info("Done. Output written to %s/", output_dir)
    logger.info("  %s (%d routes)", annotated_path, len(annotated))
    logger.info("  %s (%d routes)", optimized_path, len(optimized))
    logger.info("  %s (%d routes)", complement_path, len(complement))

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

    if enable_bgp:
        bgp_fwd_v4_path = os.path.join(output_dir, "cn_routes_bgp.txt")
        bgp_inv_v4_path = os.path.join(output_dir, "cn_routes_bgp_inverse.txt")
        write_bgp_routes(bgp_fwd_v4_path, bgp_fwd_v4, timestamp, ip_version=4, inverse=False)
        write_bgp_routes(bgp_inv_v4_path, bgp_inv_v4, timestamp, ip_version=4, inverse=True)
        logger.info("  %s (%d routes)", bgp_fwd_v4_path, len(bgp_fwd_v4))
        logger.info("  %s (%d routes)", bgp_inv_v4_path, len(bgp_inv_v4))
        if enable_ipv6:
            bgp_fwd_v6_path = os.path.join(output_dir, "cn_routes6_bgp.txt")
            bgp_inv_v6_path = os.path.join(output_dir, "cn_routes6_bgp_inverse.txt")
            write_bgp_routes(bgp_fwd_v6_path, bgp_fwd_v6, timestamp, ip_version=6, inverse=False)
            write_bgp_routes(bgp_inv_v6_path, bgp_inv_v6, timestamp, ip_version=6, inverse=True)
            logger.info("  %s (%d routes)", bgp_fwd_v6_path, len(bgp_fwd_v6))
            logger.info("  %s (%d routes)", bgp_inv_v6_path, len(bgp_inv_v6))

    if formats:
        _write_extra_formats(
            output_dir=output_dir,
            formats=formats,
            timestamp=timestamp,
            optimized_v4=optimized,
            complement_v4=complement,
            optimized_v6=optimized_v6 if enable_ipv6 else None,
            complement_v6=complement_v6 if enable_ipv6 else None,
            bgp_fwd_v4=bgp_fwd_v4 if enable_bgp else None,
            bgp_inv_v4=bgp_inv_v4 if enable_bgp else None,
            bgp_fwd_v6=bgp_fwd_v6 if (enable_bgp and enable_ipv6) else None,
            bgp_inv_v6=bgp_inv_v6 if (enable_bgp and enable_ipv6) else None,
        )

    if stats_json:
        stats_parent = os.path.dirname(os.path.abspath(stats_json))
        os.makedirs(stats_parent, exist_ok=True)
        write_stats(stats_json, stats)
        logger.info("  %s (stats)", stats_json)


def _write_extra_formats(
    output_dir: str,
    formats: list[str],
    timestamp: str,
    optimized_v4: list[str],
    complement_v4: list[str],
    optimized_v6: Optional[list[str]],
    complement_v6: Optional[list[str]],
    bgp_fwd_v4: Optional[list[str]],
    bgp_inv_v4: Optional[list[str]],
    bgp_fwd_v6: Optional[list[str]],
    bgp_inv_v6: Optional[list[str]],
) -> None:
    formats_root = os.path.join(output_dir, "formats")

    if "bird" in formats:
        bird_dir = os.path.join(formats_root, "bird")
        os.makedirs(bird_dir, exist_ok=True)
        write_bird_prefix_set(
            os.path.join(bird_dir, "cn_routes_v4.conf"), "CN_ROUTES_V4", optimized_v4, timestamp
        )
        write_bird_prefix_set(
            os.path.join(bird_dir, "cn_routes_inverse_v4.conf"),
            "CN_ROUTES_INVERSE_V4",
            complement_v4,
            timestamp,
        )
        if optimized_v6 is not None and complement_v6 is not None:
            write_bird_prefix_set(
                os.path.join(bird_dir, "cn_routes_v6.conf"), "CN_ROUTES_V6", optimized_v6, timestamp
            )
            write_bird_prefix_set(
                os.path.join(bird_dir, "cn_routes_inverse_v6.conf"),
                "CN_ROUTES_INVERSE_V6",
                complement_v6,
                timestamp,
            )
        if bgp_fwd_v4 is not None and bgp_inv_v4 is not None:
            write_bird_prefix_set(
                os.path.join(bird_dir, "cn_routes_bgp_v4.conf"),
                "CN_ROUTES_BGP_V4",
                bgp_fwd_v4,
                timestamp,
            )
            write_bird_prefix_set(
                os.path.join(bird_dir, "cn_routes_bgp_inverse_v4.conf"),
                "CN_ROUTES_BGP_INVERSE_V4",
                bgp_inv_v4,
                timestamp,
            )
        if bgp_fwd_v6 is not None and bgp_inv_v6 is not None:
            write_bird_prefix_set(
                os.path.join(bird_dir, "cn_routes_bgp_v6.conf"),
                "CN_ROUTES_BGP_V6",
                bgp_fwd_v6,
                timestamp,
            )
            write_bird_prefix_set(
                os.path.join(bird_dir, "cn_routes_bgp_inverse_v6.conf"),
                "CN_ROUTES_BGP_INVERSE_V6",
                bgp_inv_v6,
                timestamp,
            )

    if "routeros" in formats:
        ros_dir = os.path.join(formats_root, "routeros")
        os.makedirs(ros_dir, exist_ok=True)
        write_routeros_address_list(
            os.path.join(ros_dir, "cn_routes_v4.rsc"),
            "cn_routes",
            optimized_v4,
            timestamp,
            ip_version=4,
        )
        write_routeros_address_list(
            os.path.join(ros_dir, "cn_routes_inverse_v4.rsc"),
            "cn_routes_inverse",
            complement_v4,
            timestamp,
            ip_version=4,
        )
        if optimized_v6 is not None and complement_v6 is not None:
            write_routeros_address_list(
                os.path.join(ros_dir, "cn_routes_v6.rsc"),
                "cn_routes6",
                optimized_v6,
                timestamp,
                ip_version=6,
            )
            write_routeros_address_list(
                os.path.join(ros_dir, "cn_routes_inverse_v6.rsc"),
                "cn_routes6_inverse",
                complement_v6,
                timestamp,
                ip_version=6,
            )
        if bgp_fwd_v4 is not None and bgp_inv_v4 is not None:
            write_routeros_address_list(
                os.path.join(ros_dir, "cn_routes_bgp_v4.rsc"),
                "cn_routes_bgp",
                bgp_fwd_v4,
                timestamp,
                ip_version=4,
            )
            write_routeros_address_list(
                os.path.join(ros_dir, "cn_routes_bgp_inverse_v4.rsc"),
                "cn_routes_bgp_inverse",
                bgp_inv_v4,
                timestamp,
                ip_version=4,
            )
        if bgp_fwd_v6 is not None and bgp_inv_v6 is not None:
            write_routeros_address_list(
                os.path.join(ros_dir, "cn_routes_bgp_v6.rsc"),
                "cn_routes6_bgp",
                bgp_fwd_v6,
                timestamp,
                ip_version=6,
            )
            write_routeros_address_list(
                os.path.join(ros_dir, "cn_routes_bgp_inverse_v6.rsc"),
                "cn_routes6_bgp_inverse",
                bgp_inv_v6,
                timestamp,
                ip_version=6,
            )

    if "nftables" in formats:
        nft_dir = os.path.join(formats_root, "nftables")
        os.makedirs(nft_dir, exist_ok=True)
        write_nftables_set(
            os.path.join(nft_dir, "cn_routes_v4.nft"), "cn_routes_v4", optimized_v4, timestamp
        )
        write_nftables_set(
            os.path.join(nft_dir, "cn_routes_inverse_v4.nft"),
            "cn_routes_inverse_v4",
            complement_v4,
            timestamp,
        )
        if optimized_v6 is not None and complement_v6 is not None:
            write_nftables_set(
                os.path.join(nft_dir, "cn_routes_v6.nft"), "cn_routes_v6", optimized_v6, timestamp
            )
            write_nftables_set(
                os.path.join(nft_dir, "cn_routes_inverse_v6.nft"),
                "cn_routes_inverse_v6",
                complement_v6,
                timestamp,
            )
        if bgp_fwd_v4 is not None and bgp_inv_v4 is not None:
            write_nftables_set(
                os.path.join(nft_dir, "cn_routes_bgp_v4.nft"),
                "cn_routes_bgp_v4",
                bgp_fwd_v4,
                timestamp,
            )
            write_nftables_set(
                os.path.join(nft_dir, "cn_routes_bgp_inverse_v4.nft"),
                "cn_routes_bgp_inverse_v4",
                bgp_inv_v4,
                timestamp,
            )
        if bgp_fwd_v6 is not None and bgp_inv_v6 is not None:
            write_nftables_set(
                os.path.join(nft_dir, "cn_routes_bgp_v6.nft"),
                "cn_routes_bgp_v6",
                bgp_fwd_v6,
                timestamp,
            )
            write_nftables_set(
                os.path.join(nft_dir, "cn_routes_bgp_inverse_v6.nft"),
                "cn_routes_bgp_inverse_v6",
                bgp_inv_v6,
                timestamp,
            )

    if "singbox" in formats:
        sb_dir = os.path.join(formats_root, "singbox")
        os.makedirs(sb_dir, exist_ok=True)
        write_singbox_ruleset(
            os.path.join(sb_dir, "cn_routes.json"),
            optimized_v4 + (optimized_v6 or []),
        )
        write_singbox_ruleset(
            os.path.join(sb_dir, "cn_routes_inverse.json"),
            complement_v4 + (complement_v6 or []),
        )
        if bgp_fwd_v4 is not None and bgp_inv_v4 is not None:
            write_singbox_ruleset(
                os.path.join(sb_dir, "cn_routes_bgp.json"),
                bgp_fwd_v4 + (bgp_fwd_v6 or []),
            )
            write_singbox_ruleset(
                os.path.join(sb_dir, "cn_routes_bgp_inverse.json"),
                bgp_inv_v4 + (bgp_inv_v6 or []),
            )


def _build_ipv6_routes(
    args: argparse.Namespace,
    raw_apnic: Optional[str],
    raw_aws: Optional[str],
    raw_google: Optional[str],
    enable_aws_cn: bool,
    protect_overseas: bool,
    include_cache: dict[str, str],
    min_ipv6_routes: int,
    min_ipv6_inverse_routes: int,
) -> tuple[IPSet, IPSet, IPSet, list[str], list[tuple[str, str]], list[str]]:
    apnic_cidrs_v6: list[str] = []
    operator_cidrs_v6: dict[str, list[str]] = {}
    extra_cidrs_v6: list[str] = []
    aws_cidrs_v6: list[str] = []
    overseas_deny_v6: list[str] = []

    allowlist_cidrs_v6 = _load_cidr_sources(
        args.allowlist_dir, ip_version=6, include_cache=include_cache
    )
    denylist_cidrs_v6 = _load_cidr_sources(
        args.denylist_dir, ip_version=6, include_cache=include_cache
    )
    logger.info("IPv6 Allowlists: %d CIDRs", len(allowlist_cidrs_v6))
    logger.info("IPv6 Denylists: %d CIDRs", len(denylist_cidrs_v6))

    if enable_aws_cn and raw_aws is not None:
        aws_cidrs_v6 = parse_aws_ip_ranges(raw_aws, ip_version=6)
        if not aws_cidrs_v6:
            raise ValueError("AWS China source returned no usable IPv6 CIDRs")
        logger.info("  aws-cn IPv6: %d CIDRs", len(aws_cidrs_v6))

    if protect_overseas:
        cf_v6 = parse_cidr_list(fetch_cloudflare_v6(), source="cloudflare:v6", ip_version=6)
        if not cf_v6:
            raise ValueError("Cloudflare IPv6 source returned no usable CIDRs")
        google_v6 = (
            parse_google_ip_ranges(raw_google, ip_version=6) if raw_google is not None else []
        )
        if not google_v6:
            raise ValueError("Google IPv6 source returned no usable CIDRs")
        overseas_deny_v6 = cf_v6 + google_v6
        logger.info(
            "  overseas protection IPv6: %d Cloudflare + %d Google CIDRs",
            len(cf_v6),
            len(google_v6),
        )

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

    all_cidr_lists_v6 = [apnic_cidrs_v6, extra_cidrs_v6, aws_cidrs_v6, allowlist_cidrs_v6]
    for cidrs in operator_cidrs_v6.values():
        all_cidr_lists_v6.append(cidrs)

    if not any(all_cidr_lists_v6):
        raise ValueError("No positive IPv6 routes loaded. Use a remote source or an allowlist.")

    logger.info("Merging and optimizing IPv6 routes...")
    positive_v6 = merge_routes(all_cidr_lists_v6)
    allow_v6 = merge_routes([allowlist_cidrs_v6])
    deny_v6 = merge_routes([denylist_cidrs_v6, overseas_deny_v6])
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

    return final_v6, allow_v6, deny_v6, optimized_v6, annotated_v6, complement_v6


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
