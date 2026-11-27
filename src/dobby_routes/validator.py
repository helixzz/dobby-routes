import logging
from typing import Mapping, Sequence

from netaddr import IPAddress, IPSet

logger = logging.getLogger(__name__)

DEFAULT_CANARIES_V4_CN: tuple[tuple[str, str], ...] = (
    ("114.114.114.114", "114DNS"),
    ("223.5.5.5", "AliDNS"),
    ("119.29.29.29", "DNSPod"),
    ("180.76.76.76", "Baidu DNS"),
)

DEFAULT_CANARIES_V4_FOREIGN: tuple[tuple[str, str], ...] = (
    ("1.1.1.1", "Cloudflare DNS"),
    ("8.8.8.8", "Google DNS"),
    ("9.9.9.9", "Quad9 DNS"),
    ("104.18.32.47", "Cloudflare / OpenAI"),
    ("149.154.167.50", "Telegram"),
    ("47.242.0.1", "Alibaba Cloud HK"),
    ("43.132.0.1", "Tencent Cloud HK"),
)

DEFAULT_CANARIES_V6_CN: tuple[tuple[str, str], ...] = (
    ("2400:3200::1", "AliDNS IPv6"),
    ("2402:4e00::", "DNSPod IPv6"),
    ("2001:da8::1", "CERNET2"),
)

DEFAULT_CANARIES_V6_FOREIGN: tuple[tuple[str, str], ...] = (
    ("2606:4700:4700::1111", "Cloudflare DNS IPv6"),
    ("2001:4860:4860::8888", "Google DNS IPv6"),
    ("2a0a:f280::1", "Telegram IPv6"),
)

_DRIFT_SECTIONS = ("ipv4", "ipv6", "ipv4_bgp", "ipv6_bgp")
_DRIFT_METRICS = ("forward", "inverse", "addresses")


def validate_canaries(
    forward_set: IPSet,
    inverse_set: IPSet,
    cn_canaries: Sequence[tuple[str, str]],
    foreign_canaries: Sequence[tuple[str, str]],
    table_name: str = "IPv4",
) -> None:
    failures: list[str] = []

    for ip_str, desc in cn_canaries:
        addr = IPAddress(ip_str)
        if addr not in forward_set:
            failures.append(f"{table_name} CN canary missing from forward: {ip_str} ({desc})")
        if addr in inverse_set:
            failures.append(f"{table_name} CN canary leaked into inverse: {ip_str} ({desc})")

    for ip_str, desc in foreign_canaries:
        addr = IPAddress(ip_str)
        if addr in forward_set:
            failures.append(f"{table_name} foreign canary leaked into forward: {ip_str} ({desc})")
        if addr not in inverse_set:
            failures.append(f"{table_name} foreign canary missing from inverse: {ip_str} ({desc})")

    if failures:
        raise ValueError("Canary validation failed: " + "; ".join(failures))
    logger.info(
        "Canary validation passed for %s (%d CN, %d foreign)",
        table_name,
        len(cn_canaries),
        len(foreign_canaries),
    )


def validate_drift(
    current_stats: Mapping[str, object],
    baseline_stats: Mapping[str, object],
    max_drift_pct: float,
) -> None:
    if max_drift_pct < 0:
        raise ValueError(f"--max-drift-pct must be non-negative: {max_drift_pct}")
    if max_drift_pct == 0:
        return

    violations: list[str] = []
    for section in _DRIFT_SECTIONS:
        curr_sec = current_stats.get(section)
        base_sec = baseline_stats.get(section)
        if not isinstance(curr_sec, Mapping) or not isinstance(base_sec, Mapping):
            continue
        for metric in _DRIFT_METRICS:
            curr_val = curr_sec.get(metric)
            base_val = base_sec.get(metric)
            if (
                isinstance(curr_val, int)
                and isinstance(base_val, int)
                and not isinstance(curr_val, bool)
                and not isinstance(base_val, bool)
                and base_val > 0
            ):
                drift_pct = abs(curr_val - base_val) / base_val * 100.0
                if drift_pct > max_drift_pct:
                    violations.append(
                        f"{section}.{metric} drifted {drift_pct:.2f}% "
                        f"({base_val} -> {curr_val}, limit {max_drift_pct:.2f}%)"
                    )

    if violations:
        raise ValueError("Drift guardrail failed: " + "; ".join(violations))
    logger.info("Drift guardrail passed (limit %.2f%%)", max_drift_pct)
