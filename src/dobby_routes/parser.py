import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

VALID_APNIC_STATUSES = frozenset({"allocated", "assigned"})


@dataclass
class ApnicEntry:
    start_ip: str
    count: int
    date: str
    status: str
    ip_version: int = 4


@dataclass
class CidrSources:
    cidrs: list[str]
    urls: list[str]


def _validate_ip_version(ip_version: int) -> None:
    if ip_version not in (4, 6):
        raise ValueError(f"Unsupported IP version: {ip_version}")


def parse_apnic_delegated(text: str, ip_version: int = 4) -> list[ApnicEntry]:
    _validate_ip_version(ip_version)
    prefix = f"apnic|CN|ipv{ip_version}|"
    entries: list[ApnicEntry] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith(prefix):
            continue

        parts = line.split("|")
        if len(parts) < 7:
            logger.warning("Skipping malformed APNIC line: %s", raw_line)
            continue

        status = parts[6]
        if status not in VALID_APNIC_STATUSES:
            logger.warning("Skipping APNIC line with status %r: %s", status, raw_line)
            continue

        try:
            entries.append(
                ApnicEntry(
                    start_ip=parts[3],
                    count=int(parts[4]),
                    date=parts[5],
                    status=status,
                    ip_version=ip_version,
                )
            )
        except ValueError:
            logger.warning("Skipping APNIC line with invalid count: %s", raw_line)

    return entries


_MAX_IPV4 = int(ipaddress.IPv4Address("255.255.255.255"))


def apnic_entry_to_cidrs(entry: ApnicEntry) -> list[str]:
    if entry.ip_version == 6:
        if entry.count <= 0 or entry.count > 128:
            logger.warning(
                "Skipping APNIC IPv6 entry with invalid prefix length %d: %s",
                entry.count,
                entry.start_ip,
            )
            return []
        try:
            start_v6 = ipaddress.IPv6Address(entry.start_ip)
            network_v6 = ipaddress.IPv6Network(f"{start_v6}/{entry.count}", strict=False)
        except ValueError:
            logger.warning("Skipping APNIC IPv6 entry with invalid IP: %s", entry.start_ip)
            return []
        return [str(network_v6)]

    if entry.ip_version != 4:
        logger.warning("Skipping APNIC entry with unsupported IP version: %s", entry.ip_version)
        return []

    if entry.count <= 0:
        logger.warning(
            "Skipping APNIC entry with invalid count %d: %s",
            entry.count,
            entry.start_ip,
        )
        return []
    try:
        start = ipaddress.IPv4Address(entry.start_ip)
    except ValueError:
        logger.warning("Skipping APNIC entry with invalid IP: %s", entry.start_ip)
        return []
    end_int = int(start) + entry.count - 1
    if end_int > _MAX_IPV4:
        logger.warning(
            "APNIC range overflows IPv4 space: %s+%d, clamping",
            entry.start_ip,
            entry.count,
        )
        end_int = _MAX_IPV4
    end = ipaddress.IPv4Address(end_int)
    return [str(network) for network in ipaddress.summarize_address_range(start, end)]


def parse_cidr_list(text: str, source: Optional[str] = None, ip_version: int = 4) -> list[str]:
    _validate_ip_version(ip_version)
    cidrs: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        cidr = _parse_cidr(line, raw_line, source, ip_version)
        if cidr is not None:
            cidrs.append(cidr)

    return cidrs


def parse_local_cidr_list(
    text: str, source: Optional[str] = None, ip_version: int = 4
) -> CidrSources:
    _validate_ip_version(ip_version)
    cidrs: list[str] = []
    urls: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("@"):
            parts = line.split()
            if len(parts) != 2 or parts[0] != "@include":
                raise ValueError(f"Invalid directive in {_source_name(source)}: {raw_line}")
            urls.append(parts[1])
            continue
        cidr = _parse_cidr(line, raw_line, source, ip_version)
        if cidr is not None:
            cidrs.append(cidr)
    return CidrSources(cidrs=cidrs, urls=urls)


def load_cidr_directory(directory: str, ip_version: int = 4) -> CidrSources:
    _validate_ip_version(ip_version)
    directory_path = Path(directory)
    if not directory_path.exists():
        logger.info("CIDR directory does not exist; skipping: %s", directory)
        return CidrSources(cidrs=[], urls=[])
    if not directory_path.is_dir():
        raise ValueError(f"CIDR path is not a directory: {directory}")

    cidrs: list[str] = []
    urls: list[str] = []
    seen_urls: set[str] = set()
    for path in sorted(directory_path.iterdir(), key=lambda item: item.name):
        if path.is_file():
            sources = parse_local_cidr_list(
                path.read_text(encoding="utf-8"),
                source=path.name,
                ip_version=ip_version,
            )
            cidrs.extend(sources.cidrs)
            for url in sources.urls:
                if url not in seen_urls:
                    seen_urls.add(url)
                    urls.append(url)
    return CidrSources(cidrs=cidrs, urls=urls)


def _parse_cidr(
    line: str, raw_line: str, source: Optional[str], ip_version: int = 4
) -> Optional[str]:
    try:
        network = ipaddress.ip_network(line, strict=False)
    except ValueError:
        logger.warning("Skipping invalid CIDR line in %s: %s", _source_name(source), raw_line)
        return None
    if network.version != ip_version:
        if ip_version == 4:
            logger.warning("Skipping IPv6 CIDR in %s: %s", _source_name(source), raw_line)
        else:
            logger.debug("Skipping IPv4 CIDR in %s: %s", _source_name(source), raw_line)
        return None
    return str(network)


def _source_name(source: Optional[str]) -> str:
    return source if source is not None else "CIDR list"
