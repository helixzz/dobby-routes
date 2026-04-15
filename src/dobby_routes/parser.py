import ipaddress
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ApnicEntry:
    start_ip: str
    count: int
    date: str
    status: str


def parse_apnic_delegated(text: str) -> list[ApnicEntry]:
    entries: list[ApnicEntry] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("apnic|CN|ipv4|"):
            continue

        parts = line.split("|")
        if len(parts) < 7:
            logger.warning("Skipping malformed APNIC line: %s", raw_line)
            continue

        try:
            entries.append(
                ApnicEntry(
                    start_ip=parts[3],
                    count=int(parts[4]),
                    date=parts[5],
                    status=parts[6],
                )
            )
        except ValueError:
            logger.warning("Skipping APNIC line with invalid count: %s", raw_line)

    return entries


_MAX_IPV4 = int(ipaddress.IPv4Address("255.255.255.255"))


def apnic_entry_to_cidrs(entry: ApnicEntry) -> list[str]:
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


def parse_cidr_list(text: str) -> list[str]:
    cidrs: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            network = ipaddress.IPv4Network(line, strict=False)
        except ValueError:
            logger.warning("Skipping invalid CIDR line: %s", raw_line)
            continue
        cidrs.append(str(network))

    return cidrs
