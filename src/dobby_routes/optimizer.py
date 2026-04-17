import logging

from netaddr import AddrFormatError, IPNetwork, IPSet

logger = logging.getLogger(__name__)

OPERATOR_INFO = {
    "chinanet": "AS4134/AS4812 China Telecom",
    "unicom": "AS4837/AS9929 China Unicom",
    "cmcc": "AS9808 China Mobile",
    "cernet": "AS4538 CERNET",
}

# IANA Special-Purpose Address Registry + Multicast + Reserved
# https://www.iana.org/assignments/iana-ipv4-special-registry
NON_ROUTABLE_RANGES = [
    "0.0.0.0/8",  # RFC 791  - "This" network
    "10.0.0.0/8",  # RFC 1918 - Private use
    "100.64.0.0/10",  # RFC 6598 - CGNAT shared address space
    "127.0.0.0/8",  # RFC 1122 - Loopback
    "169.254.0.0/16",  # RFC 3927 - Link-local
    "172.16.0.0/12",  # RFC 1918 - Private use
    "192.0.0.0/24",  # RFC 6890 - IETF protocol assignments
    "192.0.2.0/24",  # RFC 5737 - TEST-NET-1 (documentation)
    "192.31.196.0/24",  # RFC 7535 - AS112-v4
    "192.52.193.0/24",  # RFC 7450 - AMT
    "192.88.99.0/24",  # RFC 7526 - Deprecated 6to4 relay anycast
    "192.168.0.0/16",  # RFC 1918 - Private use
    "192.175.48.0/24",  # RFC 7534 - Direct Delegation AS112 Service
    "198.18.0.0/15",  # RFC 2544 - Benchmarking
    "198.51.100.0/24",  # RFC 5737 - TEST-NET-2 (documentation)
    "203.0.113.0/24",  # RFC 5737 - TEST-NET-3 (documentation)
    "224.0.0.0/4",  # RFC 5771 - Multicast
    "240.0.0.0/4",  # RFC 1112 - Reserved for future use
]

NON_ROUTABLE_SET = IPSet(NON_ROUTABLE_RANGES)
ROUTABLE_UNIVERSE = IPSet([IPNetwork("0.0.0.0/0")]) - NON_ROUTABLE_SET


def merge_routes(cidr_lists: list[list[str]]) -> IPSet:
    result = IPSet()
    for cidr_list in cidr_lists:
        for cidr in cidr_list:
            try:
                result.add(IPNetwork(cidr))
            except (ValueError, TypeError, AddrFormatError) as e:
                logger.warning("Skipping invalid CIDR %r: %s", cidr, e)
    return result


def filter_non_routable(ipset: IPSet) -> IPSet:
    removed = ipset & NON_ROUTABLE_SET
    if removed:
        count = sum(1 for _ in removed.iter_cidrs())
        logger.info("Filtered %d non-routable CIDR(s) from routes", count)
    return ipset - NON_ROUTABLE_SET


def optimize_routes(ipset: IPSet) -> list[str]:
    return [str(net) for net in sorted(ipset.iter_cidrs())]


def compute_complement(ipset: IPSet) -> list[str]:
    complement = ROUTABLE_UNIVERSE - ipset
    return [str(net) for net in sorted(complement.iter_cidrs())]


def annotate_routes(
    operator_cidrs: dict[str, list[str]], all_merged: IPSet
) -> list[tuple[str, str]]:
    operator_combined = IPSet()
    labeled: list[tuple[IPNetwork, str]] = []
    for op, cidrs in operator_cidrs.items():
        label = OPERATOR_INFO.get(op, op)
        op_set = IPSet(cidrs)
        operator_combined |= op_set
        for net in op_set.iter_cidrs():
            labeled.append((net, label))

    remainder = all_merged - operator_combined
    for net in remainder.iter_cidrs():
        labeled.append((net, "CN"))

    labeled.sort(key=lambda t: t[0])
    return [(str(net), label) for net, label in labeled]
