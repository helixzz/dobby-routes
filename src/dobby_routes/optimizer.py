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

# IANA IPv6 Special-Purpose Address Registry (non-globally-routable / special ranges)
# https://www.iana.org/assignments/iana-ipv6-special-registry
NON_ROUTABLE_RANGES_V6 = [
    "::/128",  # RFC 4291 - Unspecified address
    "::1/128",  # RFC 4291 - Loopback address
    "::ffff:0:0/96",  # RFC 4291 - IPv4-mapped address
    "::ffff:0:0:0/96",  # RFC 8215 - IPv4-translated address
    "64:ff9b::/96",  # RFC 6052 - IPv4-IPv6 translation
    "64:ff9b:1::/48",  # RFC 8215 - Local-use IPv4-IPv6 translation
    "100::/64",  # RFC 6666 - Discard-only address block
    "2001::/32",  # RFC 4380 - Teredo tunneling
    "2001:2::/48",  # RFC 5180 - Benchmarking
    "2001:10::/28",  # RFC 4843 - Deprecated ORCHID
    "2001:db8::/32",  # RFC 3849 - Documentation
    "2002::/16",  # RFC 3056/7526 - 6to4
    "3fff::/20",  # RFC 9637 - Documentation
    "5f00::/16",  # RFC 9602 - Segment Routing SIDs
    "fc00::/7",  # RFC 4193 - Unique-local
    "fe80::/10",  # RFC 4291 - Link-local unicast
    "ff00::/8",  # RFC 4291 - Multicast
]

NON_ROUTABLE_SET_V6 = IPSet(NON_ROUTABLE_RANGES_V6)
ROUTABLE_UNIVERSE_V6 = IPSet([IPNetwork("2000::/3")]) - NON_ROUTABLE_SET_V6


def merge_routes(cidr_lists: list[list[str]]) -> IPSet:
    networks: list[IPNetwork] = []
    for cidr_list in cidr_lists:
        for cidr in cidr_list:
            try:
                networks.append(IPNetwork(cidr))
            except (ValueError, TypeError, AddrFormatError) as e:
                logger.warning("Skipping invalid CIDR %r: %s", cidr, e)
    return IPSet(networks)


def filter_non_routable(ipset: IPSet) -> IPSet:
    removed = ipset & NON_ROUTABLE_SET
    if removed:
        count = sum(1 for _ in removed.iter_cidrs())
        logger.info("Filtered %d non-routable CIDR(s) from routes", count)
    return ipset - NON_ROUTABLE_SET


def filter_non_routable_v6(ipset: IPSet) -> IPSet:
    filtered = ipset & ROUTABLE_UNIVERSE_V6
    removed = ipset - filtered
    if removed:
        count = sum(1 for _ in removed.iter_cidrs())
        logger.info("Filtered %d non-routable IPv6 CIDR(s) from routes", count)
    return filtered


def optimize_routes(ipset: IPSet) -> list[str]:
    return [str(net) for net in sorted(ipset.iter_cidrs())]


def compute_complement(ipset: IPSet) -> list[str]:
    complement = ROUTABLE_UNIVERSE - ipset
    return [str(net) for net in sorted(complement.iter_cidrs())]


def compute_complement_v6(ipset: IPSet) -> list[str]:
    complement = ROUTABLE_UNIVERSE_V6 - ipset
    return [str(net) for net in sorted(complement.iter_cidrs())]


def annotate_routes(
    operator_cidrs: dict[str, list[str]], all_merged: IPSet
) -> list[tuple[str, str]]:
    if not all_merged:
        return []

    # Partition all_merged into disjoint subsets keyed by the tuple of matching operators
    partitions: dict[tuple[str, ...], IPSet] = {(): all_merged}
    for op, cidrs in sorted(operator_cidrs.items()):
        if not cidrs:
            continue
        label = OPERATOR_INFO.get(op, op)
        op_set = merge_routes([cidrs]) & all_merged
        if not op_set:
            continue
        next_partitions: dict[tuple[str, ...], IPSet] = {}
        for labels, ipset in partitions.items():
            overlap = ipset & op_set
            diff = ipset - op_set
            if diff:
                existing = next_partitions.get(labels)
                next_partitions[labels] = existing | diff if existing else diff
            if overlap:
                combined_labels = labels + (label,)
                existing = next_partitions.get(combined_labels)
                next_partitions[combined_labels] = existing | overlap if existing else overlap
        partitions = next_partitions

    labeled: list[tuple[IPNetwork, str]] = []
    for labels, ipset in partitions.items():
        annotation = ", ".join(labels) if labels else "CN"
        for net in ipset.iter_cidrs():
            labeled.append((net, annotation))

    labeled.sort(key=lambda t: t[0])
    return [(str(net), label) for net, label in labeled]
