import logging
from netaddr import IPSet, IPNetwork, cidr_merge

logger = logging.getLogger(__name__)

OPERATOR_INFO = {
    "chinanet": "AS4134/AS4812 China Telecom",
    "unicom": "AS4837/AS9929 China Unicom",
    "cmcc": "AS9808 China Mobile",
    "cernet": "AS4538 CERNET",
}


def merge_routes(cidr_lists: list[list[str]]) -> IPSet:
    result = IPSet()
    for cidr_list in cidr_lists:
        for cidr in cidr_list:
            try:
                result.add(IPNetwork(cidr))
            except Exception as e:
                logger.warning("Skipping invalid CIDR %r: %s", cidr, e)
    return result


def optimize_routes(ipset: IPSet) -> list[str]:
    return sorted(str(net) for net in ipset.iter_cidrs())


def compute_complement(ipset: IPSet) -> list[str]:
    complement = IPSet([IPNetwork("0.0.0.0/0")]) - ipset
    return sorted(str(net) for net in complement.iter_cidrs())


def annotate_routes(
    operator_cidrs: dict[str, list[str]], all_merged: IPSet
) -> list[tuple[str, str]]:
    # Build annotated list: operator CIDRs keep their granularity and labels,
    # remaining (APNIC-only) routes are labeled "CN".
    operator_combined = IPSet()
    labeled: list[tuple[str, str]] = []
    for op, cidrs in operator_cidrs.items():
        label = OPERATOR_INFO.get(op, op)
        op_set = IPSet(cidrs)
        operator_combined |= op_set
        for net in op_set.iter_cidrs():
            labeled.append((str(net), label))

    # Routes in the merged set but not covered by any operator
    remainder = all_merged - operator_combined
    for net in remainder.iter_cidrs():
        labeled.append((str(net), "CN"))

    labeled.sort(key=lambda t: IPNetwork(t[0]))
    return labeled
