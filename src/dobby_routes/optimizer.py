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
    operator_cidrs: dict[str, list[str]], all_cidrs: list[str]
) -> list[tuple[str, str]]:
    # Pre-build IPSet per operator once for efficient membership checks
    operator_sets: dict[str, IPSet] = {
        op: IPSet(cidrs) for op, cidrs in operator_cidrs.items()
    }

    result: list[tuple[str, str]] = []
    for cidr in sorted(all_cidrs):
        network = IPNetwork(cidr)
        annotation = "CN"
        for op, ipset in operator_sets.items():
            if network in ipset:
                annotation = OPERATOR_INFO.get(op, op)
                break
        result.append((cidr, annotation))
    return result
