from netaddr import IPNetwork, IPSet

from dobby_routes.optimizer import (
    NON_ROUTABLE_SET,
    ROUTABLE_UNIVERSE,
    annotate_routes,
    compute_complement,
    filter_non_routable,
    merge_routes,
    optimize_routes,
)


def test_merge_routes_single_list():
    result = merge_routes([["10.0.0.0/24", "10.0.1.0/24"]])
    assert IPNetwork("10.0.0.0/24") in result
    assert IPNetwork("10.0.1.0/24") in result


def test_merge_routes_overlapping():
    result = merge_routes([["10.0.0.0/24", "10.0.0.0/23"]])
    assert IPNetwork("10.0.0.0/23") in result


def test_merge_routes_adjacent_merged():
    result = merge_routes([["10.0.0.0/25", "10.0.0.128/25"]])
    assert IPNetwork("10.0.0.0/24") in result


def test_merge_routes_multiple_lists_union():
    result = merge_routes([["10.0.0.0/24"], ["192.168.0.0/24"]])
    assert IPNetwork("10.0.0.0/24") in result
    assert IPNetwork("192.168.0.0/24") in result


def test_merge_routes_returns_ipset():
    result = merge_routes([["10.0.0.0/24"]])
    assert isinstance(result, IPSet)


def test_merge_routes_skips_invalid():
    result = merge_routes([["not-a-cidr", "10.0.0.0/24"]])
    assert IPNetwork("10.0.0.0/24") in result


def test_merge_routes_empty():
    result = merge_routes([])
    assert result == IPSet()


def test_optimize_routes_returns_numerically_sorted():
    ipset = IPSet(["10.0.0.0/8", "2.0.0.0/8", "192.168.0.0/24"])
    result = optimize_routes(ipset)
    assert isinstance(result, list)
    assert all(isinstance(s, str) for s in result)
    assert result == ["2.0.0.0/8", "10.0.0.0/8", "192.168.0.0/24"]


def test_optimize_routes_merges():
    ipset = IPSet(["10.0.0.0/25", "10.0.0.128/25"])
    result = optimize_routes(ipset)
    assert "10.0.0.0/24" in result


def test_compute_complement_excludes_input():
    ipset = IPSet(["0.0.0.0/0"])
    result = compute_complement(ipset)
    assert result == []


def test_compute_complement_of_10_slash_8():
    ipset = IPSet(["10.0.0.0/8"])
    complement = compute_complement(ipset)
    assert "10.0.0.0/8" not in complement
    complement_set = IPSet(complement)
    assert IPNetwork("10.0.0.0/8") not in complement_set
    for cidr in complement:
        assert IPNetwork(cidr) not in NON_ROUTABLE_SET


def test_compute_complement_plus_original_equals_routable():
    ipset = IPSet(["1.0.0.0/8"])
    complement = compute_complement(ipset)
    combined = IPSet(complement) | ipset
    assert combined == ROUTABLE_UNIVERSE


def test_compute_complement_returns_numerically_sorted():
    ipset = IPSet(["1.0.0.0/8"])
    result = compute_complement(ipset)
    networks = [IPNetwork(c) for c in result]
    assert networks == sorted(networks)


def test_annotate_routes_operator_annotation():
    operator_cidrs = {"chinanet": ["10.0.0.0/24"]}
    all_merged = IPSet(["10.0.0.0/24"])
    result = annotate_routes(operator_cidrs, all_merged)
    assert len(result) == 1
    cidr, annotation = result[0]
    assert cidr == "10.0.0.0/24"
    assert "China Telecom" in annotation


def test_annotate_routes_non_operator_gets_cn():
    operator_cidrs = {"chinanet": ["10.0.0.0/24"]}
    all_merged = IPSet(["10.0.0.0/24", "192.168.0.0/24"])
    result = annotate_routes(operator_cidrs, all_merged)
    cn_entries = [(c, a) for c, a in result if a == "CN"]
    assert len(cn_entries) == 1
    assert cn_entries[0][0] == "192.168.0.0/24"


def test_annotate_routes_sorted_output():
    operator_cidrs = {}
    all_merged = IPSet(["192.168.0.0/24", "10.0.0.0/8"])
    result = annotate_routes(operator_cidrs, all_merged)
    cidrs = [r[0] for r in result]
    networks = [IPNetwork(c) for c in cidrs]
    assert networks == sorted(networks)


def test_annotate_routes_unicom():
    operator_cidrs = {"unicom": ["172.16.0.0/24"]}
    all_merged = IPSet(["172.16.0.0/24"])
    result = annotate_routes(operator_cidrs, all_merged)
    _, annotation = result[0]
    assert "Unicom" in annotation


def test_annotate_routes_empty():
    result = annotate_routes({}, IPSet())
    assert result == []


def test_filter_non_routable_removes_rfc1918():
    ipset = IPSet(["1.0.0.0/24", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
    result = filter_non_routable(ipset)
    assert IPNetwork("1.0.0.0/24") in result
    assert IPNetwork("10.0.0.0/8") not in result
    assert IPNetwork("172.16.0.0/12") not in result
    assert IPNetwork("192.168.0.0/16") not in result


def test_filter_non_routable_removes_cgnat():
    ipset = IPSet(["1.0.0.0/24", "100.64.0.0/10"])
    result = filter_non_routable(ipset)
    assert IPNetwork("100.64.0.0/10") not in result
    assert IPNetwork("1.0.0.0/24") in result


def test_filter_non_routable_removes_loopback_and_linklocal():
    ipset = IPSet(["127.0.0.0/8", "169.254.0.0/16", "8.8.8.0/24"])
    result = filter_non_routable(ipset)
    assert IPNetwork("127.0.0.0/8") not in result
    assert IPNetwork("169.254.0.0/16") not in result
    assert IPNetwork("8.8.8.0/24") in result


def test_filter_non_routable_removes_multicast_and_reserved():
    ipset = IPSet(["224.0.0.0/4", "240.0.0.0/4", "1.2.3.0/24"])
    result = filter_non_routable(ipset)
    assert IPNetwork("224.0.0.0/4") not in result
    assert IPNetwork("240.0.0.0/4") not in result
    assert IPNetwork("1.2.3.0/24") in result


def test_filter_non_routable_removes_documentation_nets():
    ipset = IPSet(["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "1.1.1.0/24"])
    result = filter_non_routable(ipset)
    assert IPNetwork("192.0.2.0/24") not in result
    assert IPNetwork("198.51.100.0/24") not in result
    assert IPNetwork("203.0.113.0/24") not in result
    assert IPNetwork("1.1.1.0/24") in result


def test_filter_non_routable_preserves_public_only():
    public = ["1.0.0.0/8", "8.8.8.0/24", "114.114.114.0/24"]
    ipset = IPSet(public)
    result = filter_non_routable(ipset)
    assert result == ipset


def test_filter_non_routable_empty():
    result = filter_non_routable(IPSet())
    assert result == IPSet()


def test_complement_excludes_all_non_routable():
    ipset = IPSet(["1.0.0.0/8"])
    complement = compute_complement(ipset)
    complement_set = IPSet(complement)
    for cidr in complement:
        assert IPNetwork(cidr) not in NON_ROUTABLE_SET
    assert (complement_set & NON_ROUTABLE_SET) == IPSet()


def test_routable_universe_has_no_private_ranges():
    for cidr in NON_ROUTABLE_SET.iter_cidrs():
        assert cidr not in ROUTABLE_UNIVERSE
