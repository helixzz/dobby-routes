import pytest
from netaddr import IPSet, IPNetwork
from dobby_routes.optimizer import merge_routes, optimize_routes, compute_complement, annotate_routes


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


def test_optimize_routes_returns_sorted_strings():
    ipset = IPSet(["192.168.0.0/24", "10.0.0.0/8"])
    result = optimize_routes(ipset)
    assert isinstance(result, list)
    assert all(isinstance(s, str) for s in result)
    assert result == sorted(result)


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
    assert IPNetwork("192.168.0.0/24") in complement_set


def test_compute_complement_plus_original_equals_all():
    ipset = IPSet(["10.0.0.0/8"])
    complement = compute_complement(ipset)
    combined = IPSet(complement) | ipset
    assert combined == IPSet(["0.0.0.0/0"])


def test_compute_complement_returns_sorted():
    ipset = IPSet(["10.0.0.0/8"])
    result = compute_complement(ipset)
    assert result == sorted(result)


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
