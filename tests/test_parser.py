import pytest
from dobby_routes.parser import ApnicEntry, parse_apnic_delegated, apnic_entry_to_cidrs, parse_cidr_list


SAMPLE_APNIC = """\
# comment line
2|apnic|20241201|50153|20241201|20241201|+1000
apnic|JP|ipv4|1.0.0.0|256|20110811|allocated
apnic|CN|ipv4|1.0.1.0|256|20110414|allocated
apnic|CN|ipv4|1.0.2.0|512|20110414|allocated
apnic|CN|ipv6|2407:c000::|32|20120608|allocated
apnic|CN|ipv4|1.1.1.0|256|20110414|allocated
apnic|CN|ipv4|short|only
apnic|CN|ipv4|1.2.3.4|notanint|20110414|allocated
"""


def test_parse_apnic_delegated_extracts_cn_ipv4():
    entries = parse_apnic_delegated(SAMPLE_APNIC)
    start_ips = [e.start_ip for e in entries]
    assert "1.0.1.0" in start_ips
    assert "1.0.2.0" in start_ips
    assert "1.1.1.0" in start_ips


def test_parse_apnic_delegated_skips_non_cn():
    entries = parse_apnic_delegated(SAMPLE_APNIC)
    assert all(e.start_ip != "1.0.0.0" for e in entries)


def test_parse_apnic_delegated_skips_ipv6():
    entries = parse_apnic_delegated(SAMPLE_APNIC)
    assert all(":" not in e.start_ip for e in entries)


def test_parse_apnic_delegated_skips_comment_lines():
    entries = parse_apnic_delegated(SAMPLE_APNIC)
    assert len(entries) == 3


def test_parse_apnic_delegated_skips_header_summary():
    text = "2|apnic|20241201|50153|20241201|20241201|+1000\n"
    entries = parse_apnic_delegated(text)
    assert entries == []


def test_parse_apnic_delegated_skips_malformed_too_few_fields():
    text = "apnic|CN|ipv4|short|only\n"
    entries = parse_apnic_delegated(text)
    assert entries == []


def test_parse_apnic_delegated_skips_invalid_count():
    text = "apnic|CN|ipv4|1.2.3.4|notanint|20110414|allocated\n"
    entries = parse_apnic_delegated(text)
    assert entries == []


def test_parse_apnic_delegated_entry_fields():
    text = "apnic|CN|ipv4|1.0.1.0|256|20110414|allocated\n"
    entries = parse_apnic_delegated(text)
    assert len(entries) == 1
    e = entries[0]
    assert e.start_ip == "1.0.1.0"
    assert e.count == 256
    assert e.date == "20110414"
    assert e.status == "allocated"


def test_apnic_entry_to_cidrs_power_of_2_256():
    entry = ApnicEntry(start_ip="192.168.1.0", count=256, date="20110414", status="allocated")
    cidrs = apnic_entry_to_cidrs(entry)
    assert cidrs == ["192.168.1.0/24"]


def test_apnic_entry_to_cidrs_single_ip():
    entry = ApnicEntry(start_ip="10.0.0.1", count=1, date="20110414", status="allocated")
    cidrs = apnic_entry_to_cidrs(entry)
    assert cidrs == ["10.0.0.1/32"]


def test_apnic_entry_to_cidrs_non_power_of_2_768():
    entry = ApnicEntry(start_ip="192.168.0.0", count=768, date="20110414", status="allocated")
    cidrs = apnic_entry_to_cidrs(entry)
    import ipaddress
    total_ips = sum(2 ** (32 - int(c.split("/")[1])) for c in cidrs)
    assert total_ips == 768
    assert len(cidrs) > 1


def test_apnic_entry_to_cidrs_512():
    entry = ApnicEntry(start_ip="10.0.0.0", count=512, date="20110414", status="allocated")
    cidrs = apnic_entry_to_cidrs(entry)
    assert cidrs == ["10.0.0.0/23"]


def test_parse_cidr_list_valid():
    text = "10.0.0.0/8\n192.168.0.0/16\n"
    result = parse_cidr_list(text)
    assert "10.0.0.0/8" in result
    assert "192.168.0.0/16" in result


def test_parse_cidr_list_strips_comments():
    text = "# this is a comment\n10.0.0.0/8\n"
    result = parse_cidr_list(text)
    assert result == ["10.0.0.0/8"]


def test_parse_cidr_list_strips_blank_lines():
    text = "\n\n10.0.0.0/8\n\n"
    result = parse_cidr_list(text)
    assert result == ["10.0.0.0/8"]


def test_parse_cidr_list_skips_invalid():
    text = "not-a-cidr\n10.0.0.0/8\n"
    result = parse_cidr_list(text)
    assert result == ["10.0.0.0/8"]


def test_parse_cidr_list_empty():
    result = parse_cidr_list("")
    assert result == []


def test_parse_cidr_list_normalizes_host_bits():
    text = "10.0.0.1/8\n"
    result = parse_cidr_list(text)
    assert result == ["10.0.0.0/8"]
