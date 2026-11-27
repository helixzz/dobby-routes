import logging

import pytest

from dobby_routes.parser import (
    ApnicEntry,
    CidrSources,
    apnic_entry_to_cidrs,
    load_asn_file,
    load_cidr_directory,
    parse_apnic_delegated,
    parse_asn_list,
    parse_aws_ip_ranges,
    parse_bgp_asns,
    parse_bgp_table,
    parse_cidr_list,
    parse_google_ip_ranges,
    parse_local_cidr_list,
)

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


def test_apnic_entry_to_cidrs_invalid_ip():
    entry = ApnicEntry(start_ip="999.999.999.999", count=256, date="20110414", status="allocated")
    assert apnic_entry_to_cidrs(entry) == []


def test_apnic_entry_to_cidrs_zero_count():
    entry = ApnicEntry(start_ip="10.0.0.0", count=0, date="20110414", status="allocated")
    assert apnic_entry_to_cidrs(entry) == []


def test_apnic_entry_to_cidrs_negative_count():
    entry = ApnicEntry(start_ip="10.0.0.0", count=-1, date="20110414", status="allocated")
    assert apnic_entry_to_cidrs(entry) == []


def test_apnic_entry_to_cidrs_overflow_clamps():
    entry = ApnicEntry(start_ip="255.255.255.0", count=512, date="20110414", status="allocated")
    cidrs = apnic_entry_to_cidrs(entry)
    assert len(cidrs) > 0
    import ipaddress

    for cidr in cidrs:
        net = ipaddress.IPv4Network(cidr)
        assert int(net.broadcast_address) <= int(ipaddress.IPv4Address("255.255.255.255"))


def test_load_cidr_directory_aggregates_files_in_filename_order(tmp_path):
    directory = tmp_path / "lists"
    directory.mkdir()
    (directory / "z-last.txt").write_text(
        "1.1.1.1\n@include https://example.com/second.txt\n",
        encoding="utf-8",
    )
    (directory / "a-first.txt").write_text(
        "8.8.8.0/24\n@include https://example.com/first.txt\n"
        "@include https://example.com/second.txt\n",
        encoding="utf-8",
    )
    nested_directory = directory / "nested"
    nested_directory.mkdir()
    (nested_directory / "ignored.txt").write_text("9.9.9.0/24\n", encoding="utf-8")

    assert load_cidr_directory(str(directory)) == CidrSources(
        cidrs=["8.8.8.0/24", "1.1.1.1/32"],
        urls=["https://example.com/first.txt", "https://example.com/second.txt"],
    )


def test_load_cidr_directory_missing_is_tolerated(tmp_path, caplog):
    directory = tmp_path / "missing"
    caplog.set_level(logging.INFO)

    assert load_cidr_directory(str(directory)) == CidrSources(cidrs=[], urls=[])
    assert str(directory) in caplog.text


def test_load_cidr_directory_rejects_non_directory_path(tmp_path):
    path = tmp_path / "routes.txt"
    path.write_text("8.8.8.0/24\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not a directory"):
        load_cidr_directory(str(path))


def test_load_cidr_directory_invalid_line_names_source_file(tmp_path, caplog):
    directory = tmp_path / "lists"
    directory.mkdir()
    source_file = directory / "local-routes.txt"
    source_file.write_text("not-a-cidr\n8.8.8.0/24\n", encoding="utf-8")
    caplog.set_level(logging.WARNING)

    assert load_cidr_directory(str(directory)) == CidrSources(cidrs=["8.8.8.0/24"], urls=[])
    assert source_file.name in caplog.text


def test_parse_local_cidr_list_extracts_static_cidrs_and_include_urls():
    result = parse_local_cidr_list(
        "8.8.8.8\n@include https://example.com/routes.txt\n",
        source="local.txt",
    )

    assert result == CidrSources(
        cidrs=["8.8.8.8/32"],
        urls=["https://example.com/routes.txt"],
    )


@pytest.mark.parametrize("directive", ["@unknown value", "@include", "@include https://a b"])
def test_parse_local_cidr_list_rejects_invalid_directives_with_source(directive):
    with pytest.raises(ValueError, match="local.txt"):
        parse_local_cidr_list(directive, source="local.txt")


def test_parse_cidr_list_treats_include_as_invalid_content(caplog):
    caplog.set_level(logging.WARNING)

    assert parse_cidr_list("@include https://example.com/routes.txt\n", source="remote") == []
    assert "Skipping invalid CIDR line in remote" in caplog.text


def test_parse_cidr_list_skips_ipv6_with_source_warning(caplog):
    caplog.set_level(logging.WARNING)

    result = parse_cidr_list("8.8.8.0/24\n2001:4860::/32\n", source="mixed.txt")

    assert result == ["8.8.8.0/24"]
    assert "Skipping IPv6 CIDR in mixed.txt" in caplog.text


def test_parse_apnic_delegated_skips_non_routable_statuses(caplog):
    caplog.set_level(logging.WARNING)
    text = (
        "apnic|CN|ipv4|1.0.1.0|256|20110414|allocated\n"
        "apnic|CN|ipv4|1.0.2.0|256|20110414|assigned\n"
        "apnic|CN|ipv4|1.0.3.0|256|20110414|available\n"
        "apnic|CN|ipv4|1.0.4.0|256|20110414|reserved\n"
    )
    entries = parse_apnic_delegated(text)
    assert [e.start_ip for e in entries] == ["1.0.1.0", "1.0.2.0"]
    assert "available" in caplog.text
    assert "reserved" in caplog.text


def test_parse_apnic_delegated_ipv6():
    entries = parse_apnic_delegated(SAMPLE_APNIC, ip_version=6)
    assert len(entries) == 1
    assert entries[0].start_ip == "2407:c000::"
    assert entries[0].count == 32
    assert entries[0].ip_version == 6
    assert apnic_entry_to_cidrs(entries[0]) == ["2407:c000::/32"]


@pytest.mark.parametrize(
    ("start_ip", "prefix_len"),
    [
        ("2407:c000::", 0),
        ("2407:c000::", -1),
        ("2407:c000::", 129),
        ("not-ipv6", 32),
    ],
)
def test_apnic_entry_to_cidrs_ipv6_invalid(start_ip, prefix_len):
    entry = ApnicEntry(
        start_ip=start_ip,
        count=prefix_len,
        date="20120608",
        status="allocated",
        ip_version=6,
    )
    assert apnic_entry_to_cidrs(entry) == []


def test_parse_apnic_delegated_rejects_invalid_ip_version():
    with pytest.raises(ValueError, match="Unsupported IP version"):
        parse_apnic_delegated(SAMPLE_APNIC, ip_version=5)


def test_parse_cidr_list_ipv6_extracts_v6_and_skips_v4():
    result = parse_cidr_list("8.8.8.0/24\n2001:4860:0000::1/32\n", source="mixed.txt", ip_version=6)
    assert result == ["2001:4860::/32"]


def test_load_cidr_directory_ipv6(tmp_path):
    directory = tmp_path / "lists"
    directory.mkdir()
    (directory / "mixed.txt").write_text(
        "8.8.8.0/24\n2400:3200::/32\n@include https://example.com/routes.txt\n",
        encoding="utf-8",
    )
    assert load_cidr_directory(str(directory), ip_version=6) == CidrSources(
        cidrs=["2400:3200::/32"],
        urls=["https://example.com/routes.txt"],
    )


def test_parse_aws_ip_ranges_filters_cn_regions():
    body = """{
      "prefixes": [
        {"ip_prefix": "52.80.0.0/16", "region": "cn-north-1"},
        {"ip_prefix": "52.80.0.0/16", "region": "cn-north-1"},
        {"ip_prefix": "54.222.0.0/16", "region": "cn-northwest-1"},
        {"ip_prefix": "3.0.0.0/15", "region": "ap-southeast-1"}
      ],
      "ipv6_prefixes": [
        {"ipv6_prefix": "2406:dafe::/32", "region": "cn-north-1"},
        {"ipv6_prefix": "2600:1f18::/32", "region": "us-east-1"}
      ]
    }"""
    assert parse_aws_ip_ranges(body, ip_version=4) == ["52.80.0.0/16", "54.222.0.0/16"]
    assert parse_aws_ip_ranges(body, ip_version=6) == ["2406:dafe::/32"]


def test_parse_aws_ip_ranges_rejects_invalid_json():
    with pytest.raises(ValueError, match="Invalid AWS IP ranges JSON"):
        parse_aws_ip_ranges("{not json", ip_version=4)


def test_parse_google_ip_ranges_extracts_v4_and_v6():
    body = """{
      "prefixes": [
        {"ipv4Prefix": "8.8.8.0/24"},
        {"ipv4Prefix": "8.8.8.0/24"},
        {"ipv6Prefix": "2001:4860::/32"}
      ]
    }"""
    assert parse_google_ip_ranges(body, ip_version=4) == ["8.8.8.0/24"]
    assert parse_google_ip_ranges(body, ip_version=6) == ["2001:4860::/32"]


def test_parse_google_ip_ranges_rejects_invalid_json():
    with pytest.raises(ValueError, match="Invalid Google IP ranges JSON"):
        parse_google_ip_ranges("[]", ip_version=4)


def test_parse_bgp_asns_and_table():
    asns_csv = "asn,name,class,cc\nAS4134,CHINANET-BACKBONE,Eyeball,CN\nBAD,Ignore,Unknown,US\n"
    assert parse_bgp_asns(asns_csv) == {4134: "CHINANET-BACKBONE"}

    table_txt = (
        "# comment\n1.0.1.0/24 4134\n2400:3200::/32 37963\nbad-line\n1.0.2.0/24 not-an-asn\n"
    )
    v4, v6 = parse_bgp_table(table_txt)
    assert v4 == [("1.0.1.0/24", 4134)]
    assert v6 == [("2400:3200::/32", 37963)]


def test_parse_asn_list_and_load_asn_file(tmp_path):
    raw = "# header\nAS399358  # Anthropic\n399358\nAS0\ninvalid\n2906\n"
    assert parse_asn_list(raw, source="asns.txt") == [399358, 2906]

    asn_file = tmp_path / "asns.txt"
    asn_file.write_text(raw, encoding="utf-8")
    assert load_asn_file(str(asn_file)) == [399358, 2906]
    assert load_asn_file(str(tmp_path / "missing.txt")) == []
