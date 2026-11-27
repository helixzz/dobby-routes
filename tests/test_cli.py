import json
import os
from argparse import Namespace
from unittest.mock import patch

import pytest
import requests
from netaddr import IPNetwork, IPSet

from dobby_routes.cli import _run, build_arg_parser, main
from dobby_routes.fetcher import (
    REVIEWED_CIDR_SOURCE_SCOPES,
    REVIEWED_CIDR_SOURCE_SCOPES_V6,
    TELEGRAM_CIDR_SOURCE_URL,
)

TELEGRAM_CIDRS = [
    "91.108.56.0/22",
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.16.0/22",
    "91.108.12.0/22",
    "149.154.160.0/20",
    "91.105.192.0/23",
    "91.108.20.0/22",
    "185.76.151.0/24",
]


def test_default_args():
    parser = build_arg_parser()
    args = parser.parse_args([])
    assert args.output_dir == "./output"
    assert args.allowlist_dir == "./allowlists"
    assert args.denylist_dir == "./denylists"
    assert args.skip_github is False
    assert args.skip_apnic is False
    assert args.verbose is False


def test_custom_output_dir():
    parser = build_arg_parser()
    args = parser.parse_args(["--output-dir", "/tmp/routes"])
    assert args.output_dir == "/tmp/routes"


def test_custom_local_list_dirs():
    parser = build_arg_parser()
    args = parser.parse_args(["--allowlist-dir", "/tmp/allow", "--denylist-dir", "/tmp/deny"])
    assert args.allowlist_dir == "/tmp/allow"
    assert args.denylist_dir == "/tmp/deny"


def test_skip_github_flag():
    parser = build_arg_parser()
    args = parser.parse_args(["--skip-github"])
    assert args.skip_github is True


def test_skip_apnic_flag():
    parser = build_arg_parser()
    args = parser.parse_args(["--skip-apnic"])
    assert args.skip_apnic is True


def test_verbose_flag():
    parser = build_arg_parser()
    args = parser.parse_args(["-v"])
    assert args.verbose is True


def test_verbose_long_flag():
    parser = build_arg_parser()
    args = parser.parse_args(["--verbose"])
    assert args.verbose is True


SAMPLE_APNIC = (
    "apnic|CN|ipv4|1.0.1.0|256|20110414|allocated\napnic|CN|ipv4|1.0.2.0|512|20110414|allocated\n"
)
SAMPLE_OPERATOR = "1.0.1.0/24\n"
SAMPLE_CHNROUTES2 = "1.0.2.0/23\n"


def _mock_fetch_all_operators():
    return {"chinanet": SAMPLE_OPERATOR}


def _make_args(
    tmp_path,
    skip_apnic=False,
    skip_github=False,
    verbose=False,
    allowlist_dir=None,
    denylist_dir=None,
):
    if allowlist_dir is None:
        allowlist_dir = tmp_path / "allowlists"
    if denylist_dir is None:
        denylist_dir = tmp_path / "denylists"
    return Namespace(
        output_dir=str(tmp_path),
        allowlist_dir=str(allowlist_dir),
        denylist_dir=str(denylist_dir),
        skip_apnic=skip_apnic,
        skip_github=skip_github,
        verbose=verbose,
    )


@patch("dobby_routes.cli.fetch_chnroutes2", return_value=SAMPLE_CHNROUTES2)
@patch("dobby_routes.cli.fetch_all_operators", side_effect=_mock_fetch_all_operators)
@patch("dobby_routes.cli.fetch_apnic", return_value=SAMPLE_APNIC)
def test_run_full_pipeline(mock_apnic, mock_ops, mock_chn, tmp_path):
    args = _make_args(tmp_path)
    _run(args)

    assert os.path.isfile(os.path.join(str(tmp_path), "cn_routes.txt"))
    assert os.path.isfile(os.path.join(str(tmp_path), "cn_routes_annotated.txt"))
    assert os.path.isfile(os.path.join(str(tmp_path), "cn_routes_inverse.txt"))

    mock_apnic.assert_called_once()
    mock_ops.assert_called_once()
    mock_chn.assert_called_once()


@patch("dobby_routes.cli.fetch_chnroutes2", return_value=SAMPLE_CHNROUTES2)
@patch("dobby_routes.cli.fetch_all_operators", side_effect=_mock_fetch_all_operators)
@patch("dobby_routes.cli.fetch_apnic", return_value=SAMPLE_APNIC)
def test_run_skip_github(mock_apnic, mock_ops, mock_chn, tmp_path):
    args = _make_args(tmp_path, skip_github=True)
    _run(args)

    mock_apnic.assert_called_once()
    mock_ops.assert_not_called()
    mock_chn.assert_not_called()

    optimized = open(os.path.join(str(tmp_path), "cn_routes.txt")).read()
    assert "1.0.1.0" in optimized


@patch("dobby_routes.cli.fetch_chnroutes2", return_value=SAMPLE_CHNROUTES2)
@patch("dobby_routes.cli.fetch_all_operators", side_effect=_mock_fetch_all_operators)
@patch("dobby_routes.cli.fetch_apnic", return_value=SAMPLE_APNIC)
def test_run_skip_apnic(mock_apnic, mock_ops, mock_chn, tmp_path):
    args = _make_args(tmp_path, skip_apnic=True)
    _run(args)

    mock_apnic.assert_not_called()
    mock_ops.assert_called_once()
    mock_chn.assert_called_once()

    optimized = open(os.path.join(str(tmp_path), "cn_routes.txt")).read()
    assert "1.0" in optimized


def test_run_no_sources_exits(tmp_path):
    args = _make_args(tmp_path, skip_apnic=True, skip_github=True)
    with pytest.raises(SystemExit) as exc_info:
        _run(args)
    assert exc_info.value.code == 1


def test_run_allowlist_only_with_remote_sources_skipped(tmp_path):
    allowlist_dir = tmp_path / "allowlists"
    allowlist_dir.mkdir()
    (allowlist_dir / "local.txt").write_text("invalid-route\n8.8.8.0/24\n", encoding="utf-8")

    _run(
        _make_args(
            tmp_path,
            skip_apnic=True,
            skip_github=True,
            allowlist_dir=allowlist_dir,
        )
    )

    optimized = _read_data_lines(os.path.join(str(tmp_path), "cn_routes.txt"))
    annotated = _read_data_lines(os.path.join(str(tmp_path), "cn_routes_annotated.txt"))
    assert optimized == ["8.8.8.0/24"]
    assert annotated == ["8.8.8.0/24  # CN"]


def test_run_denylist_removes_routes_from_outputs_and_adds_them_to_inverse(tmp_path):
    allowlist_dir = tmp_path / "allowlists"
    denylist_dir = tmp_path / "denylists"
    allowlist_dir.mkdir()
    denylist_dir.mkdir()
    (allowlist_dir / "local.txt").write_text("8.8.8.0/24\n9.9.9.0/24\n", encoding="utf-8")
    (denylist_dir / "remove.txt").write_text("8.8.8.0/24\n", encoding="utf-8")

    _run(
        _make_args(
            tmp_path,
            skip_apnic=True,
            skip_github=True,
            allowlist_dir=allowlist_dir,
            denylist_dir=denylist_dir,
        )
    )

    optimized = _read_data_lines(os.path.join(str(tmp_path), "cn_routes.txt"))
    annotated = _read_data_lines(os.path.join(str(tmp_path), "cn_routes_annotated.txt"))
    inverse = _read_data_lines(os.path.join(str(tmp_path), "cn_routes_inverse.txt"))
    assert "8.8.8.0/24" not in optimized
    assert all(not route.startswith("8.8.8.0/24") for route in annotated)
    assert IPNetwork("8.8.8.0/24") in IPSet(inverse)


def test_run_denylist_only_exits(tmp_path):
    denylist_dir = tmp_path / "denylists"
    denylist_dir.mkdir()
    (denylist_dir / "remove.txt").write_text("8.8.8.0/24\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        _run(
            _make_args(
                tmp_path,
                skip_apnic=True,
                skip_github=True,
                denylist_dir=denylist_dir,
            )
        )
    assert exc_info.value.code == 1


@patch("dobby_routes.cli.fetch_cidr_source", return_value="8.8.8.0/24\n")
def test_run_allowlist_include_adds_routes(mock_fetch_cidr_source, tmp_path):
    allowlist_dir = tmp_path / "allowlists"
    allowlist_dir.mkdir()
    url = "https://example.com/allow.txt"
    (allowlist_dir / "include.txt").write_text(f"@include {url}\n", encoding="utf-8")

    _run(
        _make_args(
            tmp_path,
            skip_apnic=True,
            skip_github=True,
            allowlist_dir=allowlist_dir,
        )
    )

    assert _read_data_lines(os.path.join(str(tmp_path), "cn_routes.txt")) == ["8.8.8.0/24"]
    mock_fetch_cidr_source.assert_called_once_with(url)


@patch("dobby_routes.cli.fetch_cidr_source", return_value="8.8.8.0/24\n")
def test_run_denylist_include_removes_routes_and_adds_them_to_inverse(
    mock_fetch_cidr_source, tmp_path
):
    allowlist_dir = tmp_path / "allowlists"
    denylist_dir = tmp_path / "denylists"
    allowlist_dir.mkdir()
    denylist_dir.mkdir()
    url = "https://example.com/deny.txt"
    (allowlist_dir / "local.txt").write_text("8.8.8.0/24\n9.9.9.0/24\n", encoding="utf-8")
    (denylist_dir / "include.txt").write_text(f"@include {url}\n", encoding="utf-8")

    _run(
        _make_args(
            tmp_path,
            skip_apnic=True,
            skip_github=True,
            allowlist_dir=allowlist_dir,
            denylist_dir=denylist_dir,
        )
    )

    optimized = _read_data_lines(os.path.join(str(tmp_path), "cn_routes.txt"))
    annotated = _read_data_lines(os.path.join(str(tmp_path), "cn_routes_annotated.txt"))
    inverse = _read_data_lines(os.path.join(str(tmp_path), "cn_routes_inverse.txt"))
    assert "8.8.8.0/24" not in optimized
    assert all(not route.startswith("8.8.8.0/24") for route in annotated)
    assert IPNetwork("8.8.8.0/24") in IPSet(inverse)
    mock_fetch_cidr_source.assert_called_once_with(url)


@pytest.mark.parametrize("body", ["", "2001:4860::/32\n"])
@patch("dobby_routes.cli.fetch_cidr_source")
def test_run_include_requires_usable_ipv4(mock_fetch_cidr_source, body, tmp_path):
    allowlist_dir = tmp_path / "allowlists"
    allowlist_dir.mkdir()
    url = "https://example.com/allow.txt"
    (allowlist_dir / "include.txt").write_text(f"@include {url}\n", encoding="utf-8")
    mock_fetch_cidr_source.return_value = body

    with pytest.raises(ValueError, match="no usable IPv4 CIDRs"):
        _run(
            _make_args(
                tmp_path,
                skip_apnic=True,
                skip_github=True,
                allowlist_dir=allowlist_dir,
            )
        )


@patch("dobby_routes.cli.fetch_cidr_source", side_effect=requests.ConnectionError("offline"))
def test_run_include_fetch_failure_propagates(mock_fetch_cidr_source, tmp_path):
    allowlist_dir = tmp_path / "allowlists"
    allowlist_dir.mkdir()
    url = "https://example.com/allow.txt"
    (allowlist_dir / "include.txt").write_text(f"@include {url}\n", encoding="utf-8")

    with pytest.raises(requests.ConnectionError, match="offline"):
        _run(
            _make_args(
                tmp_path,
                skip_apnic=True,
                skip_github=True,
                allowlist_dir=allowlist_dir,
            )
        )
    mock_fetch_cidr_source.assert_called_once_with(url)


@patch("dobby_routes.cli.fetch_cidr_source", return_value="\n".join(TELEGRAM_CIDRS) + "\n")
def test_run_telegram_include_accepts_reviewed_cidrs(mock_fetch_cidr_source, tmp_path):
    allowlist_dir = tmp_path / "allowlists"
    denylist_dir = tmp_path / "denylists"
    allowlist_dir.mkdir()
    denylist_dir.mkdir()
    (allowlist_dir / "local.txt").write_text("8.8.8.0/24\n", encoding="utf-8")
    (denylist_dir / "telegram.txt").write_text(
        f"@include {TELEGRAM_CIDR_SOURCE_URL}\n",
        encoding="utf-8",
    )

    _run(
        _make_args(
            tmp_path,
            skip_apnic=True,
            skip_github=True,
            allowlist_dir=allowlist_dir,
            denylist_dir=denylist_dir,
        )
    )

    approved_scope = IPSet(REVIEWED_CIDR_SOURCE_SCOPES[TELEGRAM_CIDR_SOURCE_URL])
    assert IPSet(TELEGRAM_CIDRS) - approved_scope == IPSet()
    assert "8.8.8.0/24" in _read_data_lines(os.path.join(str(tmp_path), "cn_routes.txt"))
    mock_fetch_cidr_source.assert_called_once_with(TELEGRAM_CIDR_SOURCE_URL)


@patch("dobby_routes.cli.fetch_cidr_source", return_value="91.108.8.0/21\n")
def test_run_telegram_include_accepts_contained_aggregate(mock_fetch_cidr_source, tmp_path):
    allowlist_dir = tmp_path / "allowlists"
    denylist_dir = tmp_path / "denylists"
    allowlist_dir.mkdir()
    denylist_dir.mkdir()
    (allowlist_dir / "local.txt").write_text("8.8.8.0/24\n", encoding="utf-8")
    (denylist_dir / "telegram.txt").write_text(
        f"@include {TELEGRAM_CIDR_SOURCE_URL}\n",
        encoding="utf-8",
    )

    _run(
        _make_args(
            tmp_path,
            skip_apnic=True,
            skip_github=True,
            allowlist_dir=allowlist_dir,
            denylist_dir=denylist_dir,
        )
    )

    approved_scope = IPSet(REVIEWED_CIDR_SOURCE_SCOPES[TELEGRAM_CIDR_SOURCE_URL])
    assert IPSet(["91.108.8.0/21"]) - approved_scope == IPSet()
    mock_fetch_cidr_source.assert_called_once_with(TELEGRAM_CIDR_SOURCE_URL)


@pytest.mark.parametrize("body", ["0.0.0.0/0\n", "8.8.8.0/24\n"])
@patch("dobby_routes.cli.fetch_cidr_source")
def test_run_telegram_include_rejects_out_of_scope_routes(mock_fetch_cidr_source, body, tmp_path):
    allowlist_dir = tmp_path / "allowlists"
    denylist_dir = tmp_path / "denylists"
    allowlist_dir.mkdir()
    denylist_dir.mkdir()
    (allowlist_dir / "local.txt").write_text("1.1.1.0/24\n", encoding="utf-8")
    (denylist_dir / "telegram.txt").write_text(
        f"@include {TELEGRAM_CIDR_SOURCE_URL}\n",
        encoding="utf-8",
    )
    mock_fetch_cidr_source.return_value = body

    with pytest.raises(ValueError, match="outside reviewed scope"):
        _run(
            _make_args(
                tmp_path,
                skip_apnic=True,
                skip_github=True,
                allowlist_dir=allowlist_dir,
                denylist_dir=denylist_dir,
            )
        )

    assert not os.path.exists(os.path.join(str(tmp_path), "cn_routes.txt"))
    assert not os.path.exists(os.path.join(str(tmp_path), "cn_routes_annotated.txt"))
    assert not os.path.exists(os.path.join(str(tmp_path), "cn_routes_inverse.txt"))
    mock_fetch_cidr_source.assert_called_once_with(TELEGRAM_CIDR_SOURCE_URL)


@patch("dobby_routes.cli.fetch_apnic", return_value=SAMPLE_APNIC)
def test_run_tolerates_missing_local_list_directories(mock_apnic, tmp_path):
    _run(_make_args(tmp_path, skip_github=True))

    mock_apnic.assert_called_once()
    optimized = _read_data_lines(os.path.join(str(tmp_path), "cn_routes.txt"))
    assert "1.0.1.0/24" in optimized


@patch("dobby_routes.cli.fetch_chnroutes2", return_value=SAMPLE_CHNROUTES2)
@patch("dobby_routes.cli.fetch_all_operators", side_effect=_mock_fetch_all_operators)
@patch("dobby_routes.cli.fetch_apnic", return_value=SAMPLE_APNIC)
def test_annotated_output_has_operator_labels(mock_apnic, mock_ops, mock_chn, tmp_path):
    _run(_make_args(tmp_path))
    content = open(os.path.join(str(tmp_path), "cn_routes_annotated.txt")).read()
    assert "China Telecom" in content


@patch("dobby_routes.cli.fetch_chnroutes2", return_value=SAMPLE_CHNROUTES2)
@patch("dobby_routes.cli.fetch_all_operators", side_effect=_mock_fetch_all_operators)
@patch("dobby_routes.cli.fetch_apnic", return_value=SAMPLE_APNIC)
def test_inverse_output_is_complement(mock_apnic, mock_ops, mock_chn, tmp_path):
    _run(_make_args(tmp_path))
    content = open(os.path.join(str(tmp_path), "cn_routes_inverse.txt")).read()
    data_lines = [
        line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")
    ]
    assert "1.0.1.0/24" not in data_lines
    assert "1.0.2.0/23" not in data_lines


def _read_data_lines(path):
    with open(path) as route_file:
        return [line.strip() for line in route_file if line.strip() and not line.startswith("#")]


@patch("dobby_routes.cli.fetch_chnroutes2", return_value=SAMPLE_CHNROUTES2)
@patch("dobby_routes.cli.fetch_all_operators", side_effect=_mock_fetch_all_operators)
@patch("dobby_routes.cli.fetch_apnic", return_value=SAMPLE_APNIC)
def test_output_headers_have_route_counts(mock_apnic, mock_ops, mock_chn, tmp_path):
    _run(_make_args(tmp_path))
    for fname in ("cn_routes.txt", "cn_routes_annotated.txt", "cn_routes_inverse.txt"):
        content = open(os.path.join(str(tmp_path), fname)).read()
        assert "# Total routes:" in content


@patch("dobby_routes.cli._run", side_effect=OSError("disk full"))
def test_main_catches_exception(mock_run):
    with patch("sys.argv", ["dobby-routes"]):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1


@patch("dobby_routes.cli._run", side_effect=KeyboardInterrupt)
def test_main_catches_keyboard_interrupt(mock_run):
    with patch("sys.argv", ["dobby-routes"]):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 130


def test_new_cli_flags():
    parser = build_arg_parser()
    args = parser.parse_args(
        [
            "--ipv6",
            "--min-routes",
            "4000",
            "--min-inverse-routes",
            "8000",
            "--min-ipv6-routes",
            "1500",
            "--min-ipv6-inverse-routes",
            "10000",
            "--stats-json",
            "/tmp/stats.json",
        ]
    )
    assert args.ipv6 is True
    assert args.min_routes == 4000
    assert args.min_inverse_routes == 8000
    assert args.min_ipv6_routes == 1500
    assert args.min_ipv6_inverse_routes == 10000
    assert args.stats_json == "/tmp/stats.json"


SAMPLE_APNIC_DUAL_STACK = (
    "apnic|CN|ipv4|1.0.1.0|256|20110414|allocated\n"
    "apnic|CN|ipv6|2400:3200::|32|20120608|allocated\n"
)
SAMPLE_OPERATOR_V6 = "2400:3200::/32\n"
SAMPLE_CHINA_V6 = "2407:c000::/32\n"
TELEGRAM_DUAL_STACK = (
    "\n".join(TELEGRAM_CIDRS)
    + "\n"
    + "\n".join(REVIEWED_CIDR_SOURCE_SCOPES_V6[TELEGRAM_CIDR_SOURCE_URL])
    + "\n"
)


@patch("dobby_routes.cli.fetch_cidr_source", return_value=TELEGRAM_DUAL_STACK)
@patch("dobby_routes.cli.fetch_china_v6", return_value=SAMPLE_CHINA_V6)
@patch(
    "dobby_routes.cli.fetch_all_operators_v6",
    return_value={"chinanet": SAMPLE_OPERATOR_V6},
)
@patch("dobby_routes.cli.fetch_chnroutes2", return_value=SAMPLE_CHNROUTES2)
@patch("dobby_routes.cli.fetch_all_operators", side_effect=_mock_fetch_all_operators)
@patch("dobby_routes.cli.fetch_apnic", return_value=SAMPLE_APNIC_DUAL_STACK)
def test_run_full_pipeline_with_ipv6_and_stats_json(
    mock_apnic,
    mock_ops,
    mock_chn,
    mock_ops_v6,
    mock_china_v6,
    mock_include,
    tmp_path,
):
    denylist_dir = tmp_path / "denylists"
    denylist_dir.mkdir()
    (denylist_dir / "telegram.txt").write_text(
        f"@include {TELEGRAM_CIDR_SOURCE_URL}\n",
        encoding="utf-8",
    )
    stats_path = tmp_path / "meta" / "stats.json"
    args = Namespace(
        output_dir=str(tmp_path),
        allowlist_dir=str(tmp_path / "allowlists"),
        denylist_dir=str(denylist_dir),
        skip_apnic=False,
        skip_github=False,
        ipv6=True,
        min_routes=1,
        min_inverse_routes=1,
        min_ipv6_routes=1,
        min_ipv6_inverse_routes=1,
        stats_json=str(stats_path),
        verbose=False,
    )

    _run(args)

    for fname in (
        "cn_routes.txt",
        "cn_routes_annotated.txt",
        "cn_routes_inverse.txt",
        "cn_routes6.txt",
        "cn_routes6_annotated.txt",
        "cn_routes6_inverse.txt",
    ):
        assert os.path.isfile(os.path.join(str(tmp_path), fname))

    mock_apnic.assert_called_once()
    mock_include.assert_called_once_with(TELEGRAM_CIDR_SOURCE_URL)
    mock_ops_v6.assert_called_once()
    mock_china_v6.assert_called_once()

    v6_routes = _read_data_lines(os.path.join(str(tmp_path), "cn_routes6.txt"))
    v6_inverse = _read_data_lines(os.path.join(str(tmp_path), "cn_routes6_inverse.txt"))
    assert "2400:3200::/32" in v6_routes
    assert "2407:c000::/32" in v6_routes
    assert IPNetwork("2a0a:f280::/32") in IPSet(v6_inverse)

    stats = json.loads(stats_path.read_text(encoding="utf-8"))
    assert stats["ipv4"]["forward"] > 0
    assert stats["ipv6"]["forward"] == len(v6_routes)
    assert stats["ipv6"]["inverse"] == len(v6_inverse)


@patch(
    "dobby_routes.cli.fetch_cidr_source",
    return_value="91.108.56.0/22\n2606:4700::/32\n",
)
def test_run_telegram_include_rejects_out_of_scope_ipv6(mock_fetch_cidr_source, tmp_path):
    allowlist_dir = tmp_path / "allowlists"
    denylist_dir = tmp_path / "denylists"
    allowlist_dir.mkdir()
    denylist_dir.mkdir()
    (allowlist_dir / "local.txt").write_text("1.1.1.0/24\n2400:3200::/32\n", encoding="utf-8")
    (denylist_dir / "telegram.txt").write_text(
        f"@include {TELEGRAM_CIDR_SOURCE_URL}\n",
        encoding="utf-8",
    )
    args = Namespace(
        output_dir=str(tmp_path),
        allowlist_dir=str(allowlist_dir),
        denylist_dir=str(denylist_dir),
        skip_apnic=True,
        skip_github=True,
        ipv6=True,
        min_routes=0,
        min_inverse_routes=0,
        min_ipv6_routes=0,
        min_ipv6_inverse_routes=0,
        stats_json=None,
        verbose=False,
    )

    with pytest.raises(ValueError, match="outside reviewed scope"):
        _run(args)

    assert not os.path.exists(os.path.join(str(tmp_path), "cn_routes.txt"))
    assert not os.path.exists(os.path.join(str(tmp_path), "cn_routes6.txt"))


@patch("dobby_routes.cli.fetch_apnic", return_value=SAMPLE_APNIC)
def test_run_guardrail_rejects_insufficient_routes_without_writing_files(mock_apnic, tmp_path):
    args = Namespace(
        output_dir=str(tmp_path),
        allowlist_dir=str(tmp_path / "allowlists"),
        denylist_dir=str(tmp_path / "denylists"),
        skip_apnic=False,
        skip_github=True,
        ipv6=False,
        min_routes=100,
        min_inverse_routes=0,
        min_ipv6_routes=0,
        min_ipv6_inverse_routes=0,
        stats_json=None,
        verbose=False,
    )

    with pytest.raises(ValueError, match="IPv4 forward routes guardrail failed"):
        _run(args)

    assert not os.path.exists(os.path.join(str(tmp_path), "cn_routes.txt"))


@patch("dobby_routes.cli.fetch_apnic", return_value="# empty\n")
def test_run_empty_apnic_fails_closed(mock_apnic, tmp_path):
    with pytest.raises(ValueError, match="APNIC source returned no usable IPv4 CIDRs"):
        _run(_make_args(tmp_path, skip_github=True))


@patch("dobby_routes.cli.fetch_chnroutes2", return_value="# empty\n")
@patch("dobby_routes.cli.fetch_all_operators", side_effect=_mock_fetch_all_operators)
def test_run_empty_chnroutes2_fails_closed(mock_ops, mock_chn, tmp_path):
    with pytest.raises(ValueError, match="chnroutes2 source returned no usable IPv4 CIDRs"):
        _run(_make_args(tmp_path, skip_apnic=True))


def test_v040_cli_flags():
    parser = build_arg_parser()
    args = parser.parse_args(
        [
            "--aws-cn",
            "--protect-overseas",
            "--bgp",
            "--verify-canaries",
            "--baseline-stats",
            "/tmp/base.json",
            "--max-drift-pct",
            "12.5",
            "--formats",
            "bird,routeros,nftables,singbox",
        ]
    )
    assert args.aws_cn is True
    assert args.protect_overseas is True
    assert args.bgp is True
    assert args.verify_canaries is True
    assert args.baseline_stats == "/tmp/base.json"
    assert args.max_drift_pct == 12.5
    assert args.formats == "bird,routeros,nftables,singbox"


SAMPLE_AWS_JSON = json.dumps(
    {
        "prefixes": [
            {"ip_prefix": "52.80.0.0/16", "region": "cn-north-1"},
            {"ip_prefix": "3.0.0.0/16", "region": "us-east-1"},
        ],
        "ipv6_prefixes": [
            {"ipv6_prefix": "2406:dafe::/32", "region": "cn-north-1"},
            {"ipv6_prefix": "2600:1f18::/32", "region": "us-east-1"},
        ],
    }
)
SAMPLE_GOOGLE_JSON = json.dumps(
    {
        "prefixes": [
            {"ipv4Prefix": "8.8.8.0/24"},
            {"ipv6Prefix": "2001:4860::/32"},
        ]
    }
)
SAMPLE_BGP_TABLE = (
    "1.0.1.0/24 4134\n"
    "52.80.0.0/16 58879\n"
    "114.114.114.0/24 4134\n"
    "223.5.5.0/24 37963\n"
    "119.29.29.0/24 45090\n"
    "180.76.76.0/24 55967\n"
    "1.1.1.0/24 13335\n"
    "8.8.8.0/24 15169\n"
    "9.9.9.0/24 19281\n"
    "104.18.32.0/24 13335\n"
    "149.154.160.0/20 62041\n"
    "47.242.0.0/16 45102\n"
    "43.132.0.0/16 132203\n"
    "2400:3200::/32 37963\n"
    "2402:4e00::/32 45090\n"
    "2001:da8::/32 4538\n"
    "2406:dafe::/32 58879\n"
    "2606:4700:4700::/48 13335\n"
    "2001:4860:4860::/48 15169\n"
    "2a0a:f280::/32 62041\n"
)
SAMPLE_BGP_ASNS = (
    "asn,name,class,cc\n"
    "AS58879,Beijing Sinnet Technology,Content,CN\n"
    "AS37963,Alibaba Cloud,Content,CN\n"
    "AS45090,Tencent Cloud,Content,CN\n"
)
SAMPLE_CANARY_APNIC = (
    "apnic|CN|ipv4|114.114.114.0|256|20110414|allocated\n"
    "apnic|CN|ipv4|223.5.5.0|256|20110414|allocated\n"
    "apnic|CN|ipv4|119.29.29.0|256|20110414|allocated\n"
    "apnic|CN|ipv4|180.76.76.0|256|20110414|allocated\n"
    "apnic|CN|ipv4|8.8.8.0|256|20110414|allocated\n"
    "apnic|CN|ipv6|2400:3200::|32|20120608|allocated\n"
    "apnic|CN|ipv6|2402:4e00::|32|20120608|allocated\n"
    "apnic|CN|ipv6|2001:da8::|32|20120608|allocated\n"
)


@patch("dobby_routes.cli.fetch_bgp_asns", return_value=SAMPLE_BGP_ASNS)
@patch("dobby_routes.cli.fetch_bgp_table", return_value=SAMPLE_BGP_TABLE)
@patch("dobby_routes.cli.fetch_google_ip_ranges", return_value=SAMPLE_GOOGLE_JSON)
@patch("dobby_routes.cli.fetch_cloudflare_v6", return_value="2606:4700:4700::/48\n")
@patch("dobby_routes.cli.fetch_cloudflare_v4", return_value="1.1.1.0/24\n104.18.32.0/24\n")
@patch("dobby_routes.cli.fetch_aws_ip_ranges", return_value=SAMPLE_AWS_JSON)
@patch("dobby_routes.cli.fetch_china_v6", return_value="2400:3200::/32\n")
@patch("dobby_routes.cli.fetch_all_operators_v6", return_value={"chinanet": "2400:3200::/32\n"})
@patch("dobby_routes.cli.fetch_chnroutes2", return_value="1.0.1.0/24\n")
@patch("dobby_routes.cli.fetch_all_operators", side_effect=_mock_fetch_all_operators)
@patch("dobby_routes.cli.fetch_apnic", return_value=SAMPLE_CANARY_APNIC)
def test_run_v040_full_features_with_bgp_canaries_and_formats(
    mock_apnic,
    mock_ops,
    mock_chn,
    mock_ops_v6,
    mock_china_v6,
    mock_aws,
    mock_cf4,
    mock_cf6,
    mock_google,
    mock_bgp_table,
    mock_bgp_asns,
    tmp_path,
):
    stats_path = tmp_path / "stats.json"
    args = Namespace(
        output_dir=str(tmp_path),
        allowlist_dir=str(tmp_path / "allowlists"),
        denylist_dir=str(tmp_path / "denylists"),
        skip_apnic=False,
        skip_github=False,
        ipv6=True,
        aws_cn=True,
        protect_overseas=True,
        bgp=True,
        verify_canaries=True,
        baseline_stats=str(tmp_path / "missing-baseline.json"),
        max_drift_pct=15.0,
        formats="bird,routeros,nftables,singbox",
        min_routes=1,
        min_inverse_routes=1,
        min_ipv6_routes=1,
        min_ipv6_inverse_routes=1,
        stats_json=str(stats_path),
        verbose=False,
    )

    _run(args)

    # AWS CN added, Google 8.8.8.0/24 excluded by --protect-overseas even though polluted in APNIC
    v4_routes = _read_data_lines(os.path.join(str(tmp_path), "cn_routes.txt"))
    assert "52.80.0.0/16" in v4_routes
    assert "8.8.8.0/24" not in v4_routes

    # Annotated enriched with BGP origin ASN name for non-operator route
    annotated_text = open(os.path.join(str(tmp_path), "cn_routes_annotated.txt")).read()
    assert "AS58879 Beijing Sinnet Technology" in annotated_text

    # BGP-minimized outputs and all extra format outputs written
    for rel in (
        "cn_routes_bgp.txt",
        "cn_routes_bgp_inverse.txt",
        "cn_routes6_bgp.txt",
        "cn_routes6_bgp_inverse.txt",
        "formats/bird/cn_routes_v4.conf",
        "formats/bird/cn_routes_bgp_inverse_v6.conf",
        "formats/routeros/cn_routes_v4.rsc",
        "formats/nftables/cn_routes_v4.nft",
        "formats/singbox/cn_routes.json",
        "formats/singbox/cn_routes_bgp_inverse.json",
    ):
        assert os.path.isfile(os.path.join(str(tmp_path), rel)), f"Missing {rel}"

    stats = json.loads(stats_path.read_text(encoding="utf-8"))
    assert "ipv4_bgp" in stats
    assert "ipv6_bgp" in stats


@patch("dobby_routes.cli.fetch_apnic", return_value=SAMPLE_APNIC)
def test_run_drift_guardrail_blocks_writing_files(mock_apnic, tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"ipv4": {"forward": 5000}}), encoding="utf-8")
    args = Namespace(
        output_dir=str(tmp_path / "out"),
        allowlist_dir=str(tmp_path / "allowlists"),
        denylist_dir=str(tmp_path / "denylists"),
        skip_apnic=False,
        skip_github=True,
        baseline_stats=str(baseline),
        max_drift_pct=15.0,
        verbose=False,
    )

    with pytest.raises(ValueError, match="Drift guardrail failed"):
        _run(args)

    assert not os.path.exists(str(tmp_path / "out" / "cn_routes.txt"))


def test_run_rejects_unknown_format(tmp_path):
    args = Namespace(
        output_dir=str(tmp_path),
        allowlist_dir=str(tmp_path / "allowlists"),
        denylist_dir=str(tmp_path / "denylists"),
        skip_apnic=True,
        skip_github=True,
        formats="bird,unknownfmt",
        verbose=False,
    )
    with pytest.raises(ValueError, match="Unsupported format"):
        _run(args)
