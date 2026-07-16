import os
from argparse import Namespace
from unittest.mock import patch

import pytest
import requests
from netaddr import IPNetwork, IPSet

from dobby_routes.cli import _run, build_arg_parser, main
from dobby_routes.fetcher import REVIEWED_CIDR_SOURCE_SCOPES, TELEGRAM_CIDR_SOURCE_URL

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
