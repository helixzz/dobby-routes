import os
from argparse import Namespace
from unittest.mock import patch

import pytest

from dobby_routes.cli import _run, build_arg_parser, main


def test_default_args():
    parser = build_arg_parser()
    args = parser.parse_args([])
    assert args.output_dir == "./output"
    assert args.skip_github is False
    assert args.skip_apnic is False
    assert args.verbose is False


def test_custom_output_dir():
    parser = build_arg_parser()
    args = parser.parse_args(["--output-dir", "/tmp/routes"])
    assert args.output_dir == "/tmp/routes"


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


def _make_args(tmp_path, skip_apnic=False, skip_github=False, verbose=False):
    return Namespace(
        output_dir=str(tmp_path),
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
