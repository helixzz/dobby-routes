from unittest.mock import MagicMock, patch

import pytest
import requests

from dobby_routes.fetcher import (
    _USER_AGENT,
    APNIC_URL,
    CHNROUTES2_URL,
    GITHUB_CHINA_URL,
    GITHUB_OPERATOR_URLS,
    fetch_all_operators,
    fetch_apnic,
    fetch_chnroutes2,
    fetch_operator,
    fetch_url,
)


def test_apnic_url_format():
    assert APNIC_URL.startswith("https://")
    assert "apnic" in APNIC_URL


def test_github_operator_urls_contains_expected_keys():
    assert "chinanet" in GITHUB_OPERATOR_URLS
    assert "unicom" in GITHUB_OPERATOR_URLS
    assert "cmcc" in GITHUB_OPERATOR_URLS
    assert "cernet" in GITHUB_OPERATOR_URLS


def test_github_operator_urls_are_https():
    for url in GITHUB_OPERATOR_URLS.values():
        assert url.startswith("https://")


def test_github_china_url_format():
    assert GITHUB_CHINA_URL.startswith("https://")
    assert "china" in GITHUB_CHINA_URL


def test_chnroutes2_url_format():
    assert CHNROUTES2_URL.startswith("https://")
    assert "chnroutes" in CHNROUTES2_URL


def test_fetch_url_returns_text():
    mock_response = MagicMock()
    mock_response.text = "192.168.0.0/16\n"
    mock_response.raise_for_status = MagicMock()

    with patch("dobby_routes.fetcher.requests.get", return_value=mock_response) as mock_get:
        result = fetch_url("https://example.com/data.txt")

    assert result == "192.168.0.0/16\n"
    mock_get.assert_called_once_with(
        "https://example.com/data.txt",
        timeout=30,
        headers={"User-Agent": _USER_AGENT},
    )


def test_fetch_url_calls_raise_for_status():
    mock_response = MagicMock()
    mock_response.text = "data"

    with patch("dobby_routes.fetcher.requests.get", return_value=mock_response):
        fetch_url("https://example.com/")

    mock_response.raise_for_status.assert_called_once()


def test_fetch_url_custom_timeout():
    mock_response = MagicMock()
    mock_response.text = "data"
    mock_response.raise_for_status = MagicMock()

    with patch("dobby_routes.fetcher.requests.get", return_value=mock_response) as mock_get:
        fetch_url("https://example.com/", timeout=10)

    mock_get.assert_called_once_with(
        "https://example.com/",
        timeout=10,
        headers={"User-Agent": _USER_AGENT},
    )


def test_fetch_apnic_uses_apnic_url():
    mock_response = MagicMock()
    mock_response.text = "apnic data"
    mock_response.raise_for_status = MagicMock()

    with patch("dobby_routes.fetcher.requests.get", return_value=mock_response) as mock_get:
        result = fetch_apnic()

    assert result == "apnic data"
    args, _ = mock_get.call_args
    assert args[0] == APNIC_URL


def test_fetch_operator_known():
    mock_response = MagicMock()
    mock_response.text = "chinanet data"
    mock_response.raise_for_status = MagicMock()

    with patch("dobby_routes.fetcher.requests.get", return_value=mock_response):
        result = fetch_operator("chinanet")

    assert result == "chinanet data"


def test_fetch_operator_unknown_raises_value_error():
    with pytest.raises(ValueError, match="Unknown operator"):
        fetch_operator("unknown_operator_xyz")


def test_fetch_all_operators_returns_all_keys():
    mock_response = MagicMock()
    mock_response.text = "data"
    mock_response.raise_for_status = MagicMock()

    with patch("dobby_routes.fetcher.requests.get", return_value=mock_response):
        result = fetch_all_operators()

    assert set(result.keys()) == set(GITHUB_OPERATOR_URLS.keys())


def test_fetch_all_operators_values_are_strings():
    mock_response = MagicMock()
    mock_response.text = "some content"
    mock_response.raise_for_status = MagicMock()

    with patch("dobby_routes.fetcher.requests.get", return_value=mock_response):
        result = fetch_all_operators()

    assert all(isinstance(v, str) for v in result.values())


def test_fetch_chnroutes2_uses_chnroutes2_url():
    mock_response = MagicMock()
    mock_response.text = "chnroutes data"
    mock_response.raise_for_status = MagicMock()

    with patch("dobby_routes.fetcher.requests.get", return_value=mock_response) as mock_get:
        result = fetch_chnroutes2()

    assert result == "chnroutes data"
    args, _ = mock_get.call_args
    assert args[0] == CHNROUTES2_URL


@patch("dobby_routes.fetcher.time.sleep")
def test_fetch_url_retries_on_connection_error(mock_sleep):
    mock_response = MagicMock()
    mock_response.text = "ok"
    mock_response.raise_for_status = MagicMock()

    with patch(
        "dobby_routes.fetcher.requests.get",
        side_effect=[requests.ConnectionError("fail"), mock_response],
    ):
        result = fetch_url("https://example.com/", retries=2)

    assert result == "ok"
    mock_sleep.assert_called_once_with(1)


@patch("dobby_routes.fetcher.time.sleep")
def test_fetch_url_raises_after_all_retries_exhausted(mock_sleep):
    with patch(
        "dobby_routes.fetcher.requests.get",
        side_effect=requests.ConnectionError("fail"),
    ):
        with pytest.raises(requests.ConnectionError):
            fetch_url("https://example.com/", retries=3)

    assert mock_sleep.call_count == 2


def test_fetch_url_no_retry_on_success():
    mock_response = MagicMock()
    mock_response.text = "data"
    mock_response.raise_for_status = MagicMock()

    with patch("dobby_routes.fetcher.requests.get", return_value=mock_response) as mock_get:
        fetch_url("https://example.com/", retries=3)

    mock_get.assert_called_once()


@patch("dobby_routes.fetcher.time.sleep")
def test_fetch_url_retries_on_http_error(mock_sleep):
    error = requests.HTTPError(response=MagicMock(status_code=500))
    mock_response = MagicMock()
    mock_response.text = "recovered"
    mock_response.raise_for_status = MagicMock()

    with patch(
        "dobby_routes.fetcher.requests.get",
        side_effect=[MagicMock(raise_for_status=MagicMock(side_effect=error)), mock_response],
    ):
        result = fetch_url("https://example.com/", retries=2)

    assert result == "recovered"
