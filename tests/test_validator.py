import pytest
from netaddr import IPSet

from dobby_routes.validator import validate_canaries, validate_drift


def test_validate_canaries_passes_when_all_match():
    fwd = IPSet(["114.114.114.0/24", "223.5.5.0/24"])
    inv = IPSet(["1.1.1.0/24", "8.8.8.0/24"])

    validate_canaries(
        fwd,
        inv,
        cn_canaries=[("114.114.114.114", "114DNS"), ("223.5.5.5", "AliDNS")],
        foreign_canaries=[("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google")],
        table_name="IPv4",
    )


def test_validate_canaries_fails_when_cn_missing_or_foreign_leaked():
    fwd = IPSet(["1.1.1.0/24"])
    inv = IPSet(["114.114.114.0/24"])

    with pytest.raises(ValueError, match="Canary validation failed") as exc_info:
        validate_canaries(
            fwd,
            inv,
            cn_canaries=[("114.114.114.114", "114DNS")],
            foreign_canaries=[("1.1.1.1", "Cloudflare")],
            table_name="IPv4",
        )
    msg = str(exc_info.value)
    assert "CN canary missing from forward: 114.114.114.114" in msg
    assert "foreign canary leaked into forward: 1.1.1.1" in msg


def test_validate_drift_passes_within_limit():
    baseline = {"ipv4": {"forward": 5000, "inverse": 12000, "addresses": 340000000}}
    current = {"ipv4": {"forward": 5200, "inverse": 12500, "addresses": 345000000}}
    validate_drift(current, baseline, max_drift_pct=15.0)


def test_validate_drift_fails_when_exceeding_limit():
    baseline = {"ipv4": {"forward": 5000, "inverse": 12000}}
    current = {"ipv4": {"forward": 3000, "inverse": 12000}}
    with pytest.raises(ValueError, match=r"ipv4\.forward drifted 40\.00%"):
        validate_drift(current, baseline, max_drift_pct=15.0)


def test_validate_drift_ignores_new_sections_not_in_baseline():
    baseline = {"ipv4": {"forward": 5000}}
    current = {"ipv4": {"forward": 5050}, "ipv4_bgp": {"forward": 2700}}
    validate_drift(current, baseline, max_drift_pct=10.0)


def test_validate_drift_rejects_negative_limit():
    with pytest.raises(ValueError, match="non-negative"):
        validate_drift({}, {}, max_drift_pct=-1.0)
