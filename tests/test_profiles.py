"""Device profile loading tests."""

from ciscogen.profiles import REQUIRED_KEYS, DATA_DIR, load_profile_file

EXPECTED_MODELS = 36


def test_all_profiles_load(profiles):
    assert len(profiles) == EXPECTED_MODELS


def test_profiles_have_required_fields():
    for path in DATA_DIR.glob("*.json"):
        profile = load_profile_file(path)
        for key in REQUIRED_KEYS:
            assert getattr(profile, key) is not None, f"{path.name}: {key}"


def test_interface_lists_consistent(profiles):
    for profile in profiles.values():
        assert profile.interfaces, profile.model
        assert profile.interface_count == len(profile.interfaces)


def test_switch_router_split(profiles):
    switches = [p for p in profiles.values() if p.is_switch]
    routers = [p for p in profiles.values() if p.is_router]
    assert len(switches) == 17
    assert len(routers) == 19


def test_capability_expectations(profiles):
    c2960 = profiles["Catalyst 2960"]
    assert c2960.supports("layer2") and not c2960.supports("layer3")
    assert not c2960.supports("nat") and not c2960.supports("ospf")
    assert c2960.os_type == "IOS"

    c9300 = profiles["Catalyst 9300"]
    assert c9300.supports("layer3") and c9300.supports("svi")
    assert c9300.os_type == "IOS-XE"

    c9200 = profiles["Catalyst 9200"]
    assert not c9200.supports("bgp")
    assert c9200.warning_for("bgp")

    isr = profiles["Cisco ISR 4331"]
    assert isr.is_router and isr.supports("nat")
    assert isr.supports("subinterfaces") and not isr.supports("layer2")

    c3560 = profiles["Catalyst 3560"]
    assert c3560.supports("requires_trunk_encap")

    cbs = profiles["Cisco CBS350"]
    assert cbs.os_type == "IOS-like (CBS)"
    assert cbs.platform_warnings


def test_feature_warning_lookup(profiles):
    c2960 = profiles["Catalyst 2960"]
    assert c2960.warning_for("dai")
    assert c2960.warning_for("nonexistent-feature") is None
