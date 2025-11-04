import ipaddress

from indico_payment_niubiz.security import ip_in_whitelist, parse_ip_list


def test_parse_ip_list_and_membership():
    networks = parse_ip_list(["10.0.0.0/24", "192.168.1.10"])
    assert any(isinstance(net, ipaddress.IPv4Network) for net in networks)
    assert ip_in_whitelist("10.0.0.42", networks)
    assert not ip_in_whitelist("10.0.1.1", networks)


def test_invalid_entries_are_ignored(caplog):
    caplog.set_level("WARNING")
    networks = parse_ip_list(["invalid", "200.48.119.0/24"])
    assert len(networks) == 1
    assert "Ignoring invalid Niubiz callback IP range" in caplog.text
