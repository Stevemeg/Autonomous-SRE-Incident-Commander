"""Phase 15.19: SSRF / egress campaign over URL normalisation, and the two layers' agreement.

Egress targets are administrator configuration (connector rows, JWKS URL, OTLP endpoint) -
never user- or model-supplied - but a hostile or mistaken configuration value is exactly how
SSRF happens. Two independent layers must refuse the same dangerous destinations:

* the application's ``validate_endpoint``/``check_egress_host`` (every outbound call); and
* the deployment renderer's CIDR policy for the NetworkPolicy egress allow-list (N-3).

Explicit non-claim: DNS rebinding (a public name that later resolves to a private or metadata
address) is *not* prevented by the application - it validates names, not resolutions. That is
the network policy / DNS-aware egress gateway's job, and a test below pins the limitation so
it can never be silently re-described as a control.
"""

from __future__ import annotations

import ipaddress

import pytest
from scripts.render_deployment import check_egress_cidr

from asic.domain.errors import IntegrationError
from asic.integrations.transport import (
    HttpClientTransport,
    HttpRequest,
    check_egress_host,
    validate_endpoint,
)
from tests.integrations.local_http import Scripted, local_server

pytestmark = pytest.mark.security

REFUSED_URLS = {
    # metadata and link-local in every spelling
    "metadata_v4": "https://169.254.169.254/latest/meta-data/",
    "metadata_v4_mapped": "https://[::ffff:169.254.169.254]/",
    "metadata_v4_mapped_hex": "https://[::ffff:a9fe:a9fe]/",
    "metadata_ipv6_ec2": "https://[fd00:ec2::254]/",
    "metadata_name": "https://metadata.google.internal/computeMetadata/v1/",
    "decimal": "https://2852039166/",
    "hex": "https://0xA9FEA9FE/",
    "octal_dotted": "https://0251.0376.0251.0376/",
    "short_form": "https://169.254.43518/",
    "link_local_v6": "https://[fe80::1]/",
    "link_local_v6_zone": "https://[fe80::1%25eth0]/",
    "unspecified_v4": "https://0.0.0.0/",
    "unspecified_v6": "https://[::]/",
    "multicast": "https://224.0.0.1/",
    # parser-confusion tricks
    "userinfo": "https://good.example@169.254.169.254/",
    "userinfo_encoded": "https://169.254.169.254%2f@good.example/",
    "fragment": "https://good.example#@169.254.169.254/",
    "query": "https://good.example/?next=http://169.254.169.254/",
    "percent_host": "https://%31%36%39.254.169.254/",
    "backslash": "https://good.example\\@169.254.169.254/",
    "whitespace": "https://good.example /",
    "control": "https://good.example\x00.evil/",
    "idn_lookalike": "https://g" + chr(0x43E) * 2 + "d.example/",  # Cyrillic o
    "underscore": "https://a_b.example/",
    "empty_label": "https://good..example/",
    # scheme abuse
    "plain_http_remote": "http://api.slack.com/",
    "file_scheme": "file:///etc/passwd",
    "gopher": "gopher://good.example:70/",
}


@pytest.mark.parametrize("url", list(REFUSED_URLS.values()), ids=list(REFUSED_URLS))
def test_dangerous_endpoints_are_refused_before_any_connection(url: str) -> None:
    with pytest.raises(IntegrationError) as refused:
        validate_endpoint(url, allow_loopback_http=False)
    assert refused.value.effect_not_applied


@pytest.mark.parametrize(
    "url",
    [
        "https://hooks.slack.com/services",
        "https://api.pagerduty.example/v2",
        "https://xn--bcher-kva.example/",  # punycode is the legitimate IDN form
        "https://10.20.0.12:8443/",  # on-premises / in-cluster targets are legitimate
        "https://prometheus.monitoring.svc:9090",
    ],
)
def test_legitimate_endpoints_are_accepted(url: str) -> None:
    validate_endpoint(url, allow_loopback_http=False)


def test_the_application_and_network_layers_agree_on_special_addresses() -> None:
    """Every IP literal the application refuses as special-purpose is also refused by the
    deployment's egress CIDR policy - the two layers cannot drift apart silently."""
    literals = [
        "169.254.169.254",
        "169.254.0.1",
        "224.0.0.1",
        "0.0.0.0",
        "::",
        "fe80::1",
        "::ffff:169.254.169.254",
    ]
    for literal in literals:
        with pytest.raises(IntegrationError):
            check_egress_host(literal)
        network = ipaddress.ip_network(literal)
        with pytest.raises(ValueError):
            check_egress_cidr(str(network))


def test_redirects_are_never_followed() -> None:
    """A trusted endpoint answering 302 -> metadata cannot steer the request anywhere."""
    with local_server() as server:
        server.route(
            "GET",
            "/api/v1/query_range",
            Scripted(status=302, headers={"Location": "http://169.254.169.254/latest/"}),
        )
        endpoint = validate_endpoint(server.url, allow_loopback_http=True)
        response = HttpClientTransport().send(
            HttpRequest(method="GET", endpoint=endpoint, path="/api/v1/query_range"),
            timeout_seconds=5,
        )
        assert response.status == 302  # returned as-is, not followed
        assert len(server.requests) == 1


def test_dns_rebinding_is_not_an_application_control() -> None:
    """Documented limitation, pinned: a public-looking name is accepted whatever it later
    resolves to. Resolution-time egress control is the NetworkPolicy / DNS-aware egress
    gateway (docs/deployment/PHASE14_DEPLOYMENT.md), never this function."""
    validate_endpoint("https://rebind.attacker.example/", allow_loopback_http=False)
