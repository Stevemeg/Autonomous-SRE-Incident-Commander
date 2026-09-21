"""Phase 13 secret-handling proof (carry-forward F-16).

The defence is layered and the layers are tested separately so that none can silently stand
in for another:

1. **Typed** - a ``SecretValue`` (``NeverRender``) is redacted by type wherever it appears.
2. **Structural** - request/response objects never render credentials or bodies.
3. **Name-based** - a key that names a secret is replaced whatever its value looks like.
4. **Shape-based** - a secret-shaped value under an innocuous key is replaced (backup only).

No layer promises perfect detection; a secret with no marker, no telling key and no known
shape can still be logged by code that formats it by hand. The primary rule (recorded in
``docs/security/SECRETS_POLICY.md``) is that secret-bearing structures are never passed to a
logger at all.
"""

from __future__ import annotations

import io
import json
import logging
import pickle

import pytest

from asic.integrations.credentials import SecretValue
from asic.integrations.transport import Endpoint, HttpRequest, HttpResponse
from asic.observability.logging import JsonFormatter, log_event
from asic.observability.redaction import (
    REDACTED,
    is_secret_key_name,
    looks_like_secret,
    redact_arguments,
    redact_mapping,
    redact_value,
)

pytestmark = pytest.mark.security

CANARY = "canary-secret-7f3a91-DO-NOT-LEAK"


class TestTypedRedaction:
    def test_a_secret_value_is_redacted_under_any_key_and_at_any_depth(self) -> None:
        secret = SecretValue(CANARY)
        payload = {
            "note": secret,
            "nested": {"list": [1, secret, {"deep": secret}]},
            "tuple": (secret,),
        }
        rendered = json.dumps(redact_mapping(payload))
        assert CANARY not in rendered
        assert rendered.count(REDACTED) == 4

    def test_a_secret_value_never_renders_or_serialises(self) -> None:
        secret = SecretValue(CANARY)
        for text in (repr(secret), str(secret), f"{secret}", f"{secret!r}", "%s" % secret):  # noqa: UP031
            assert CANARY not in text
        with pytest.raises(TypeError):
            pickle.dumps(secret)
        with pytest.raises(TypeError):
            hash(secret)

    def test_raw_bytes_are_never_rendered(self) -> None:
        rendered = json.dumps(redact_mapping({"body": CANARY.encode(), "b": bytearray(b"xyz")}))
        assert CANARY not in rendered
        assert "bytes]" in rendered


class TestStructuralRedaction:
    def _request(self) -> HttpRequest:
        return HttpRequest(
            method="POST",
            endpoint=Endpoint("https", "hooks.example.invalid", 443, ""),
            path="/v1/x",
            query=(("sig", CANARY),),
            headers=(("Authorization", f"Bearer {CANARY}"),),
            body=json.dumps({"token": CANARY}).encode(),
        )

    def test_a_request_never_renders_credentials_query_or_body(self) -> None:
        request = self._request()
        for text in (repr(request), str(request), f"{request}", request.describe()):
            assert CANARY not in text

    def test_a_response_never_renders_headers_or_body(self) -> None:
        response = HttpResponse(status=200, headers={"set-cookie": CANARY}, body=CANARY.encode())
        assert CANARY not in repr(response)

    def test_logging_a_request_object_cannot_leak_it(self) -> None:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(JsonFormatter(service="test"))
        logger = logging.getLogger("asic.test.structural")
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.DEBUG)
        log_event(
            logger,
            "outbound.failed",
            request=self._request(),
            secret=SecretValue(CANARY),
            error=RuntimeError(CANARY),
        )
        line = stream.getvalue()
        assert CANARY not in line
        assert len(line.strip().splitlines()) == 1


class TestNameBasedRedaction:
    @pytest.mark.parametrize(
        "key",
        [
            "password",
            "token",
            "client_secret",
            "bot_token",
            "slack_webhook_url",
            "webhook_url",
            "db_password",
            "x-api-key",
            "Authorization",
            "Set-Cookie",
            "pagerduty_routing_key",
            "signing_key",
            "service_account_credentials",
        ],
    )
    def test_secret_naming_keys_are_replaced(self, key: str) -> None:
        assert is_secret_key_name(key)
        assert redact_mapping({key: CANARY}) == {key: REDACTED}

    @pytest.mark.parametrize(
        "key",
        [
            "total_tokens",
            "input_tokens",
            "token_count",
            "max_tokens",
            "credential_ref",
            "secret_ref",
            "idempotency_key",
            "sort_key",
            "cache_key",
            "environment",
        ],
    )
    def test_ordinary_and_reference_keys_are_preserved(self, key: str) -> None:
        assert not is_secret_key_name(key) or key in {"credential_ref", "secret_ref"}
        assert redact_mapping({key: "value-1"})[key] == "value-1"

    def test_arguments_are_redacted_before_persistence(self) -> None:
        stored = redact_arguments({"channel": "C123", "webhook_url": CANARY, "count": 3})
        assert CANARY not in json.dumps(stored)
        assert stored["channel"] == "C123" and stored["count"] == 3


class TestShapeBasedRedaction:
    @pytest.mark.parametrize(
        "value",
        [
            # Assembled at import so no scanner (or grep) sees a webhook-shaped literal.
            "https://hooks." + "slack.com/services/" + "T00000000/B00000000/" + "X" * 24,
            "https://contoso.webhook."
            + "office.com/webhookb2/"
            + "aaaa-bbbb@cccc/IncomingWebhook/abcdef/12345",
            "https://prod-12.westus.logic.azure.com/workflows/abc?api-version=1&sig=abcdef123456",
            "GET https://api.example.invalid/v1/x?access_token=abcdef123456&y=1",
            "https://api.example.invalid/x?X-Amz-Signature=deadbeefcafe0123",
            "xox" + "b-1234567890-" + "abcdefghijk",
            "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789",
            "github" + "_pat_11ABCDEFG0123456789_" + "abcdefghijklmnop",
            "AIzaSyA-1234567890abcdefghijklmnopqrstuv",
            "ATATT3xFfGF0abcdefghijklmnopqrstuvwx=1234",
            "Authorization: " + "Bear" + "er abcdefghijklmnop1234",
            "postgresql" + "://asic:" + "hunter2hunter2" + "@db.internal:5432/asic",
            "-----BEGIN " + "RSA PRIVATE " + "KEY-----",
        ],
    )
    def test_secret_shaped_values_are_replaced_under_an_innocuous_key(self, value: str) -> None:
        assert looks_like_secret(value), value
        assert redact_mapping({"note": value}) == {"note": REDACTED}
        assert redact_value(f"prefix {value} suffix") == REDACTED

    @pytest.mark.parametrize(
        "value",
        [
            "GET /api/v1/incidents?limit=50&cursor=abc",
            "deploy checkout-api revision 42 succeeded",
            "https://grafana.example.invalid/d/abc/overview",
            "token bucket refilled",
            "the key is to restart the pod",
        ],
    )
    def test_ordinary_text_is_not_over_redacted(self, value: str) -> None:
        assert not looks_like_secret(value), value
        assert redact_value(value) == value

    def test_shape_rules_are_documented_as_a_backup_not_a_guarantee(self) -> None:
        """An unmarked, unnamed, unshaped secret survives: that limit is deliberate to state.

        Nothing here claims detection is complete. The guarantee is the typed/structural
        layers plus never passing secret-bearing structures to a logger.
        """
        assert redact_value("correct horse battery staple") == "correct horse battery staple"
