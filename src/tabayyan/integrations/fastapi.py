from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from tabayyan import AuditLog, Guard, RedactionMode


@dataclass(frozen=True)
class RequestProtectionStats:
    """Summary of PII protection applied to an HTTP request."""

    pii_detected: bool
    redacted_count: int


class TabayyanPrivacyMiddleware:
    """ASGI middleware that redacts PII from JSON request bodies.

    The middleware is designed for FastAPI and Starlette applications. It keeps
    the core Tabayyan package local-first and provider-agnostic while making it
    easy to protect prompts before they reach application routes or LLM clients.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        destination: str = "local",
        mode: RedactionMode = RedactionMode.MASK,
        audit_path: str | None = None,
        block_cross_border: bool = False,
        include_response_headers: bool = True,
    ) -> None:
        self._app = app
        self._destination = destination
        self._include_response_headers = include_response_headers

        audit = AuditLog(path=audit_path) if audit_path else None
        self._guard = Guard(
            mode=mode,
            audit=audit,
            block_cross_border=block_cross_border,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        if not self._is_json_request(scope):
            await self._app(scope, receive, send)
            return

        body = await self._read_body(receive)
        protected_body, stats = self._protect_body(body)

        protected_scope = self._with_content_length(scope, len(protected_body))

        async def protected_receive() -> Message:
            return {
                "type": "http.request",
                "body": protected_body,
                "more_body": False,
            }

        async def protected_send(message: Message) -> None:
            if (
                self._include_response_headers
                and message["type"] == "http.response.start"
            ):
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (
                            b"x-tabayyan-pii-detected",
                            str(stats.pii_detected).lower().encode("utf-8"),
                        ),
                        (
                            b"x-tabayyan-redacted-count",
                            str(stats.redacted_count).encode("utf-8"),
                        ),
                    ]
                )
                message["headers"] = headers

            await send(message)

        await self._app(protected_scope, protected_receive, protected_send)

    def _is_json_request(self, scope: Scope) -> bool:
        headers = self._headers(scope)
        content_type = headers.get(b"content-type", b"").decode("latin-1").lower()

        return "application/json" in content_type

    def _protect_body(self, body: bytes) -> tuple[bytes, RequestProtectionStats]:
        if not body:
            return body, RequestProtectionStats(
                pii_detected=False,
                redacted_count=0,
            )

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return body, RequestProtectionStats(
                pii_detected=False,
                redacted_count=0,
            )

        protected_payload, redacted_count = self._protect_value(payload)

        protected_body = json.dumps(
            protected_payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        return protected_body, RequestProtectionStats(
            pii_detected=redacted_count > 0,
            redacted_count=redacted_count,
        )

    def _protect_value(self, value: Any) -> tuple[Any, int]:
        if isinstance(value, str):
            protected = self._guard.protect(
                value,
                destination=self._destination,
            )

            return protected.text, len(protected.matches)

        if isinstance(value, list):
            protected_items: list[Any] = []
            redacted_count = 0

            for item in value:
                protected_item, item_count = self._protect_value(item)
                protected_items.append(protected_item)
                redacted_count += item_count

            return protected_items, redacted_count

        if isinstance(value, dict):
            protected_dict: dict[str, Any] = {}
            redacted_count = 0

            for key, item in value.items():
                protected_item, item_count = self._protect_value(item)
                protected_dict[str(key)] = protected_item
                redacted_count += item_count

            return protected_dict, redacted_count

        return value, 0

    async def _read_body(self, receive: Receive) -> bytes:
        chunks: list[bytes] = []

        while True:
            message = await receive()

            if message["type"] == "http.disconnect":
                break

            chunks.append(message.get("body", b""))

            if not message.get("more_body", False):
                break

        return b"".join(chunks)

    def _headers(self, scope: Scope) -> Mapping[bytes, bytes]:
        return {
            key.lower(): value
            for key, value in scope.get("headers", [])
        }

    def _with_content_length(self, scope: Scope, body_length: int) -> Scope:
        headers = [
            (key, value)
            for key, value in scope.get("headers", [])
            if key.lower() != b"content-length"
        ]
        headers.append((b"content-length", str(body_length).encode("utf-8")))

        return {
            **scope,
            "headers": headers,
        }