from __future__ import annotations

import json
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from tabayyan import AuditLog, Guard, RedactionMode


DEFAULT_MAX_BODY_SIZE = 1_000_000


@dataclass(frozen=True)
class RequestProtectionStats:
    """Summary of PII protection applied to an HTTP request."""

    pii_detected: bool
    redacted_count: int


class RequestBodyTooLarge(Exception):
    """Raised when an HTTP request body exceeds the configured safety limit."""

    def __init__(self, max_body_size: int) -> None:
        self.max_body_size = max_body_size
        super().__init__(f"Request body exceeds max_body_size={max_body_size}")


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
        max_body_size: int | None = DEFAULT_MAX_BODY_SIZE,
        include_fields: Collection[str] | None = None,
        exclude_fields: Collection[str] | None = None,
    ) -> None:
        if max_body_size is not None and max_body_size < 0:
            raise ValueError("max_body_size must be a non-negative integer or None")

        self._app = app
        self._destination = destination
        self._include_response_headers = include_response_headers
        self._max_body_size = max_body_size
        self._include_fields = self._normalize_fields(include_fields)
        self._exclude_fields = self._normalize_fields(exclude_fields)

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

        if self._request_is_too_large_from_headers(scope):
            await self._send_payload_too_large(send)
            return

        try:
            body = await self._read_body(receive)
        except RequestBodyTooLarge:
            await self._send_payload_too_large(send)
            return

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

    def _request_is_too_large_from_headers(self, scope: Scope) -> bool:
        if self._max_body_size is None:
            return False

        content_length = self._content_length(scope)

        return content_length is not None and content_length > self._max_body_size

    def _content_length(self, scope: Scope) -> int | None:
        headers = self._headers(scope)
        raw_content_length = headers.get(b"content-length")

        if raw_content_length is None:
            return None

        try:
            return int(raw_content_length.decode("latin-1"))
        except ValueError:
            return None

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

    def _protect_value(
        self,
        value: Any,
        *,
        field_name: str | None = None,
        force_protect: bool = False,
    ) -> tuple[Any, int]:
        if isinstance(value, str):
            if not self._should_protect_field(field_name, force_protect):
                return value, 0

            protected = self._guard.protect(
                value,
                destination=self._destination,
            )

            return protected.text, len(protected.matches)

        if isinstance(value, list):
            protected_items: list[Any] = []
            redacted_count = 0

            for item in value:
                protected_item, item_count = self._protect_value(
                    item,
                    field_name=field_name,
                    force_protect=force_protect,
                )
                protected_items.append(protected_item)
                redacted_count += item_count

            return protected_items, redacted_count

        if isinstance(value, dict):
            protected_dict: dict[str, Any] = {}
            redacted_count = 0

            for key, item in value.items():
                key_name = str(key)

                if self._field_is_excluded(key_name):
                    protected_dict[key_name] = item
                    continue

                protected_item, item_count = self._protect_value(
                    item,
                    field_name=key_name,
                    force_protect=(
                        force_protect or self._field_is_included(key_name)
                    ),
                )
                protected_dict[key_name] = protected_item
                redacted_count += item_count

            return protected_dict, redacted_count

        return value, 0

    def _should_protect_field(
        self,
        field_name: str | None,
        force_protect: bool,
    ) -> bool:
        if self._field_is_excluded(field_name):
            return False

        if force_protect:
            return True

        if self._include_fields is None:
            return True

        return self._field_is_included(field_name)

    def _field_is_included(self, field_name: str | None) -> bool:
        if self._include_fields is None or field_name is None:
            return False

        return self._normalize_field(field_name) in self._include_fields

    def _field_is_excluded(self, field_name: str | None) -> bool:
        if self._exclude_fields is None or field_name is None:
            return False

        return self._normalize_field(field_name) in self._exclude_fields

    def _normalize_fields(
        self,
        fields: Collection[str] | None,
    ) -> set[str] | None:
        if fields is None:
            return None

        if isinstance(fields, str):
            return {self._normalize_field(fields)}

        return {
            self._normalize_field(field)
            for field in fields
        }

    def _normalize_field(self, field: str) -> str:
        return str(field).strip().lower()

    async def _read_body(self, receive: Receive) -> bytes:
        chunks: list[bytes] = []
        body_size = 0

        while True:
            message = await receive()

            if message["type"] == "http.disconnect":
                break

            chunk = message.get("body", b"")
            body_size += len(chunk)

            if (
                self._max_body_size is not None
                and body_size > self._max_body_size
            ):
                raise RequestBodyTooLarge(self._max_body_size)

            chunks.append(chunk)

            if not message.get("more_body", False):
                break

        return b"".join(chunks)

    async def _send_payload_too_large(self, send: Send) -> None:
        body = b'{"detail":"Request body too large"}'

        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("utf-8")),
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": body,
                "more_body": False,
            }
        )

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