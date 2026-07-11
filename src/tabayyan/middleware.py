"""Middleware + audit layer.

Sits between an application and an LLM endpoint: scans a prompt, redacts
personal data before it leaves, and emits a structured audit record. The
record is the compensating-control evidence — what was detected, what was
redacted, the data categories involved, and whether the destination
constitutes a cross-border transfer.

Stdlib only. Provider-agnostic: the OpenAI/Azure wrapper is duck-typed and
imports nothing — you pass your own client.

Cross-border logic (the PDPL Art. 29 trigger): if personal data is present
AND the destination endpoint is not in-Kingdom, the call is flagged as a
cross-border transfer event. "In-Kingdom" is determined by a `.sa` host or
an explicit allowlist you configure — until your in-Kingdom endpoint is
live, external endpoints (e.g. *.openai.azure.com) are flagged.
"""
from __future__ import annotations

import ipaddress
import json
import os
import threading
import warnings
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable, Sequence
from urllib.parse import urlparse

from .engine import DetectionEngine
from .entities import Category, Match
from .ndmo import classification_summary, classify
from .redaction import RedactionMode, RedactionResult, redact, restore

_PERSONAL_CATEGORIES = {
    Category.NATIONAL_IDENTIFIER, Category.FINANCIAL, Category.CONTACT,
    Category.SENSITIVE_HEALTH, Category.PERSON,
}


class UnscannedContentWarning(UserWarning):
    """A message or content part was passed through without scanning.

    Emitted (by default) when ``protect_messages`` receives a shape it does
    not understand — e.g. a typed SDK object instead of a plain dict. Silence
    with ``Guard(on_unrecognized="pass")`` or fail closed with
    ``Guard(on_unrecognized="error")``.
    """


def host_of(destination: str | None) -> str | None:
    if not destination:
        return None
    if "://" not in destination:
        destination = "//" + destination
    host = urlparse(destination).hostname
    return host.lower() if host else None


def is_in_kingdom(destination: str | None, allowlist: Sequence[str] = ()) -> bool | None:
    """True/False/None(unknown). A `.sa` host or an allowlisted host is in-Kingdom."""
    host = host_of(destination)
    if host is None:
        return None
    if host.endswith(".sa") or host == "sa":
        return True
    allow = {h.lower() for h in allowlist}
    if host in allow or any(host.endswith("." + h) for h in allow):
        return True
    return False


# Hostnames that mean "this process / this machine" rather than a network
# destination. Data sent there never leaves the environment, so it cannot
# constitute a cross-border transfer.
_LOCAL_HOSTS = {"local", "localhost"}


def is_local_destination(destination: str | None) -> bool:
    """True when the destination cannot be a cross-border transfer target:
    no destination at all, the documented ``"local"`` placeholder,
    ``localhost``, or a loopback IP (127.0.0.0/8, ``::1``).

    Unparseable hosts return False so unknown destinations stay conservative
    (flagged, not silently trusted).
    """
    if destination is None:
        return True
    host = host_of(destination)
    if host is None:
        return False
    if host in _LOCAL_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass
class AuditRecord:
    timestamp: str
    destination: str | None
    destination_host: str | None
    in_kingdom: bool | None
    cross_border_transfer: bool
    action: str                     # allow | redact | block
    personal_data_present: bool
    health_data_present: bool
    entity_summary: dict            # entity_type -> count
    category_summary: dict          # category -> count
    redacted: bool
    blocked: bool
    data_classification: str | None = None   # highest NDMO level present
    classification_summary: dict = field(default_factory=dict)  # level -> count
    values: list | None = None      # raw values, only if explicitly enabled
    destination_scope: str = "unknown"  # none | local | in_kingdom | external | unknown

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


@dataclass
class ProtectResult:
    text: str
    audit: AuditRecord
    blocked: bool
    vault: dict = field(default_factory=dict)
    matches: list = field(default_factory=list)


class AuditLog:
    """Append-only audit sink. Writes JSONL to a path and/or a callable.

    File safety: the JSONL file is created with owner-only permissions
    (0600) where the platform supports POSIX modes; on Windows this is
    advisory (NTFS ACLs govern access — restrict the containing directory).
    Writes within one process are serialized with a lock. Across processes
    the file is opened in append mode but lines are not locked: run one
    writer per audit file, or point each process at its own path.
    """

    def __init__(self, path: str | None = None, sink: Callable[[AuditRecord], None] | None = None):
        self.path = path
        self.sink = sink
        self.records: list[AuditRecord] = []
        self._lock = threading.Lock()

    def record(self, rec: AuditRecord) -> None:
        line = rec.to_json() + "\n"
        with self._lock:
            self.records.append(rec)
            if self.path:
                # O_APPEND for atomic-append semantics; 0600 so a fresh audit
                # file is never world-readable (mode applies at creation).
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(line)
        if self.sink:
            self.sink(rec)


class Guard:
    """Scan -> decide -> redact/block -> audit.

    block_categories: if any detected entity falls in these categories the
        call is blocked (action='block', text not forwarded).
    block_cross_border: block (instead of redact) when a cross-border
        transfer of personal data would occur.
    """

    def __init__(
        self,
        engine: DetectionEngine | None = None,
        mode: RedactionMode | str = RedactionMode.MASK,
        in_kingdom_hosts: Sequence[str] = (),
        block_categories: Iterable[Category] = (),
        block_cross_border: bool = False,
        audit: AuditLog | None = None,
        record_values: bool = False,
        salt: str = "",
        on_unrecognized: str = "warn",
    ) -> None:
        if on_unrecognized not in ("warn", "error", "pass"):
            raise ValueError(
                f"on_unrecognized must be 'warn', 'error', or 'pass', "
                f"got {on_unrecognized!r}"
            )
        self.engine = engine or DetectionEngine()
        self.mode = RedactionMode(mode)
        self.in_kingdom_hosts = list(in_kingdom_hosts)
        self.block_categories = set(block_categories)
        self.block_cross_border = block_cross_border
        self.audit = audit
        self.record_values = record_values
        self.salt = salt
        self.on_unrecognized = on_unrecognized

    def _unrecognized(self, what: str) -> None:
        """Apply the on_unrecognized policy to an unscannable shape.

        Silence is the wrong failure mode for a privacy gateway: a message
        the guard does not understand looks protected but is not.
        """
        message = (
            f"tabayyan: {what} was passed through WITHOUT scanning. "
            "protect_messages understands dict messages whose content is a "
            "string or a list of dict parts. Convert typed SDK objects to "
            "plain dicts, or set Guard(on_unrecognized='pass') to silence "
            "this warning / 'error' to fail closed."
        )
        if self.on_unrecognized == "error":
            raise ValueError(message)
        if self.on_unrecognized == "warn":
            warnings.warn(message, UnscannedContentWarning, stacklevel=4)

    def inspect(self, text: str) -> list[Match]:
        return self.engine.scan(text)

    def protect(self, text: str, destination: str | None = None) -> ProtectResult:
        matches = self.engine.scan(text)
        categories = {m.category for m in matches}
        personal = bool(categories & _PERSONAL_CATEGORIES)
        health = Category.SENSITIVE_HEALTH in categories

        in_kingdom = is_in_kingdom(destination, self.in_kingdom_hosts)
        local = is_local_destination(destination)
        # Cross-border requires personal data AND a real external destination.
        # Local destinations (no destination, "local", localhost, loopback)
        # never leave the environment; unknown external hosts stay flagged
        # (fail closed).
        cross_border = bool(personal and not local and in_kingdom is not True)
        if destination is None:
            destination_scope = "none"
        elif local:
            destination_scope = "local"
        elif in_kingdom is True:
            destination_scope = "in_kingdom"
        elif in_kingdom is False:
            destination_scope = "external"
        else:
            destination_scope = "unknown"

        block = bool(self.block_categories & categories) or (cross_border and self.block_cross_border)

        vault: dict = {}
        if block:
            # Blocked means "do not forward". We still hand back text for logging
            # context, but it is MASK-redacted, never the raw original: a caller
            # that mistakenly forwards `result.text` must not leak PII. MASK is
            # used regardless of self.mode so this path never needs a salt.
            out_text = redact(text, matches, RedactionMode.MASK).text if matches else text
            action = "block"
            redacted = False
        elif matches:
            result: RedactionResult = redact(text, matches, self.mode, salt=self.salt)
            out_text = result.text
            vault = result.vault
            action = "redact"
            redacted = True
        else:
            out_text = text
            action = "allow"
            redacted = False

        rec = AuditRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            destination=destination,
            destination_host=host_of(destination),
            in_kingdom=in_kingdom,
            cross_border_transfer=cross_border,
            action=action,
            personal_data_present=personal,
            health_data_present=health,
            entity_summary=_count(m.entity_type.value for m in matches),
            category_summary=_count(m.category.value for m in matches),
            redacted=redacted,
            blocked=block,
            data_classification=(c.value if (c := classify(matches)) else None),
            classification_summary=classification_summary(matches),
            values=[m.value for m in matches] if self.record_values else None,
            destination_scope=destination_scope,
        )
        if self.audit:
            self.audit.record(rec)
        return ProtectResult(text=out_text, audit=rec, blocked=block, vault=vault, matches=matches)

    def _protect_json(self, value, destination, audits, vault):
        """Recursively redact every string inside a JSON-like structure.

        Used for tool payloads (OpenAI function arguments after decoding,
        Anthropic tool_use input) where PII can hide in nested values.
        Returns (protected_value, blocked). Builds new containers — caller
        data is never mutated.
        """
        if isinstance(value, str) and value:
            pr = self.protect(value, destination=destination)
            audits.append(pr.audit)
            vault.update(pr.vault)
            return pr.text, pr.blocked
        if isinstance(value, list):
            out, blocked = [], False
            for item in value:
                new_item, item_blocked = self._protect_json(
                    item, destination, audits, vault
                )
                out.append(new_item)
                blocked = blocked or item_blocked
            return out, blocked
        if isinstance(value, dict):
            out_d, blocked = {}, False
            for k, item in value.items():
                new_item, item_blocked = self._protect_json(
                    item, destination, audits, vault
                )
                out_d[k] = new_item
                blocked = blocked or item_blocked
            return out_d, blocked
        return value, False

    def _protect_part(self, part, destination, audits, vault):
        """Protect one content part (multimodal block). Returns (part, blocked)."""
        if not isinstance(part, dict):
            self._unrecognized(f"content part of type {type(part).__name__!r}")
            return part, False
        if isinstance(part.get("text"), str) and part["text"]:
            pr = self.protect(part["text"], destination=destination)
            audits.append(pr.audit)
            vault.update(pr.vault)
            return {**part, "text": pr.text}, pr.blocked
        # Anthropic tool_use: PII can sit anywhere in the input payload.
        if part.get("type") == "tool_use" and isinstance(part.get("input"), (dict, list)):
            new_input, blocked = self._protect_json(
                part["input"], destination, audits, vault
            )
            return {**part, "input": new_input}, blocked
        # Anthropic tool_result: content is a string or a list of parts.
        if part.get("type") == "tool_result":
            inner = part.get("content")
            if isinstance(inner, str) and inner:
                pr = self.protect(inner, destination=destination)
                audits.append(pr.audit)
                vault.update(pr.vault)
                return {**part, "content": pr.text}, pr.blocked
            if isinstance(inner, list):
                new_inner, blocked = [], False
                for sub in inner:
                    new_sub, sub_blocked = self._protect_part(
                        sub, destination, audits, vault
                    )
                    new_inner.append(new_sub)
                    blocked = blocked or sub_blocked
                return {**part, "content": new_inner}, blocked
        # Non-text parts (image blocks, etc.) are intentionally preserved.
        return part, False

    def _protect_tool_calls(self, msg, destination, audits, vault):
        """Redact OpenAI-style tool/function call arguments. Returns
        (updated_message, blocked). The arguments field is a JSON-encoded
        string; PII inside it would otherwise leave unscanned."""
        blocked = False
        out_msg = msg

        def protect_arguments(container):
            nonlocal blocked, out_msg
            fn = container.get("function") if "function" in container else container
            args = fn.get("arguments") if isinstance(fn, dict) else None
            if not (isinstance(args, str) and args):
                return container
            pr = self.protect(args, destination=destination)
            audits.append(pr.audit)
            vault.update(pr.vault)
            blocked = blocked or pr.blocked
            if fn is container:
                return {**container, "arguments": pr.text}
            return {**container, "function": {**fn, "arguments": pr.text}}

        tool_calls = msg.get("tool_calls")
        if isinstance(tool_calls, list):
            new_calls = []
            for call in tool_calls:
                if isinstance(call, dict):
                    new_calls.append(protect_arguments(call))
                else:
                    self._unrecognized(
                        f"tool call of type {type(call).__name__!r}"
                    )
                    new_calls.append(call)
            out_msg = {**out_msg, "tool_calls": new_calls}

        function_call = msg.get("function_call")  # legacy OpenAI shape
        if isinstance(function_call, dict):
            out_msg = {**out_msg, "function_call": protect_arguments(function_call)}

        return out_msg, blocked

    def protect_messages(self, messages, destination: str | None = None):
        """Redact a list of chat messages. SDK-agnostic building block.

        Handles the content shapes seen across OpenAI/Azure/Anthropic SDKs:
          * str content                       -> redacted
          * list of dict parts (multimodal)   -> text parts redacted; tool_use
            input and tool_result content redacted; other parts kept
          * missing/None content              -> passed through
          * tool_calls / function_call args   -> redacted (JSON-string payloads)
        Applies to every role (PII can appear in system/tool/assistant text).

        Shapes it does not understand (typed SDK objects, non-dict messages)
        are subject to the guard's ``on_unrecognized`` policy: ``"warn"``
        (default) emits an UnscannedContentWarning and passes the item
        through, ``"error"`` raises, ``"pass"`` stays silent.

        Returns ``(safe_messages, audits, merged_vault, blocked)``. `audits`
        is one AuditRecord per protected text span group; `merged_vault` lets
        you restore tokens across the whole exchange (tokenize mode);
        `blocked` is True when any span triggered the guard's block policy.
        Caller-owned messages are never mutated.
        """
        safe: list = []
        audits: list[AuditRecord] = []
        vault: dict = {}
        blocked = False
        for msg in messages:
            if not isinstance(msg, dict):
                self._unrecognized(f"message of type {type(msg).__name__!r}")
                safe.append(msg)
                continue
            out_msg = dict(msg)
            content = out_msg.get("content")
            if isinstance(content, str) and content:
                pr = self.protect(content, destination=destination)
                audits.append(pr.audit)
                vault.update(pr.vault)
                blocked = blocked or pr.blocked
                out_msg["content"] = pr.text
            elif isinstance(content, list):
                new_parts = []
                for part in content:
                    new_part, part_blocked = self._protect_part(
                        part, destination, audits, vault
                    )
                    new_parts.append(new_part)
                    blocked = blocked or part_blocked
                out_msg["content"] = new_parts
            elif content is None or content == "":
                pass  # documented pass-through (e.g. assistant tool-call turns)
            else:
                self._unrecognized(f"content of type {type(content).__name__!r}")
            out_msg, tc_blocked = self._protect_tool_calls(
                out_msg, destination, audits, vault
            )
            blocked = blocked or tc_blocked
            safe.append(out_msg)
        return safe, audits, vault, blocked

    # --- provider-agnostic wrapper: one guard, every SDK (duck-typed) ---
    def wrap(self, client, provider: str = "auto", destination: str | None = None,
             restore_response: bool = False):
        """Wrap any LLM client behind the guard and return a uniform proxy.

        The returned object exposes a single ``create(**kwargs)`` method that
        works for every supported provider: it redacts PII in the request,
        invokes the underlying client, and (in tokenize mode) restores tokens
        in the response. The provider is auto-detected by client shape, or set
        explicitly with ``provider="openai" | "anthropic" | <registered>``.

        Built-in adapters cover OpenAI/Azure and Anthropic; add your own with
        ``tabayyan.providers.register_adapter``. For zero magic, call
        ``protect_messages(...)`` and your client yourself.

        Limitations match the underlying SDK: with ``stream=True`` the request
        is redacted but the streamed response is passed through (no restore).
        """
        from .providers import resolve_adapter

        adapter = resolve_adapter(client, provider)
        guard = self

        class _Wrapped:
            provider_name = adapter.name

            def create(self, **kwargs):
                audits, vault, blocked = adapter.redact_request(guard, kwargs, destination)
                if blocked:
                    cats = sorted({c for a in audits for c in a.category_summary})
                    cb = any(a.cross_border_transfer for a in audits)
                    raise PermissionError(
                        f"tabayyan Guard blocked a {'cross-border ' if cb else ''}"
                        f"message containing {cats}"
                    )
                resp = adapter.invoke(client, kwargs)
                if (restore_response and guard.mode is RedactionMode.TOKENIZE
                        and not kwargs.get("stream")):
                    adapter.restore_response(resp, vault)
                return resp

        return _Wrapped()

    # --- reference OpenAI/Azure adapter (duck-typed; imports nothing) ---
    def guard_openai(self, client, destination: str | None = None, restore_response: bool = False):
        """DEPRECATED: use ``wrap(client, provider="openai", ...)`` instead.

        Kept as a thin, backward-compatible OpenAI-style proxy exposing
        ``.chat.completions.create``. New code should prefer ``wrap()``, which
        is provider-agnostic.

        REFERENCE adapter for an OpenAI-style client. Duck-typed.

        IMPORTANT: this is a thin reference wrapper validated against common
        message *shapes*, NOT against a live OpenAI/Azure SDK. For production,
        prefer the stable building block `protect_messages(...)` and call your
        client yourself. Known limitations:
          * Streaming (`stream=True`): the request is still redacted, but the
            streamed response is passed through untouched (no token restore).
          * Response restore works only for non-streaming responses whose
            content is at `resp.choices[i].message.content`.

        `client` must expose `.chat.completions.create(model, messages, ...)`.
        """
        warnings.warn(
            "Guard.guard_openai() is deprecated; use Guard.wrap(client, "
            "provider='openai', ...) instead.",
            DeprecationWarning, stacklevel=2,
        )
        guard = self

        class _Completions:
            def create(self, *, model, messages, **kw):
                safe_messages, _audits, vault, blocked = guard.protect_messages(
                    messages, destination=destination
                )
                if blocked:
                    cats = sorted({c for a in _audits for c in a.category_summary})
                    cb = any(a.cross_border_transfer for a in _audits)
                    raise PermissionError(
                        f"tabayyan Guard blocked a {'cross-border ' if cb else ''}"
                        f"message containing {cats}"
                    )
                resp = client.chat.completions.create(model=model, messages=safe_messages, **kw)
                # Do not attempt to restore into a streaming iterator.
                if restore_response and guard.mode is RedactionMode.TOKENIZE and not kw.get("stream"):
                    _restore_openai_response(resp, vault)
                return resp

        class _Chat:
            completions = _Completions()

        class _Proxy:
            chat = _Chat()

        return _Proxy()


def _restore_openai_response(resp, vault: dict) -> None:
    try:
        for choice in resp.choices:
            msg = choice.message
            if getattr(msg, "content", None):
                msg.content = restore(msg.content, vault)
    except AttributeError:
        pass


def _count(items: Iterable[str]) -> dict:
    out: dict = {}
    for it in items:
        out[it] = out.get(it, 0) + 1
    return out
