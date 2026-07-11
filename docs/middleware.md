# Middleware & audit

`Guard` sits between your application and an LLM endpoint: it scans a prompt,
redacts personal data before it leaves, and emits a structured audit record.
The record is the **compensating-control evidence** — what was detected, what
was redacted, the data categories, and whether the destination is a
cross-border transfer. Stdlib only; the OpenAI/Azure wrapper is duck-typed.

```python
from tabayyan import AuditLog, Guard, RedactionMode

guard = Guard(
    mode=RedactionMode.MASK,
    in_kingdom_hosts=["llm.myhospital.health.sa"],
    audit=AuditLog(path="audit.jsonl"),
)

pr = guard.protect(
    "اسم المريض عبدالله القحطاني، الهوية 1158813996",
    destination="https://contoso.openai.azure.com/v1/chat",
)

print(pr.text)                         # redacted
print(pr.audit.cross_border_transfer)  # True — external endpoint + personal data
print(pr.audit.health_data_present)    # category-aware
```

## FastAPI / Starlette request middleware

For FastAPI and Starlette applications, use `TabayyanPrivacyMiddleware` to
redact PII from JSON request bodies before they reach your route handlers.

Install the optional FastAPI extra:

```bash
pip install "tabayyan[fastapi]"
```

Then add the middleware to your application:

```python
from fastapi import FastAPI

from tabayyan.integrations.fastapi import TabayyanPrivacyMiddleware

app = FastAPI()

app.add_middleware(
    TabayyanPrivacyMiddleware,
    destination="https://api.openai.com",
)
```

Any string value inside a JSON body is scanned and protected, including nested
objects and lists.

```python
@app.post("/chat")
def chat(payload: dict[str, object]) -> dict[str, object]:
    # The payload has already been protected by the middleware.
    return payload
```

Example request:

```json
{
  "prompt": "رقم الهوية 1158813996، الجوال +966512345678"
}
```

The route receives a protected payload:

```json
{
  "prompt": "رقم الهوية [SAUDI_NATIONAL_ID]، الجوال [SAUDI_MOBILE]"
}
```

By default, the middleware adds response headers that make protection visible to
upstream gateways, observability tools, or tests:

```text
x-tabayyan-pii-detected: true
x-tabayyan-redacted-count: 2
```

Configure the middleware when needed:

```python
from tabayyan import RedactionMode

app.add_middleware(
    TabayyanPrivacyMiddleware,
    destination="https://api.openai.com",
    mode=RedactionMode.MASK,
    audit_path="audit.jsonl",
    block_cross_border=False,
    include_response_headers=True,
    max_body_size=1_000_000,
    include_fields={"prompt", "messages", "content"},
    exclude_fields={"metadata"},
    include_paths={"/chat", "/messages"},
    exclude_paths={"/health", "/metrics"},
    include_methods={"POST", "PUT"},
    exclude_methods={"DELETE"},
)
```

Notes:

- JSON request bodies using `application/json` or a structured `+json`
  media type are modified.
- Non-JSON and unsupported JSON-like media types pass through unchanged.
- Malformed JSON on a protected route is rejected with `400 Bad Request`
  (fail closed): a body that cannot be parsed cannot be scanned, so it is
  never forwarded to the application.
- With `block_cross_border=True`, a request the guard blocks is rejected
  with `403 Forbidden` and never reaches the route handler; the response
  body does not contain the original text.
- `mode=RedactionMode.HASH` requires a non-empty `salt` (validated at
  construction time, used as the HMAC key).
- `mode=RedactionMode.TOKENIZE` is rejected at construction: the request
  middleware has no channel to return the vault, so tokenization could
  never be reversed. Use `Guard` directly for reversible tokenization.
- When nothing is redacted, the original body bytes are forwarded unchanged
  (no re-serialization).
- The middleware does not call any external service.
- `max_body_size` defaults to `1_000_000` bytes.
- JSON requests larger than the configured limit return `413 Payload Too Large`.
- Set `max_body_size=None` to disable the body size limit.
- `include_fields` limits protection to selected JSON field names, such as
  `prompt`, `messages`, or `content`.
- `exclude_fields` skips selected JSON fields or subtrees, such as `metadata`.
- `exclude_fields` takes precedence over `include_fields`.
- `include_paths` limits middleware processing to selected exact route paths.
- `exclude_paths` skips selected exact route paths.
- `exclude_paths` takes precedence over `include_paths`.
- `include_methods` limits middleware processing to selected HTTP methods.
- `exclude_methods` skips selected HTTP methods.
- `exclude_methods` takes precedence over `include_methods`.
- When route and method filters are both configured, both must match.
- Raw values are not written to audit logs unless audit configuration explicitly
  enables them.

### JSON media types

The middleware processes requests whose `Content-Type` is either:

- `application/json`
- A media type ending with the structured syntax suffix `+json`

Supported examples include:

```text
application/json
application/json; charset=utf-8
application/problem+json
application/vnd.api+json
application/merge-patch+json
```

Media type matching is case-insensitive, and parameters such as `charset` are
ignored when determining whether the request contains JSON.

JSON-like but unsupported media types pass through unchanged, including:

```text
application/jsonp
text/json
application/not-json
```

### Route filtering

Use `include_paths` and `exclude_paths` to control which application routes are
processed by the middleware.

```python
app.add_middleware(
    TabayyanPrivacyMiddleware,
    destination="https://api.openai.com",
    include_paths={"/chat", "/messages"},
    exclude_paths={"/health", "/metrics"},
)
```

Route filtering behavior:

- `include_paths=None` protects every eligible JSON route.
- `include_paths` limits protection to the configured paths.
- `exclude_paths` skips the configured paths completely.
- `exclude_paths` takes precedence when a path appears in both options.
- Route matching is exact.
- Wildcard and prefix matching are not currently supported.
- Configured paths are normalized.
- Values such as `chat/`, `/chat/`, and `/chat` are treated as `/chat`.
- An empty configured path is normalized to `/`.
- Skipped routes pass through without request-body rewriting.
- Skipped routes do not receive `x-tabayyan-*` response headers.
- Route filtering is evaluated before reading the request body.
- Route filtering is evaluated before request-body size validation.

For example, this configuration protects `/chat` but skips `/health`:

```python
app.add_middleware(
    TabayyanPrivacyMiddleware,
    include_paths={"/chat", "/health"},
    exclude_paths={"/health"},
)
```

In this case:

```text
POST /chat    -> protected
POST /health  -> skipped because exclusions take precedence
POST /echo    -> skipped because it is not included
```

### HTTP method filtering

Use `include_methods` to process only selected HTTP methods, or
`exclude_methods` to skip selected methods:

```python
app.add_middleware(
    TabayyanPrivacyMiddleware,
    include_methods={"POST", "PUT"},
    exclude_methods={"DELETE"},
)
```

HTTP method filtering behavior:

- `include_methods=None` protects every otherwise eligible HTTP method.
- `include_methods` limits processing to the configured methods.
- `exclude_methods` skips the configured methods completely.
- `exclude_methods` takes precedence when a method appears in both options.
- Method names are normalized by trimming whitespace and converting them to
  uppercase.
- Values such as `"post"`, `" POST "`, and `"Post"` are treated as `"POST"`.
- Skipped methods pass through without request-body rewriting.
- Skipped methods do not receive `x-tabayyan-*` response headers.
- Method filtering is evaluated before JSON detection.
- Method filtering is evaluated before reading the request body.
- Method filtering is evaluated before request-body size validation.
- When route and method filters are both configured, a request must satisfy
  both filters to be processed.

For example:

```python
app.add_middleware(
    TabayyanPrivacyMiddleware,
    include_paths={"/chat"},
    include_methods={"POST"},
)
```

This produces:

```text
POST /chat  -> protected
PUT  /chat  -> skipped because PUT is not included
POST /echo  -> skipped because /echo is not included
```

## Cross-border logic (PDPL Art. 29)

If personal data is present **and** the destination is a real external
endpoint that is not in-Kingdom, the call is flagged as a cross-border
transfer. "In-Kingdom" means a `.sa` host or a host in `in_kingdom_hosts`.

Local destinations are never cross-border: no destination at all, the
`"local"` placeholder, `localhost`, and loopback IPs (`127.0.0.1`, `::1`)
describe processing that stays on the machine. Unknown or unparseable
external hosts remain flagged (fail closed). Every audit record also carries
`destination_scope` — one of `none`, `local`, `in_kingdom`, `external`, or
`unknown` — so reviewers can distinguish real transfers from local runs.

Until your in-Kingdom endpoint is live, external endpoints such as
`*.openai.azure.com` are flagged — exactly the evidence trail a reviewer
expects for a conditional cloud-AI pilot.

## Blocking

```python
from tabayyan.entities import Category

# Block any cross-border transfer containing personal data.
guard = Guard(block_cross_border=True)

# Block sensitive health data outright.
guard = Guard(
    block_categories=[Category.SENSITIVE_HEALTH],
)
```

## Wrapping any LLM client — one guard, every SDK

`Guard.wrap()` returns a uniform proxy with a single `create(**kwargs)` method.
The provider is auto-detected from the client's shape, or set explicitly.

PII in the request is redacted before the call. For Anthropic clients, this
includes both message content and the `system` prompt.

```python
# OpenAI / Azure — auto-detected.
gpt = guard.wrap(
    OpenAI(...),
    destination="https://contoso.openai.azure.com",
)

gpt.create(
    model="gpt-4o",
    messages=[...],
)

# Anthropic / Claude — auto-detected.
claude = guard.wrap(Anthropic(...))

claude.create(
    model="claude-sonnet-4-6",
    system="...",
    messages=[...],
)

# Force a provider or use a registered custom adapter.
client = guard.wrap(
    my_client,
    provider="anthropic",
)
```

Built-in adapters cover OpenAI/Azure and Anthropic. Teach Tabayyan a new SDK
with `register_adapter`:

```python
from tabayyan import register_adapter


class MyAdapter:
    name = "myllm"

    def matches(self, client):
        ...

    def redact_request(self, guard, kwargs, destination):
        # Return: audits, vault, blocked
        ...

    def invoke(self, client, kwargs):
        ...

    def restore_response(self, response, vault):
        ...


register_adapter(MyAdapter())
```

With `RedactionMode.TOKENIZE` and `restore_response=True`, the wrapper restores
original values in the model response so personalization can survive.

For zero magic, the fully provider-agnostic building block is:

```python
safe_messages, audits, vault, blocked = guard.protect_messages(
    messages,
    destination="https://api.openai.com",
)
```

Redact the messages first, then call your client directly.

> `guard_openai()` is deprecated in favour of
> `wrap(client, provider="openai")`. It still works and emits a
> `DeprecationWarning`.

## NDMO data classification

Every audit record carries `data_classification` — the highest NDMO sensitivity
level among the detected entities — plus a `classification_summary` mapping
each level to its count.

Health data classifies as **secret**. Most personal identifiers, financial
data, contact data, and names classify as **confidential**. Organization and
network identifiers classify as **public**.

```python
pr = guard.protect(
    "MRN: A1234, ID 1158813996",
    destination="https://api.openai.com",
)

pr.audit.data_classification
# "secret" — health data outranks the national identifier

pr.audit.classification_summary
# {"secret": 1, "confidential": 1}
```

The mapping is a practical default. Override
`tabayyan.ndmo.CATEGORY_CLASSIFICATION` to match your organization's data
classification matrix.

Use classification directly without the middleware through:

```python
from tabayyan import classification_summary, classify

level = classify(matches)
summary = classification_summary(matches)
```

## Audit privacy

Raw values are **not** written to the audit by default:

```python
guard = Guard(record_values=False)
```

The audit captures:

- Detection counts.
- Entity categories.
- Data classification.
- Cross-border status.
- Protection action.

It does not capture the original detected values unless `record_values=True`
is explicitly configured.