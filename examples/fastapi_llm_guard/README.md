\# FastAPI LLM Guard Example



This example shows how to place Tabayyan in front of an LLM call.



It demonstrates a clean separation between:



\- API routing

\- request and response schemas

\- runtime configuration

\- privacy protection service

\- LLM client abstraction



No external LLM call is made. The example uses a fake LLM client so it remains

offline and safe by default.



\## Flow



```text

User prompt

→ FastAPI endpoint

→ Tabayyan Guard

→ Redacted prompt

→ Fake LLM client

→ Safe response

→ Audit log

