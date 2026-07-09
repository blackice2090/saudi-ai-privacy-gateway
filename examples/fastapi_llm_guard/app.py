from __future__ import annotations

from fastapi import FastAPI

from examples.fastapi_llm_guard.config import get_settings
from examples.fastapi_llm_guard.schemas import ChatRequest, ChatResponse
from examples.fastapi_llm_guard.services import FakeLlmClient, LlmGuardService

app = FastAPI(
    title="Saudi AI Privacy Gateway",
    description="FastAPI example showing how to protect LLM prompts with Tabayyan.",
    version="0.1.0",
)

settings = get_settings()
guard_service = LlmGuardService(
    settings=settings,
    llm_client=FakeLlmClient(),
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/chat", response_model=ChatResponse)
def chat(request: ChatRequest) -> ChatResponse:
    result = guard_service.chat(request.prompt)

    return ChatResponse(
        safe_prompt=result.safe_prompt,
        llm_response=result.llm_response,
        detection=result.detection,
    )