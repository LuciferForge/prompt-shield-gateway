#!/usr/bin/env python3
"""
Prompt-Shield Gateway Proxy Server (FastAPI)
Provides transparent, sub-30ms security proxy endpoints for LLM applications and agent pipelines.
"""

import time
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any

from sanitizer import Layer1Sanitizer
from crypto_shield import Layer3CryptoShield
from metrics_engine import get_live_metrics, record_blocked_attack

app = FastAPI(
    title="Prompt-Shield Gateway Proxy API",
    description="OWASP LLM Top 10 (2025/2026) Compliant Security Proxy",
    version="1.0.0"
)

sanitizer = Layer1Sanitizer()
crypto_shield = Layer3CryptoShield()

class InspectPromptRequest(BaseModel):
    prompt: str
    tool_call: Optional[str] = None
    tool_args: Optional[Dict[str, Any]] = None
    signature_payload: Optional[Dict[str, Any]] = None

class InspectPromptResponse(BaseModel):
    is_safe: bool
    status: str
    latency_ms: float
    sanitized_prompt: Optional[str] = None
    metrics: Dict[str, Any]

@app.get("/health")
def health_check():
    return {"status": "ACTIVE", "shield_version": "1.0.0"}

@app.get("/metrics")
def get_metrics_endpoint():
    return get_live_metrics()

@app.post("/v1/shield/inspect", response_model=InspectPromptResponse)
def inspect_and_shield(req: InspectPromptRequest):
    start_time = time.perf_counter()
    
    # 1. Layer 1 Heuristic & Injection Scan (< 5ms)
    is_safe, reason, metrics = sanitizer.inspect_input(req.prompt)
    if not is_safe:
        elapsed = (time.perf_counter() - start_time) * 1000.0
        record_blocked_attack(reason)
        return InspectPromptResponse(
            is_safe=False,
            status=f"BLOCKED: {reason}",
            latency_ms=round(elapsed, 2),
            metrics=metrics
        )

    # 2. Layer 3 Cryptographic Financial Guardrail
    if req.tool_call:
        is_tool_approved, tool_reason = crypto_shield.enforce_financial_guardrail(
            tool_call=req.tool_call,
            tool_args=req.tool_args or {},
            signature_payload=req.signature_payload
        )
        if not is_tool_approved:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return InspectPromptResponse(
                is_safe=False,
                status=f"BLOCKED_EXCESSIVE_AGENCY: {tool_reason}",
                latency_ms=round(elapsed, 2),
                metrics={"threat": "LLM06_EXCESSIVE_AGENCY"}
            )

    elapsed = (time.perf_counter() - start_time) * 1000.0
    return InspectPromptResponse(
        is_safe=True,
        status="PASSED",
        latency_ms=round(elapsed, 2),
        sanitized_prompt=req.prompt,
        metrics=metrics
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8090)
