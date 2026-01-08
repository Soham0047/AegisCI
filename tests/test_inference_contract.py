from model_service.schemas import (
    CategoryPrediction,
    InferenceRequest,
    InferenceResponse,
    LineAttribution,
    ToolFinding,
)


def test_inference_schema_roundtrip():
    request = InferenceRequest(
        language="python",
        code="print('hello')",
        filepath="app.py",
        context_before="",
        context_after="",
        tool_findings=[
            ToolFinding(rule_id="B101", message="use of assert", severity="LOW", line=3)
        ],
    )
    request_payload = request.model_dump()
    assert InferenceRequest.model_validate(request_payload)

    response = InferenceResponse(
        risk_score=0.42,
        confidence=0.42,
        top_categories=[CategoryPrediction(category="misc.other", confidence=0.42)],
        line_attributions=[LineAttribution(line=3, score=0.1)],
    )
    response_payload = response.model_dump()
    assert InferenceResponse.model_validate(response_payload)
