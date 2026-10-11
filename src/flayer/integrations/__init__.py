"""Consumer-neutral observation contracts without transport, dispatch, or authorization."""

from .adapters import AdaptDiagnostics, AdaptLifecycle, AdaptState
from .contracts import (
    CheckEvidence,
    DiagnosticEvidence,
    IntegrationError,
    IntegrationOperation,
    IntegrationRequest,
    IntegrationResult,
    LifecycleEvidence,
    Metric,
    ResourceCount,
    StateEvidence,
)
from .wire import ParseRequest, ParseResult, SerializeRequest, SerializeResult

__all__ = [
    "AdaptDiagnostics", "AdaptLifecycle", "AdaptState", "CheckEvidence", "DiagnosticEvidence",
    "IntegrationError", "IntegrationOperation", "IntegrationRequest", "IntegrationResult",
    "LifecycleEvidence", "Metric", "ParseRequest", "ParseResult", "ResourceCount", "SerializeRequest",
    "SerializeResult", "StateEvidence",
]
