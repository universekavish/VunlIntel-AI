"""Configurable structured LLM provider abstraction."""

from typing import Protocol

from pydantic import BaseModel, Field


class StructuredAnalysis(BaseModel):
    """Evidence-grounded structured model response."""

    summary: str = Field(min_length=1, max_length=5000)
    evidence_citations: list[str] = Field(default_factory=list)
    recommendations: list["StructuredRecommendation"] = Field(default_factory=list)
    unsupported_claims: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class StructuredRecommendation(BaseModel):
    action: str = Field(min_length=1, max_length=2000)
    rationale: str = Field(min_length=1, max_length=5000)
    evidence_citations: list[str] = Field(default_factory=list)
    patch_allowed: bool = False
    requires_human_approval: bool = True


class StructuredLLMProvider(Protocol):
    """Typed interface for evidence-grounded structured investigation analysis."""

    def analyze(self, *, prompt: str) -> StructuredAnalysis: ...


class DeterministicEvidenceProvider:
    """No-provider fallback that never invents facts or commands.

    It summarizes only supplied evidence text and creates no patch commands.
    """

    def analyze(self, *, prompt: str) -> StructuredAnalysis:
        import re

        citations = sorted(
            set(
                re.findall(
                    r"\b(?:nvd|osv|cisa_kev|mitre_cwe|vendor_advisory):"
                    r"[A-Z0-9_.-]+",
                    prompt,
                )
            )
        )
        unique_claims = [citation for citation in citations]
        summary = "Investigation evidence was reviewed. " + (
            f"{len(unique_claims)} persisted citation(s) support the findings."
            if unique_claims
            else "No persisted evidence citations were available."
        )
        recommendations = []
        if citations:
            recommendations.append(
                StructuredRecommendation(
                    action=(
                        "Review the cited vulnerability evidence and implement "
                        "the vendor-recommended remediation."
                    ),
                    rationale=(
                        "The recommendation is conditional on validated evidence "
                        "and requires human approval."
                    ),
                    evidence_citations=citations,
                    patch_allowed=False,
                    requires_human_approval=True,
                )
            )
        return StructuredAnalysis(
            summary=summary,
            evidence_citations=citations,
            recommendations=recommendations,
            unsupported_claims=[],
            confidence=0.75 if citations else 0.0,
        )
