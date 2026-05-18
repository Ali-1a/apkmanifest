"""
Risk Scorer - Computes a 0-100 risk score from findings.
Weights critical findings heavily, medium moderately, low lightly.
"""


SEVERITY_WEIGHTS = {
    "critical": 25,
    "medium": 10,
    "low": 3,
}

MAX_SCORE = 100


class RiskScorer:
    """Computes overall risk score from a list of findings."""

    def __init__(self, findings: list):
        self.findings = findings

    def calculate(self) -> int:
        """Calculate risk score from 0 (safe) to 100 (very risky)."""
        score = 0
        for finding in self.findings:
            severity = finding.get("severity", "low")
            score += SEVERITY_WEIGHTS.get(severity, 0)

        return min(score, MAX_SCORE)

    @staticmethod
    def get_risk_level(score: int) -> str:
        """Convert numeric score to a human-readable risk level."""
        if score >= 75:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 25:
            return "Medium"
        elif score > 0:
            return "Low"
        else:
            return "Minimal"

    @staticmethod
    def get_risk_color(score: int) -> str:
        """Return a color code for UI display."""
        if score >= 75:
            return "#791F1F"
        elif score >= 50:
            return "#A32D2D"
        elif score >= 25:
            return "#854F0B"
        elif score > 0:
            return "#185FA5"
        else:
            return "#0F6E56"
