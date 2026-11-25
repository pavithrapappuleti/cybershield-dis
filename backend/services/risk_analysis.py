"""Explainable Rule-Based Risk Analysis Engine.

Designed around a modular BaseRiskAnalyzer interface so a supervised or
unsupervised ML anomaly detector can be plugged in later without altering the
downstream response and reporting pipeline. The current implementation uses
transparent, deterministic weighted rules (not an ML model).
"""

from abc import ABC, abstractmethod


class BaseRiskAnalyzer(ABC):
    """Modular interface for risk scoring engines (rule-based or future ML)."""

    engine_name = "BaseRiskAnalyzer"
    engine_mode = "abstract"

    @abstractmethod
    def analyze(self, event_type, failed_login_count, request_count, repetition_count, immune_history_hits=0, rule=None):
        """Return a structured risk assessment dictionary."""


class ExplainableRuleRiskAnalyzer(BaseRiskAnalyzer):
    """Deterministic, explainable rule-based risk scorer (0-100 scale)."""

    engine_name = "Explainable Rule-Based Risk Engine v1.0"
    engine_mode = "rule_based_explainable"

    ACTIVITY_BASE_WEIGHTS = {
        "normal_traffic": 4,
        "repeated_ip_requests": 16,
        "suspicious_frequency": 20,
        "failed_login_burst": 22,
        "restricted_endpoint_access": 24,
        "unusual_activity_pattern": 20,
        "service_failure": 25,
        "database_failure": 25,
        "excessive_errors": 22,
    }

    @staticmethod
    def classify_severity(score):
        """Map 0-100 numeric risk score to standard severity levels."""
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 30:
            return "Medium"
        return "Low"

    @staticmethod
    def recommend_response(severity, event_type, score):
        """Produce a clear, safe recommended response action."""
        if event_type in ("service_failure", "database_failure", "excessive_errors"):
            return "Initiate Self-Recovery Engine to restore simulated service state and re-verify health."
        if severity == "Critical":
            return "Temporarily block simulated source IP, open Critical incident, and notify SOC analyst."
        if severity == "High":
            return "Apply temporary simulated IP isolation and monitor traffic burst patterns."
        if severity == "Medium":
            return "Increase monitoring sensitivity and log pattern to Digital Immune Memory."
        return f"Log telemetry event (risk {score}/100); no automated containment required."

    def analyze(
        self,
        event_type,
        failed_login_count=0,
        request_count=1,
        repetition_count=1,
        immune_history_hits=0,
        rule=None,
    ):
        """Compute explainable 0-100 risk score and per-factor breakdown."""
        # 1. Failed login factor (0 - 30)
        failed_factor = min(30, failed_login_count * 4)

        # 2. Request frequency factor (0 - 25)
        if request_count <= 5:
            freq_factor = request_count * 1
        elif request_count <= 25:
            freq_factor = 5 + int((request_count - 5) * 0.5)
        else:
            freq_factor = min(25, 15 + int((request_count - 25) * 0.25))

        # 3. Event repetition / threshold-excess factor (0 - 20)
        repetition_factor = min(20, max(0, (repetition_count - 1) * 5))

        # 4. Activity type weight (0 - 25)
        rule_weight = rule.base_risk_weight if rule else None
        activity_factor = min(
            25,
            rule_weight if rule_weight is not None else self.ACTIVITY_BASE_WEIGHTS.get(event_type, 12),
        )

        # 5. Historical pattern memory boost (0 - 15)
        immune_boost = min(15, immune_history_hits * 5) if immune_history_hits > 0 else 0
        if rule and rule.immune_boost_applied:
            immune_boost = min(15, max(immune_boost, rule.immune_boost_applied))

        # Normal baseline traffic or isolated single failed login stays Low
        if event_type == "normal_traffic" and request_count < 30 and failed_login_count == 0:
            raw_score = min(18, freq_factor + activity_factor)
            immune_boost = 0
            repetition_factor = 0
        elif event_type == "failed_login_burst" and failed_login_count <= 1 and repetition_count <= 1:
            raw_score = min(25, failed_factor + freq_factor + 12)
            activity_factor = 12
            immune_boost = 0
        else:
            raw_score = failed_factor + freq_factor + repetition_factor + activity_factor + immune_boost

        score = max(0, min(100, int(raw_score)))
        severity = self.classify_severity(score)
        recommended = self.recommend_response(severity, event_type, score)

        reasons = []
        if failed_factor > 0:
            reasons.append(f"failed login volume (+{failed_factor})")
        if freq_factor >= 10:
            reasons.append(f"high request frequency (+{freq_factor})")
        if repetition_factor > 0:
            reasons.append(f"event repetition x{repetition_count} (+{repetition_factor})")
        reasons.append(f"activity class '{event_type}' (+{activity_factor})")
        if immune_boost > 0:
            reasons.append(f"known recurring pattern in Immune Memory (+{immune_boost})")

        explanation = (
            f"Explainable rule-based score {score}/100 ({severity}) computed from: "
            + ", ".join(reasons)
            + "."
        )

        return {
            "engine_name": self.engine_name,
            "engine_mode": self.engine_mode,
            "risk_score": score,
            "severity": severity,
            "explanation": explanation,
            "recommended_response": recommended,
            "breakdown": {
                "failed_login_factor": failed_factor,
                "request_frequency_factor": freq_factor,
                "repetition_factor": repetition_factor,
                "activity_type_factor": activity_factor,
                "immune_memory_boost": immune_boost,
            },
        }


# Active analyzer instance (replaceable with an ML subclass in future versions)
active_risk_analyzer = ExplainableRuleRiskAnalyzer()
