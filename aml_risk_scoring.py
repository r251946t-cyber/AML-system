"""
aml_risk_scoring.py — Comprehensive Risk Scoring System for AML
=============================================================
Provides detailed risk assessment including:
- Numerical risk score (0-100)
- Risk level classification
- Confidence scores
- Probability distribution
- Top contributing factors
- Recommended actions
- Explainable reasons
"""

from typing import Any, Dict, List, Optional, Tuple
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class RiskScoringSystem:
    """
    Comprehensive risk scoring system that combines ML predictions,
    fraud pattern detection, and rule-based signals.
    """
    
    RISK_LEVELS = {
        "low": (0, 25),
        "medium": (25, 50),
        "high": (50, 75),
        "critical": (75, 100)
    }
    
    def __init__(self):
        """Initialize the risk scoring system."""
        self.risk_thresholds = {
            "low": 25,
            "medium": 25,
            "high": 50,
            "critical": 75
        }
    
    def calculate_comprehensive_risk(
        self,
        ml_prediction: Dict[str, Any],
        fraud_patterns: Dict[str, Any],
        rule_based_score: float = 0.0,
        transaction: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Calculate comprehensive risk assessment.
        
        Args:
            ml_prediction: ML model prediction output
            fraud_patterns: Fraud pattern detection output
            rule_based_score: Rule-based risk score (0-100)
            transaction: Original transaction data
            
        Returns:
            Comprehensive risk assessment dictionary
        """
        # Extract components
        ml_risk_level = ml_prediction.get("risk_level", "normal")
        ml_risk_score = ml_prediction.get("risk_score", 0)
        ml_confidence = ml_prediction.get("confidence", 0)
        ml_probabilities = ml_prediction.get("probabilities", {})
        ml_anomaly_score = ml_prediction.get("anomaly_score")
        
        pattern_risk_score = fraud_patterns.get("risk_score", 0)
        pattern_count = fraud_patterns.get("pattern_count", 0)
        high_risk_patterns = fraud_patterns.get("high_risk_patterns", [])
        
        # Calculate weighted composite score
        composite_score = self._calculate_composite_score(
            ml_risk_score,
            pattern_risk_score,
            rule_based_score,
            ml_confidence
        )
        
        # Determine final risk level
        final_risk_level = self._determine_risk_level(composite_score, ml_risk_level, high_risk_patterns)
        
        # Generate explanations
        explanations = self._generate_explanations(
            ml_prediction,
            fraud_patterns,
            rule_based_score,
            transaction
        )
        
        # Get top contributing factors
        contributing_factors = self._get_contributing_factors(
            ml_prediction,
            fraud_patterns,
            rule_based_score
        )
        
        # Generate recommended action
        recommended_action = self._generate_recommended_action(
            final_risk_level,
            composite_score,
            high_risk_patterns,
            pattern_count
        )
        
        # Build comprehensive assessment
        assessment = {
            "risk_level": final_risk_level,
            "risk_score": round(composite_score, 2),
            "confidence": round(ml_confidence, 3),
            "probabilities": {
                "normal": round(ml_probabilities.get("normal", 0), 3),
                "suspicious": round(ml_probabilities.get("suspicious", 0), 3),
                "super_suspicious": round(ml_probabilities.get("super_suspicious", 0), 3)
            },
            "component_scores": {
                "ml_score": round(ml_risk_score, 2),
                "pattern_score": round(pattern_risk_score, 2),
                "rule_score": round(rule_based_score, 2)
            },
            "anomaly_score": ml_anomaly_score,
            "patterns_detected": pattern_count,
            "high_risk_patterns": high_risk_patterns,
            "explanations": explanations,
            "contributing_factors": contributing_factors,
            "recommended_action": recommended_action,
            "assessment_timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        return assessment
    
    def _calculate_composite_score(
        self,
        ml_score: float,
        pattern_score: float,
        rule_score: float,
        ml_confidence: float
    ) -> float:
        """
        Calculate weighted composite risk score.
        
        Weights:
        - ML prediction: 50% (primary signal)
        - Fraud patterns: 30% (behavioral signal)
        - Rule-based: 20% (regulatory signal)
        """
        # Adjust ML score by confidence
        weighted_ml = ml_score * (0.5 + ml_confidence * 0.3)
        
        # Pattern score (already weighted by severity)
        weighted_pattern = pattern_score * 0.3
        
        # Rule-based score
        weighted_rule = rule_score * 0.2
        
        composite = weighted_ml + weighted_pattern + weighted_rule
        
        return min(100, max(0, composite))
    
    def _determine_risk_level(
        self,
        composite_score: float,
        ml_risk_level: str,
        high_risk_patterns: List[str]
    ) -> str:
        """
        Determine final risk level based on composite score and patterns.
        """
        # Escalate if high-risk patterns detected
        if len(high_risk_patterns) >= 2:
            return "critical"
        if len(high_risk_patterns) >= 1:
            if composite_score >= 40:
                return "critical"
            return "high"
        
        # Map score to risk level
        if composite_score >= self.risk_thresholds["critical"]:
            return "critical"
        elif composite_score >= self.risk_thresholds["high"]:
            return "high"
        elif composite_score >= self.risk_thresholds["medium"]:
            return "medium"
        else:
            return "low"
    
    def _generate_explanations(
        self,
        ml_prediction: Dict[str, Any],
        fraud_patterns: Dict[str, Any],
        rule_score: float,
        transaction: Optional[Dict[str, Any]]
    ) -> List[str]:
        """
        Generate human-readable explanations for the risk assessment.
        """
        explanations = []
        
        # ML-based explanations
        ml_risk_level = ml_prediction.get("risk_level", "normal")
        ml_confidence = ml_prediction.get("confidence", 0)
        
        if ml_risk_level == "super_suspicious":
            explanations.append(
                f"ML model predicts high risk with {ml_confidence:.1%} confidence"
            )
        elif ml_risk_level == "suspicious":
            explanations.append(
                f"ML model predicts suspicious activity with {ml_confidence:.1%} confidence"
            )
        
        # Anomaly explanation
        anomaly_score = ml_prediction.get("anomaly_score")
        if anomaly_score is not None and anomaly_score < -0.1:
            explanations.append(
                f"Transaction shows strong anomaly behavior (score: {anomaly_score:.2f})"
            )
        
        # Pattern-based explanations
        patterns = fraud_patterns.get("patterns", [])
        for pattern in patterns[:3]:  # Top 3 patterns
            pattern_type = pattern.get("type", "")
            description = pattern.get("description", "")
            if description:
                explanations.append(f"Pattern detected: {description}")
        
        # Rule-based explanations
        if rule_score >= 50:
            explanations.append(
                f"Rule-based analysis indicates elevated risk (score: {rule_score:.0f})"
            )
        
        # Transaction-specific explanations
        if transaction:
            amount = float(transaction.get("amount", 0))
            if amount >= 10000:
                explanations.append(f"Large transaction amount: ${amount:,.2f}")
            
            tx_type = transaction.get("transaction_type", "")
            if tx_type == "transfer":
                receiver = transaction.get("receiver_account", "")
                if receiver and transaction.get("is_new_recipient"):
                    explanations.append("Transfer to new beneficiary")
        
        return explanations
    
    def _get_contributing_factors(
        self,
        ml_prediction: Dict[str, Any],
        fraud_patterns: Dict[str, Any],
        rule_score: float
    ) -> List[Dict[str, Any]]:
        """
        Get top contributing factors to the risk score.
        """
        factors = []
        
        # ML prediction factor
        ml_score = ml_prediction.get("risk_score", 0)
        ml_confidence = ml_prediction.get("confidence", 0)
        factors.append({
            "factor": "ML Prediction",
            "value": ml_score,
            "weight": 0.5,
            "description": f"Model risk score with {ml_confidence:.1%} confidence"
        })
        
        # Pattern detection factor
        pattern_score = fraud_patterns.get("risk_score", 0)
        pattern_count = fraud_patterns.get("pattern_count", 0)
        if pattern_score > 0:
            factors.append({
                "factor": "Fraud Patterns",
                "value": pattern_score,
                "weight": 0.3,
                "description": f"{pattern_count} suspicious patterns detected"
            })
        
        # Rule-based factor
        if rule_score > 0:
            factors.append({
                "factor": "Rule-Based Analysis",
                "value": rule_score,
                "weight": 0.2,
                "description": "Regulatory rule violations"
            })
        
        # Anomaly factor
        anomaly_score = ml_prediction.get("anomaly_score")
        if anomaly_score is not None and anomaly_score < 0:
            factors.append({
                "factor": "Anomaly Detection",
                "value": abs(anomaly_score) * 100,
                "weight": 0.15,
                "description": f"Behavioral anomaly detected (score: {anomaly_score:.2f})"
            })
        
        # Sort by contribution
        factors.sort(key=lambda x: x["value"], reverse=True)
        
        return factors[:5]  # Return top 5 factors
    
    def _generate_recommended_action(
        self,
        risk_level: str,
        risk_score: float,
        high_risk_patterns: List[str],
        pattern_count: int
    ) -> Dict[str, Any]:
        """
        Generate recommended action based on risk assessment.
        """
        if risk_level == "critical":
            return {
                "action": "FREEZE_AND_ESCALATE",
                "priority": "immediate",
                "description": "Freeze transaction and escalate to senior AML analyst for immediate review",
                "timeline": "Within 1 hour",
                "required_approvals": ["Senior AML Analyst", "Compliance Officer"]
            }
        elif risk_level == "high":
            if len(high_risk_patterns) >= 2:
                return {
                    "action": "FREEZE_AND_ESCALATE",
                    "priority": "high",
                    "description": "Freeze transaction and escalate to AML analyst for review",
                    "timeline": "Within 4 hours",
                    "required_approvals": ["AML Analyst"]
                }
            else:
                return {
                    "action": "HOLD_FOR_REVIEW",
                    "priority": "high",
                    "description": "Place transaction on hold for AML analyst review",
                    "timeline": "Within 24 hours",
                    "required_approvals": ["AML Analyst"]
                }
        elif risk_level == "medium":
            return {
                "action": "ENHANCED_MONITORING",
                "priority": "medium",
                "description": "Place account on enhanced monitoring for 30 days",
                "timeline": "Immediate",
                "required_approvals": ["System"]
            }
        else:  # low
            return {
                "action": "APPROVE",
                "priority": "low",
                "description": "Transaction approved for processing",
                "timeline": "Immediate",
                "required_approvals": ["System"]
            }
    
    def get_risk_level_from_score(self, score: float) -> str:
        """
        Get risk level from numerical score.
        
        Args:
            score: Numerical risk score (0-100)
            
        Returns:
            Risk level string
        """
        if score >= self.risk_thresholds["critical"]:
            return "critical"
        elif score >= self.risk_thresholds["high"]:
            return "high"
        elif score >= self.risk_thresholds["medium"]:
            return "medium"
        else:
            return "low"
    
    def format_assessment_for_display(self, assessment: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format assessment for user-friendly display.
        
        Args:
            assessment: Comprehensive risk assessment
            
        Returns:
            Formatted assessment for display
        """
        return {
            "summary": {
                "risk_level": assessment["risk_level"].upper(),
                "risk_score": assessment["risk_score"],
                "confidence": f"{assessment['confidence']:.1%}",
                "status": self._get_status_badge(assessment["risk_level"])
            },
            "details": {
                "probabilities": assessment["probabilities"],
                "component_scores": assessment["component_scores"],
                "patterns_detected": assessment["patterns_detected"]
            },
            "explanations": assessment["explanations"],
            "factors": assessment["contributing_factors"],
            "action": assessment["recommended_action"],
            "timestamp": assessment["assessment_timestamp"]
        }
    
    def _get_status_badge(self, risk_level: str) -> str:
        """Get status badge for risk level."""
        badges = {
            "low": "✓ Normal",
            "medium": "⚠ Review",
            "high": "⚠⚠ High Risk",
            "critical": "🚨 Critical"
        }
        return badges.get(risk_level, "Unknown")


# Global scoring system instance
_default_scorer = RiskScoringSystem()


def calculate_risk_assessment(
    ml_prediction: Dict[str, Any],
    fraud_patterns: Dict[str, Any],
    rule_based_score: float = 0.0,
    transaction: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Convenience function to calculate comprehensive risk assessment.
    
    Args:
        ml_prediction: ML model prediction output
        fraud_patterns: Fraud pattern detection output
        rule_based_score: Rule-based risk score (0-100)
        transaction: Original transaction data
        
    Returns:
        Comprehensive risk assessment dictionary
    """
    return _default_scorer.calculate_comprehensive_risk(
        ml_prediction,
        fraud_patterns,
        rule_based_score,
        transaction
    )


def get_risk_level(score: float) -> str:
    """Get risk level from numerical score."""
    return _default_scorer.get_risk_level_from_score(score)


def format_for_display(assessment: Dict[str, Any]) -> Dict[str, Any]:
    """Format assessment for display."""
    return _default_scorer.format_assessment_for_display(assessment)
