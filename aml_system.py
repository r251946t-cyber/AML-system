"""
aml_system.py — Integrated Enterprise AML Detection System
==========================================================
Main integration module that combines all AML components:
- Data validation
- Feature engineering
- ML prediction
- Fraud pattern detection
- Risk scoring
- Explainability
- Model versioning
- Continuous learning

This module provides a unified interface for the entire AML detection pipeline.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

from aml_data_validator import TransactionValidator, validate_transaction
from aml_feature_engineering import FeatureEngineer, extract_features
from aml_ml_engine import AMLEnsembleModel, train_model, predict_risk, get_model_info
from aml_fraud_patterns import FraudPatternDetector, detect_fraud_patterns
from aml_risk_scoring import RiskScoringSystem, calculate_risk_assessment
from aml_explainability import ModelExplainer, RuleBasedExplainer, explain_pattern
from aml_model_registry import ModelRegistry, register_model, deploy_model, get_current_model
from aml_continuous_learning import ContinuousLearningPipeline, add_labeled_transaction, check_retrain_needed

logger = logging.getLogger(__name__)


class AMLDetectionSystem:
    """
    Enterprise-grade AML detection system.
    
    Integrates all components into a unified pipeline:
    1. Data validation
    2. Feature engineering
    3. ML prediction
    4. Fraud pattern detection
    5. Risk scoring
    6. Explainability
    """
    
    def __init__(
        self,
        use_advanced_features: bool = True,
        enable_explainability: bool = True,
        enable_continuous_learning: bool = True
    ):
        """
        Initialize the AML detection system.
        
        Args:
            use_advanced_features: Whether to use advanced feature engineering
            enable_explainability: Whether to enable SHAP explainability
            enable_continuous_learning: Whether to enable continuous learning
        """
        self.use_advanced_features = use_advanced_features
        self.enable_explainability = enable_explainability
        self.enable_continuous_learning = enable_continuous_learning
        
        # Initialize components
        self.validator = TransactionValidator(strict_mode=False)
        self.feature_engineer = FeatureEngineer()
        self.ml_model = AMLEnsembleModel()
        self.pattern_detector = FraudPatternDetector()
        self.risk_scorer = RiskScoringSystem()
        self.model_registry = ModelRegistry()
        
        # Optional components
        self.shap_explainer = None
        self.rule_explainer = RuleBasedExplainer()
        
        if enable_explainability:
            self.shap_explainer = ModelExplainer()
        
        if enable_continuous_learning:
            self.continuous_learning = ContinuousLearningPipeline(self.model_registry)
        else:
            self.continuous_learning = None
        
        self.is_initialized = False
        logger.info("AML Detection System initialized")
    
    def initialize_model(
        self,
        training_transactions: List[Dict[str, Any]],
        register_model: bool = True
    ) -> Dict[str, Any]:
        """
        Initialize and train the ML model.
        
        Args:
            training_transactions: Labeled training transactions
            register_model: Whether to register model in registry
            
        Returns:
            Training result dictionary
        """
        logger.info(f"Initializing model with {len(training_transactions)} transactions")
        
        # Train model
        training_result = self.ml_model.train(training_transactions)
        
        if not training_result.get("success"):
            logger.error("Model training failed")
            return training_result
        
        # Register model if requested
        if register_model:
            model_version = self.ml_model.MODEL_VERSION
            model_path = "aml_ai_model_temp.pkl"
            
            # Save temporary model
            self.ml_model.save(model_path, f"{model_path}_meta.json")
            
            # Register in registry
            metadata = training_result.get("metadata", {})
            performance_metrics = {
                "f1_weighted": metadata.get("cross_val_scores", {}).get("f1_weighted", 0),
                "accuracy": metadata.get("cross_val_scores", {}).get("accuracy", 0),
                "training_samples": metadata.get("training_samples", 0)
            }
            
            model_id = self.model_registry.register_model(
                model_version,
                model_path,
                metadata,
                performance_metrics
            )
            
            # Deploy model
            self.model_registry.deploy_model(model_id, "initial_training")
            
            # Clean up temporary files
            import os
            if os.path.exists(model_path):
                os.remove(model_path)
            if os.path.exists(f"{model_path}_meta.json"):
                os.remove(f"{model_path}_meta.json")
            
            training_result["model_id"] = model_id
        
        # Initialize SHAP explainer if enabled
        if self.enable_explainability and self.shap_explainer:
            try:
                X, _ = self.ml_model.prepare_training_data(training_transactions)
                if len(X) > 0:
                    self.shap_explainer.initialize(
                        self.ml_model.classifier,
                        X[:min(100, len(X))]  # Use subset for background
                    )
            except Exception as e:
                logger.warning(f"SHAP initialization failed: {e}")
        
        self.is_initialized = True
        logger.info("Model initialization complete")
        
        return training_result
    
    def analyze_transaction(
        self,
        transaction: Dict[str, Any],
        historical_data: Optional[List[Dict[str, Any]]] = None,
        include_explanations: bool = True
    ) -> Dict[str, Any]:
        """
        Perform comprehensive AML analysis on a transaction.
        
        Args:
            transaction: Transaction dictionary
            historical_data: Optional historical transactions for the sender
            include_explanations: Whether to include explanations
            
        Returns:
            Comprehensive analysis dictionary
        """
        analysis_start = datetime.now(timezone.utc)
        
        # Step 1: Validate transaction
        is_valid, cleaned_tx, validation_errors = self.validator.validate_transaction(transaction)
        
        # Step 2: Extract features
        features = extract_features(cleaned_tx, historical_data)
        
        # Step 3: ML prediction
        ml_prediction = self.ml_model.predict(cleaned_tx, historical_data)
        
        # Step 4: Fraud pattern detection
        fraud_patterns = self.pattern_detector.detect_patterns(cleaned_tx, historical_data or [])
        
        # Step 5: Risk scoring
        rule_based_score = self._calculate_rule_based_score(cleaned_tx)
        
        risk_assessment = self.risk_scorer.calculate_comprehensive_risk(
            ml_prediction,
            fraud_patterns,
            rule_based_score,
            cleaned_tx
        )
        
        # Step 6: Explainability
        explanations = {}
        if include_explanations:
            explanations = self._generate_explanations(
                cleaned_tx,
                features,
                ml_prediction,
                fraud_patterns,
                risk_assessment
            )
        
        # Build comprehensive analysis
        analysis = {
            "transaction_id": transaction.get("id"),
            "validation": {
                "is_valid": is_valid,
                "errors": validation_errors
            },
            "ml_prediction": ml_prediction,
            "fraud_patterns": fraud_patterns,
            "risk_assessment": risk_assessment,
            "explanations": explanations,
            "processing_time_ms": (datetime.now(timezone.utc) - analysis_start).total_seconds() * 1000,
            "analyzed_at": datetime.now(timezone.utc).isoformat()
        }
        
        return analysis
    
    def _calculate_rule_based_score(self, transaction: Dict[str, Any]) -> float:
        """Calculate rule-based risk score."""
        score = 0.0
        
        amount = float(transaction.get("amount", 0))
        
        # Large amount penalty
        if amount >= 10000:
            score += 20
        elif amount >= 5000:
            score += 10
        
        # High-risk country penalty
        origin_country = transaction.get("origin_country", "").upper()
        dest_country = transaction.get("destination_country", "").upper()
        
        high_risk_countries = {"AF", "KP", "IR", "SY", "MM", "LR", "SS", "YE", "CU", "VE"}
        
        if origin_country in high_risk_countries or dest_country in high_risk_countries:
            score += 25
        
        # PEP flag penalty
        if transaction.get("pep_flag"):
            score += 15
        
        # Sanctioned flag penalty
        if transaction.get("sanctioned_flag"):
            score += 30
        
        # New recipient penalty
        if transaction.get("is_new_recipient"):
            score += 10
        
        return min(100, score)
    
    def _generate_explanations(
        self,
        transaction: Dict[str, Any],
        features,
        ml_prediction: Dict[str, Any],
        fraud_patterns: Dict[str, Any],
        risk_assessment: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate explanations for the analysis."""
        explanations = {
            "risk_factors": risk_assessment.get("explanations", []),
            "contributing_factors": risk_assessment.get("contributing_factors", []),
            "pattern_explanations": [],
            "shap_explanation": None
        }
        
        # Pattern explanations
        for pattern in fraud_patterns.get("patterns", [])[:3]:
            pattern_type = pattern.get("type", "")
            explanations["pattern_explanations"].append(
                self.rule_explainer.explain_pattern(pattern_type)
            )
        
        # SHAP explanation
        if self.enable_explainability and self.shap_explainer and self.shap_explainer.is_initialized:
            try:
                shap_result = self.shap_explainer.explain_prediction(
                    features,
                    self.ml_model.classifier.classes_
                )
                explanations["shap_explanation"] = shap_result.get("explanation_text")
            except Exception as e:
                logger.warning(f"SHAP explanation failed: {e}")
        
        return explanations
    
    def batch_analyze(
        self,
        transactions: List[Dict[str, Any]],
        historical_data_map: Optional[Dict[str, List[Dict[str, Any]]]] = None
    ) -> List[Dict[str, Any]]:
        """
        Analyze a batch of transactions.
        
        Args:
            transactions: List of transaction dictionaries
            historical_data_map: Map of account numbers to their historical data
            
        Returns:
            List of analysis results
        """
        results = []
        
        for tx in transactions:
            sender = tx.get("sender_account", "")
            historical = historical_data_map.get(sender, []) if historical_data_map else None
            
            analysis = self.analyze_transaction(tx, historical)
            results.append(analysis)
        
        return results
    
    def add_feedback(
        self,
        transaction: Dict[str, Any],
        actual_label: str
    ) -> Dict[str, Any]:
        """
        Add feedback for continuous learning.
        
        Args:
            transaction: Transaction dictionary
            actual_label: Ground truth label
            
        Returns:
            Feedback result
        """
        if not self.enable_continuous_learning:
            return {"success": False, "error": "Continuous learning disabled"}
        
        # Get current prediction
        analysis = self.analyze_transaction(transaction)
        ml_prediction = analysis["ml_prediction"]
        
        # Record feedback
        feedback = self.continuous_learning.record_prediction_feedback(
            transaction,
            ml_prediction,
            actual_label
        )
        
        # Check if retraining is needed
        should_retrain, reason = self.continuous_learning.should_retrain()
        
        return {
            "success": True,
            "feedback": feedback,
            "should_retrain": should_retrain,
            "retrain_reason": reason
        }
    
    def retrain_if_needed(self) -> Dict[str, Any]:
        """
        Retrain model if conditions are met.
        
        Returns:
            Retraining result
        """
        if not self.enable_continuous_learning:
            return {"success": False, "error": "Continuous learning disabled"}
        
        should_retrain, reason = self.continuous_learning.should_retrain()
        
        if not should_retrain:
            return {
                "success": False,
                "message": "Retraining not needed",
                "reason": reason
            }
        
        # Perform retraining
        result = self.continuous_learning.retrain_model()
        
        return result
    
    def get_system_status(self) -> Dict[str, Any]:
        """
        Get overall system status.
        
        Returns:
            System status dictionary
        """
        current_model = self.model_registry.get_current_model()
        
        status = {
            "is_initialized": self.is_initialized,
            "model_info": get_model_info(),
            "current_model": {
                "model_id": current_model.get("model_id") if current_model else None,
                "model_version": current_model.get("model_version") if current_model else None,
                "deployed_at": current_model.get("deployed_at") if current_model else None
            },
            "features_enabled": {
                "advanced_features": self.use_advanced_features,
                "explainability": self.enable_explainability,
                "continuous_learning": self.enable_continuous_learning
            },
            "continuous_learning": None
        }
        
        if self.enable_continuous_learning:
            status["continuous_learning"] = self.continuous_learning.get_performance_summary()
        
        return status


# Global system instance
_default_system = AMLDetectionSystem()


def initialize_system(
    training_transactions: List[Dict[str, Any]],
    use_advanced_features: bool = True,
    enable_explainability: bool = True,
    enable_continuous_learning: bool = True
) -> Dict[str, Any]:
    """Initialize the AML system."""
    global _default_system
    _default_system = AMLDetectionSystem(
        use_advanced_features,
        enable_explainability,
        enable_continuous_learning
    )
    return _default_system.initialize_model(training_transactions)


def analyze_transaction(
    transaction: Dict[str, Any],
    historical_data: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """Analyze a single transaction."""
    return _default_system.analyze_transaction(transaction, historical_data)


def add_feedback(transaction: Dict[str, Any], actual_label: str) -> Dict[str, Any]:
    """Add feedback for continuous learning."""
    return _default_system.add_feedback(transaction, actual_label)


def get_system_status() -> Dict[str, Any]:
    """Get system status."""
    return _default_system.get_system_status()
