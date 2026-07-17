"""
aml_continuous_learning.py — Continuous Learning Pipeline for AML Models
=======================================================================
Implements continuous learning capabilities including:
- Incremental model training
- Performance monitoring
- Automatic retraining triggers
- Model drift detection
- A/B testing framework
"""

import json
import os
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from aml_ml_engine import AMLEnsembleModel, train_model, predict_risk
from aml_model_registry import ModelRegistry, register_model, deploy_model, get_current_model

logger = logging.getLogger(__name__)


class ContinuousLearningPipeline:
    """
    Manages continuous learning and model improvement over time.
    
    Features:
    - Performance monitoring
    - Drift detection
    - Automatic retraining triggers
    - A/B testing
    - Model comparison
    """
    
    def __init__(
        self,
        registry: Optional[ModelRegistry] = None,
        min_samples_for_retrain: int = 100,
        performance_threshold: float = 0.75,
        drift_threshold: float = 0.15
    ):
        """
        Initialize continuous learning pipeline.
        
        Args:
            registry: Model registry instance
            min_samples_for_retrain: Minimum new samples before retraining
            performance_threshold: Minimum F1 score threshold
            drift_threshold: Performance drift threshold for retraining
        """
        self.registry = registry or ModelRegistry()
        self.min_samples_for_retrain = min_samples_for_retrain
        self.performance_threshold = performance_threshold
        self.drift_threshold = drift_threshold
        
        self.new_labels = []
        self.performance_history = []
        self.last_retrain_time = None
        self.last_performance_score = None
        
        self._load_state()
    
    def _load_state(self) -> None:
        """Load pipeline state from file."""
        state_file = self.registry.registry_dir / "continuous_learning_state.json"
        if state_file.exists():
            try:
                with open(state_file, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                self.new_labels = state.get("new_labels", [])
                self.performance_history = state.get("performance_history", [])
                self.last_retrain_time = state.get("last_retrain_time")
                self.last_performance_score = state.get("last_performance_score")
            except Exception as e:
                logger.error(f"Failed to load pipeline state: {e}")
    
    def _save_state(self) -> None:
        """Save pipeline state to file."""
        state_file = self.registry.registry_dir / "continuous_learning_state.json"
        try:
            state = {
                "new_labels": self.new_labels,
                "performance_history": self.performance_history,
                "last_retrain_time": self.last_retrain_time,
                "last_performance_score": self.last_performance_score,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
            with open(state_file, 'w', encoding='utf-8') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save pipeline state: {e}")
    
    def add_labeled_transaction(self, transaction: Dict[str, Any], label: str) -> None:
        """
        Add a labeled transaction for future training.
        
        Args:
            transaction: Transaction dictionary
            label: Ground truth label (normal, suspicious, super_suspicious)
        """
        labeled_tx = dict(transaction)
        labeled_tx["ai_training_label"] = label
        labeled_tx["added_at"] = datetime.now(timezone.utc).isoformat()
        
        self.new_labels.append(labeled_tx)
        self._save_state()
        
        logger.info(f"Added labeled transaction. Total new labels: {len(self.new_labels)}")
    
    def add_labeled_batch(self, transactions: List[Dict[str, Any]], labels: List[str]) -> None:
        """
        Add a batch of labeled transactions.
        
        Args:
            transactions: List of transaction dictionaries
            labels: List of corresponding labels
        """
        for tx, label in zip(transactions, labels):
            self.add_labeled_transaction(tx, label)
    
    def should_retrain(self) -> Tuple[bool, str]:
        """
        Determine if model should be retrained.
        
        Returns:
            Tuple of (should_retrain, reason)
        """
        reasons = []
        
        # Check minimum samples
        if len(self.new_labels) >= self.min_samples_for_retrain:
            reasons.append(f"Minimum samples reached: {len(self.new_labels)}")
        
        # Check time since last retrain
        if self.last_retrain_time:
            last_retrain = datetime.fromisoformat(self.last_retrain_time)
            days_since_retrain = (datetime.now(timezone.utc) - last_retrain).days
            if days_since_retrain >= 30:  # Monthly retrain
                reasons.append(f"Monthly retrain due: {days_since_retrain} days since last retrain")
        
        # Check performance drift
        if self.last_performance_score and len(self.performance_history) >= 2:
            recent_perf = self.performance_history[-1]["f1_weighted"]
            if recent_perf < self.last_performance_score * (1 - self.drift_threshold):
                reasons.append(
                    f"Performance drift detected: {recent_perf:.3f} vs {self.last_performance_score:.3f}"
                )
        
        should_retrain = len(reasons) > 0
        reason = "; ".join(reasons) if reasons else "No retrain trigger met"
        
        return should_retrain, reason
    
    def retrain_model(
        self,
        historical_transactions: Optional[List[Dict[str, Any]]] = None,
        validation_split: float = 0.2
    ) -> Dict[str, Any]:
        """
        Retrain model with new labeled data.
        
        Args:
            historical_transactions: Additional historical transactions
            validation_split: Validation split fraction
            
        Returns:
            Training result dictionary
        """
        if len(self.new_labels) < self.min_samples_for_retrain:
            return {
                "success": False,
                "error": f"Insufficient new labels: {len(self.new_labels)} < {self.min_samples_for_retrain}"
            }
        
        logger.info(f"Starting retraining with {len(self.new_labels)} new labels")
        
        # Combine new labels with historical data
        training_data = list(self.new_labels)
        if historical_transactions:
            training_data.extend(historical_transactions)
        
        # Train new model
        model = AMLEnsembleModel()
        training_result = model.train(training_data, validation_split)
        
        if not training_result.get("success"):
            return training_result
        
        # Get current model for comparison
        current_model = self.registry.get_current_model()
        
        # Register new model
        model_version = f"3.0.{len(self.registry.list_models()) + 1}"
        model_path = f"aml_ai_model_v{model_version}.pkl"
        
        # Save model
        model.save(model_path, f"{model_path}_meta.json")
        
        # Register in registry
        metadata = training_result.get("metadata", {})
        performance_metrics = {
            "f1_weighted": metadata.get("cross_val_scores", {}).get("f1_weighted", 0),
            "accuracy": metadata.get("cross_val_scores", {}).get("accuracy", 0),
            "training_samples": metadata.get("training_samples", 0)
        }
        
        model_id = self.registry.register_model(
            model_version,
            model_path,
            metadata,
            performance_metrics
        )
        
        # Compare with current model
        comparison = None
        if current_model:
            current_metrics = current_model.get("performance_metrics", {})
            comparison = {
                "previous_f1": current_metrics.get("f1_weighted", 0),
                "new_f1": performance_metrics.get("f1_weighted", 0),
                "improvement": performance_metrics.get("f1_weighted", 0) - current_metrics.get("f1_weighted", 0)
            }
            
            # Deploy if better
            if comparison["improvement"] > 0:
                self.registry.deploy_model(model_id, "continuous_learning")
                logger.info(f"Deployed improved model: {model_id}")
            else:
                logger.info(f"New model not better. Keeping current model.")
        else:
            # Deploy if no current model
            self.registry.deploy_model(model_id, "continuous_learning")
            logger.info(f"Deployed first model: {model_id}")
        
        # Update state
        self.new_labels = []
        self.last_retrain_time = datetime.now(timezone.utc).isoformat()
        self.last_performance_score = performance_metrics.get("f1_weighted")
        self.performance_history.append({
            "timestamp": self.last_retrain_time,
            "model_id": model_id,
            "f1_weighted": performance_metrics.get("f1_weighted"),
            "accuracy": performance_metrics.get("accuracy")
        })
        self._save_state()
        
        # Clean up temporary model file
        if os.path.exists(model_path):
            os.remove(model_path)
        if os.path.exists(f"{model_path}_meta.json"):
            os.remove(f"{model_path}_meta.json")
        
        return {
            "success": True,
            "model_id": model_id,
            "model_version": model_version,
            "performance_metrics": performance_metrics,
            "comparison": comparison,
            "new_labels_used": len(self.new_labels) if not historical_transactions else len(self.new_labels) + len(historical_transactions)
        }
    
    def record_prediction_feedback(
        self,
        transaction: Dict[str, Any],
        prediction: Dict[str, Any],
        actual_label: str
    ) -> Dict[str, Any]:
        """
        Record feedback on prediction accuracy.
        
        Args:
            transaction: Original transaction
            prediction: Model prediction
            actual_label: Ground truth label
            
        Returns:
            Feedback record
        """
        predicted_label = prediction.get("risk_level", "normal")
        confidence = prediction.get("confidence", 0)
        
        is_correct = predicted_label == actual_label
        
        feedback = {
            "transaction_id": transaction.get("id"),
            "predicted_label": predicted_label,
            "actual_label": actual_label,
            "is_correct": is_correct,
            "confidence": confidence,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Add to labeled data if incorrect
        if not is_correct:
            self.add_labeled_transaction(transaction, actual_label)
        
        return feedback
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Get performance summary.
        
        Returns:
            Performance summary dictionary
        """
        current_model = self.registry.get_current_model()
        
        summary = {
            "current_model": {
                "model_id": current_model.get("model_id") if current_model else None,
                "model_version": current_model.get("model_version") if current_model else None,
                "deployed_at": current_model.get("deployed_at") if current_model else None
            },
            "new_labels_pending": len(self.new_labels),
            "last_retrain": self.last_retrain_time,
            "last_performance_score": self.last_performance_score,
            "should_retrain": self.should_retrain()[0],
            "performance_history": self.performance_history[-10:]  # Last 10 entries
        }
        
        return summary


class ABTestFramework:
    """
    A/B testing framework for comparing model versions.
    """
    
    def __init__(self, registry: Optional[ModelRegistry] = None):
        """
        Initialize A/B testing framework.
        
        Args:
            registry: Model registry instance
        """
        self.registry = registry or ModelRegistry()
        self.active_tests = {}
    
    def start_ab_test(
        self,
        model_a_id: str,
        model_b_id: str,
        traffic_split: float = 0.5,
        test_duration_hours: int = 168
    ) -> str:
        """
        Start an A/B test between two models.
        
        Args:
            model_a_id: First model ID
            model_b_id: Second model ID
            traffic_split: Fraction of traffic to model A (0-1)
            test_duration_hours: Duration of test in hours
            
        Returns:
            Test ID
        """
        test_id = f"ab_test_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        
        # Verify models exist
        model_a = self.registry.get_model_record(model_a_id)
        model_b = self.registry.get_model_record(model_b_id)
        
        if not model_a or not model_b:
            raise ValueError("One or both models not found")
        
        self.active_tests[test_id] = {
            "model_a_id": model_a_id,
            "model_b_id": model_b_id,
            "traffic_split": traffic_split,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "ends_at": (datetime.now(timezone.utc) + timedelta(hours=test_duration_hours)).isoformat(),
            "results_a": [],
            "results_b": [],
            "status": "active"
        }
        
        logger.info(f"A/B test started: {test_id}")
        return test_id
    
    def record_ab_test_result(
        self,
        test_id: str,
        model_used: str,
        transaction: Dict[str, Any],
        prediction: Dict[str, Any],
        actual_label: Optional[str] = None
    ) -> None:
        """
        Record result from A/B test.
        
        Args:
            test_id: Test ID
            model_used: Which model was used (a or b)
            transaction: Transaction data
            prediction: Model prediction
            actual_label: Optional ground truth label
        """
        if test_id not in self.active_tests:
            logger.warning(f"Test not found: {test_id}")
            return
        
        result = {
            "transaction_id": transaction.get("id"),
            "prediction": prediction,
            "actual_label": actual_label,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        if model_used == "a":
            self.active_tests[test_id]["results_a"].append(result)
        elif model_used == "b":
            self.active_tests[test_id]["results_b"].append(result)
    
    def get_ab_test_results(self, test_id: str) -> Optional[Dict[str, Any]]:
        """
        Get A/B test results.
        
        Args:
            test_id: Test ID
            
        Returns:
            Test results dictionary
        """
        if test_id not in self.active_tests:
            return None
        
        test = self.active_tests[test_id]
        
        # Calculate metrics for each model
        results_a = test["results_a"]
        results_b = test["results_b"]
        
        def calculate_metrics(results):
            if not results:
                return {}
            
            correct = sum(1 for r in results if r.get("actual_label") and r.get("prediction", {}).get("risk_level") == r.get("actual_label"))
            total = len([r for r in results if r.get("actual_label")])
            
            return {
                "total_predictions": len(results),
                "labeled_predictions": total,
                "accuracy": correct / total if total > 0 else 0
            }
        
        return {
            "test_id": test_id,
            "status": test["status"],
            "started_at": test["started_at"],
            "ends_at": test["ends_at"],
            "model_a": {
                "model_id": test["model_a_id"],
                "metrics": calculate_metrics(results_a)
            },
            "model_b": {
                "model_id": test["model_b_id"],
                "metrics": calculate_metrics(results_b)
            }
        }
    
    def end_ab_test(self, test_id: str, winner: str) -> bool:
        """
        End A/B test and deploy winner.
        
        Args:
            test_id: Test ID
            winner: Which model won (a or b)
            
        Returns:
            True if successful
        """
        if test_id not in self.active_tests:
            return False
        
        test = self.active_tests[test_id]
        winner_id = test["model_a_id"] if winner == "a" else test["model_b_id"]
        
        # Deploy winner
        success = self.registry.deploy_model(winner_id, "ab_test")
        
        test["status"] = "completed"
        test["winner"] = winner
        test["completed_at"] = datetime.now(timezone.utc).isoformat()
        
        return success


# Global instances
_default_pipeline = ContinuousLearningPipeline()
_default_ab_test = ABTestFramework()


def add_labeled_transaction(transaction: Dict[str, Any], label: str) -> None:
    """Add labeled transaction for continuous learning."""
    _default_pipeline.add_labeled_transaction(transaction, label)


def check_retrain_needed() -> Tuple[bool, str]:
    """Check if model should be retrained."""
    return _default_pipeline.should_retrain()


def retrain_model(historical_transactions: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Retrain model with new data."""
    return _default_pipeline.retrain_model(historical_transactions)


def get_performance_summary() -> Dict[str, Any]:
    """Get performance summary."""
    return _default_pipeline.get_performance_summary()
