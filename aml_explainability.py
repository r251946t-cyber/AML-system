"""
aml_explainability.py — Model Explainability for AML Detection
=============================================================
Provides SHAP-based explainability for ML predictions including:
- Feature importance scores
- SHAP values for individual predictions
- Global feature importance
- Local explanation generation
- Human-readable explanations
"""

from typing import Any, Dict, List, Optional, Tuple
import logging
import numpy as np

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    logging.warning("SHAP not available. Explainability features limited.")

from aml_feature_engineering import get_feature_names

logger = logging.getLogger(__name__)


class ModelExplainer:
    """
    Provides explainability for AML ML predictions using SHAP.
    """
    
    def __init__(self):
        """Initialize the model explainer."""
        self.explainer = None
        self.feature_names = get_feature_names()
        self.is_initialized = False
    
    def initialize(self, model, background_data: np.ndarray) -> bool:
        """
        Initialize SHAP explainer with model and background data.
        
        Args:
            model: Trained ML model
            background_data: Background dataset for SHAP
            
        Returns:
            True if successful, False otherwise
        """
        if not SHAP_AVAILABLE:
            logger.warning("SHAP not available, explainability disabled")
            return False
        
        try:
            # Use TreeExplainer for tree-based models (XGBoost, LightGBM, RandomForest)
            self.explainer = shap.TreeExplainer(model, background_data)
            self.is_initialized = True
            logger.info("SHAP explainer initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize SHAP explainer: {e}")
            # Fallback to KernelExplainer
            try:
                self.explainer = shap.KernelExplainer(model.predict_proba, background_data)
                self.is_initialized = True
                logger.info("SHAP KernelExplainer initialized as fallback")
                return True
            except Exception as e2:
                logger.error(f"Failed to initialize KernelExplainer: {e2}")
                return False
    
    def explain_prediction(
        self,
        transaction_features: np.ndarray,
        model_classes: List[str]
    ) -> Dict[str, Any]:
        """
        Generate explanation for a single prediction.
        
        Args:
            transaction_features: Feature vector for the transaction
            model_classes: List of model class names
            
        Returns:
            Explanation dictionary with SHAP values and feature importance
        """
        if not self.is_initialized or self.explainer is None:
            return {
                "success": False,
                "error": "Explainer not initialized",
                "explanation": None
            }
        
        try:
            # Reshape for single prediction
            if len(transaction_features.shape) == 1:
                transaction_features = transaction_features.reshape(1, -1)
            
            # Calculate SHAP values
            shap_values = self.explainer.shap_values(transaction_features)
            
            # Handle multi-class output
            if isinstance(shap_values, list):
                # Multi-class: use values for predicted class
                shap_values_array = shap_values[0]  # Use first class
            else:
                shap_values_array = shap_values
            
            # Get base value (expected value)
            if hasattr(self.explainer, 'expected_value'):
                base_value = self.explainer.expected_value
                if isinstance(base_value, list):
                    base_value = base_value[0]
            else:
                base_value = 0.0
            
            # Calculate feature importance
            feature_importance = self._calculate_feature_importance(
                shap_values_array[0],
                transaction_features[0]
            )
            
            # Generate human-readable explanation
            explanation_text = self._generate_explanation_text(
                shap_values_array[0],
                transaction_features[0],
                feature_importance[:5]  # Top 5 features
            )
            
            return {
                "success": True,
                "shap_values": shap_values_array[0].tolist(),
                "base_value": float(base_value),
                "feature_importance": feature_importance,
                "explanation_text": explanation_text,
                "feature_names": self.feature_names
            }
            
        except Exception as e:
            logger.error(f"Failed to generate explanation: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "explanation": None
            }
    
    def _calculate_feature_importance(
        self,
        shap_values: np.ndarray,
        feature_values: np.ndarray
    ) -> List[Dict[str, Any]]:
        """
        Calculate feature importance from SHAP values.
        
        Args:
            shap_values: SHAP values for the prediction
            feature_values: Actual feature values
            
        Returns:
            List of feature importance dictionaries
        """
        importance = []
        
        # Calculate absolute SHAP values
        abs_shap = np.abs(shap_values)
        
        for i, (shap_val, feat_val) in enumerate(zip(shap_values, feature_values)):
            importance.append({
                "feature_index": i,
                "feature_name": self.feature_names[i] if i < len(self.feature_names) else f"feature_{i}",
                "shap_value": float(shap_val),
                "absolute_shap": float(abs_shap[i]),
                "feature_value": float(feat_val),
                "direction": "increases_risk" if shap_val > 0 else "decreases_risk"
            })
        
        # Sort by absolute SHAP value
        importance.sort(key=lambda x: x["absolute_shap"], reverse=True)
        
        return importance
    
    def _generate_explanation_text(
        self,
        shap_values: np.ndarray,
        feature_values: np.ndarray,
        top_features: List[Dict[str, Any]]
    ) -> str:
        """
        Generate human-readable explanation text.
        
        Args:
            shap_values: SHAP values
            feature_values: Feature values
            top_features: Top contributing features
            
        Returns:
            Human-readable explanation text
        """
        explanations = []
        
        for feat in top_features:
            name = feat["feature_name"]
            value = feat["feature_value"]
            shap_val = feat["shap_value"]
            direction = feat["direction"]
            
            # Format feature name for readability
            readable_name = name.replace("_", " ").title()
            
            # Format value
            if abs(value) < 0.01:
                value_str = f"{value:.4f}"
            elif abs(value) < 100:
                value_str = f"{value:.2f}"
            else:
                value_str = f"{value:,.0f}"
            
            # Generate explanation
            if direction == "increases_risk":
                explanations.append(
                    f"{readable_name} = {value_str} increases risk (SHAP: {shap_val:.3f})"
                )
            else:
                explanations.append(
                    f"{readable_name} = {value_str} decreases risk (SHAP: {shap_val:.3f})"
                )
        
        return "; ".join(explanations)
    
    def get_global_feature_importance(
        self,
        X: np.ndarray,
        max_features: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Calculate global feature importance across dataset.
        
        Args:
            X: Feature matrix
            max_features: Maximum number of features to return
            
        Returns:
            List of global feature importance
        """
        if not self.is_initialized or self.explainer is None:
            return []
        
        try:
            # Calculate SHAP values for entire dataset
            shap_values = self.explainer.shap_values(X)
            
            # Handle multi-class output
            if isinstance(shap_values, list):
                shap_values_array = shap_values[0]
            else:
                shap_values_array = shap_values
            
            # Calculate mean absolute SHAP values
            mean_abs_shap = np.mean(np.abs(shap_values_array), axis=0)
            
            # Build importance list
            importance = []
            for i, mean_shap in enumerate(mean_abs_shap):
                importance.append({
                    "feature_index": i,
                    "feature_name": self.feature_names[i] if i < len(self.feature_names) else f"feature_{i}",
                    "mean_absolute_shap": float(mean_shap)
                })
            
            # Sort by importance
            importance.sort(key=lambda x: x["mean_absolute_shap"], reverse=True)
            
            return importance[:max_features]
            
        except Exception as e:
            logger.error(f"Failed to calculate global feature importance: {e}")
            return []
    
    def get_feature_summary(
        self,
        feature_name: str,
        X: np.ndarray
    ) -> Dict[str, Any]:
        """
        Get summary statistics for a specific feature.
        
        Args:
            feature_name: Name of the feature
            X: Feature matrix
            
        Returns:
            Feature summary dictionary
        """
        if feature_name not in self.feature_names:
            return {"error": f"Feature {feature_name} not found"}
        
        feature_idx = self.feature_names.index(feature_name)
        feature_values = X[:, feature_idx]
        
        return {
            "feature_name": feature_name,
            "mean": float(np.mean(feature_values)),
            "std": float(np.std(feature_values)),
            "min": float(np.min(feature_values)),
            "max": float(np.max(feature_values)),
            "median": float(np.median(feature_values)),
            "q25": float(np.percentile(feature_values, 25)),
            "q75": float(np.percentile(feature_values, 75))
        }


class RuleBasedExplainer:
    """
    Provides rule-based explanations for fraud patterns and risk factors.
    """
    
    def __init__(self):
        """Initialize rule-based explainer."""
        self.rule_explanations = {
            "structuring": "Multiple transactions just below $10,000 reporting threshold suggest structuring to avoid detection",
            "layering": "Rapid transfers to multiple accounts indicate layering to obscure audit trail",
            "funnel_account": "Account receives from many sources and sends to few destinations, typical of consolidation",
            "circular_transfer": "Funds moving in circles (A->B->A) create false appearance of legitimate activity",
            "money_mule": "Account quickly passes through received funds, characteristic of money mule behavior",
            "rapid_movement": "Large amounts moved quickly suggest attempt to avoid detection",
            "round_tripping": "Funds sent out and returned create false business activity appearance",
            "self_laundering": "Transfers between same customer's accounts obscure fund origin",
            "dormant_activation": "Sudden activity on long-dormant account is suspicious",
            "transaction_burst": "Unusually high transaction frequency indicates potential automated activity",
            "shell_company_behavior": "Consistent high-value transactions with low variation suggest shell company"
        }
    
    def explain_pattern(self, pattern_type: str) -> str:
        """
        Get explanation for a fraud pattern.
        
        Args:
            pattern_type: Type of fraud pattern
            
        Returns:
            Explanation text
        """
        return self.rule_explanations.get(
            pattern_type,
            f"Suspicious pattern detected: {pattern_type}"
        )
    
    def explain_risk_factors(
        self,
        risk_factors: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Generate explanations for risk factors.
        
        Args:
            risk_factors: List of risk factor dictionaries
            
        Returns:
            List of explanation strings
        """
        explanations = []
        
        for factor in risk_factors:
            factor_name = factor.get("factor", "")
            description = factor.get("description", "")
            value = factor.get("value", 0)
            
            if description:
                explanations.append(description)
            else:
                explanations.append(f"{factor_name} contributes to risk (value: {value})")
        
        return explanations


# Global explainer instances
_shap_explainer = ModelExplainer()
_rule_explainer = RuleBasedExplainer()


def initialize_explainer(model, background_data: np.ndarray) -> bool:
    """Initialize SHAP explainer."""
    return _shap_explainer.initialize(model, background_data)


def explain_prediction(
    transaction_features: np.ndarray,
    model_classes: List[str]
) -> Dict[str, Any]:
    """Generate explanation for prediction."""
    return _shap_explainer.explain_prediction(transaction_features, model_classes)


def get_global_importance(X: np.ndarray, max_features: int = 20) -> List[Dict[str, Any]]:
    """Get global feature importance."""
    return _shap_explainer.get_global_feature_importance(X, max_features)


def explain_pattern(pattern_type: str) -> str:
    """Get explanation for fraud pattern."""
    return _rule_explainer.explain_pattern(pattern_type)


def explain_risk_factors(risk_factors: List[Dict[str, Any]]) -> List[str]:
    """Generate explanations for risk factors."""
    return _rule_explainer.explain_risk_factors(risk_factors)
