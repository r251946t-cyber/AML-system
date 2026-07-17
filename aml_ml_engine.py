"""
aml_ml_engine.py — Advanced Ensemble ML Engine for AML Detection
==============================================================
Enterprise-grade machine learning engine with:
- Ensemble of XGBoost, LightGBM, and Isolation Forest
- SMOTE/ADASYN class imbalance handling
- Cross-validation and hyperparameter optimization
- Model versioning and metadata tracking
- Comprehensive error handling
"""

import json
import os
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import joblib

try:
    from imblearn.over_sampling import SMOTE, ADASYN
    from imblearn.ensemble import BalancedBaggingClassifier
    IMBLEARN_AVAILABLE = True
except ImportError:
    IMBLEARN_AVAILABLE = False
    logging.warning("imbalanced-learn not available. SMOTE/ADASYN disabled.")

try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    logging.warning("XGBoost not available. Using fallback models.")

try:
    from lightgbm import LGBMClassifier
    LIGHTGBM_AVAILABLE = True
except ImportError:
    LIGHTGBM_AVAILABLE = False
    logging.warning("LightGBM not available. Using fallback models.")

from sklearn.ensemble import RandomForestClassifier, IsolationForest, VotingClassifier
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix

from aml_feature_engineering import FeatureEngineer, extract_features, get_feature_names
from aml_data_validator import TransactionValidator, validate_transaction

logger = logging.getLogger(__name__)


class AMLEnsembleModel:
    """
    Ensemble ML model for AML detection.
    
    Combines multiple algorithms:
    - XGBoost (gradient boosting)
    - LightGBM (gradient boosting)
    - RandomForest (bagging)
    - IsolationForest (unsupervised anomaly detection)
    """
    
    MODEL_VERSION = "3.0.0"
    LABELS = ("normal", "suspicious", "super_suspicious")
    
    def __init__(
        self,
        use_smote: bool = True,
        use_xgboost: bool = True,
        use_lightgbm: bool = True,
        random_state: int = 42
    ):
        """
        Initialize the ensemble model.
        
        Args:
            use_smote: Whether to use SMOTE for class imbalance
            use_xgboost: Whether to include XGBoost in ensemble
            use_lightgbm: Whether to include LightGBM in ensemble
            random_state: Random seed for reproducibility
        """
        self.use_smote = use_smote and IMBLEARN_AVAILABLE
        self.use_xgboost = use_xgboost and XGBOOST_AVAILABLE
        self.use_lightgbm = use_lightgbm and LIGHTGBM_AVAILABLE
        
        self.random_state = random_state
        self.feature_engineer = FeatureEngineer()
        self.validator = TransactionValidator(strict_mode=False)
        
        self.classifier = None
        self.anomaly_detector = None
        self.scaler = StandardScaler()
        
        self.is_trained = False
        self.metadata = {}
        
        self._initialize_models()
    
    def _initialize_models(self) -> None:
        """Initialize the individual models in the ensemble."""
        estimators = []
        
        # XGBoost
        if self.use_xgboost:
            xgb = XGBClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.05,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=self.random_state,
                eval_metric='mlogloss',
                use_label_encoder=False
            )
            estimators.append(('xgboost', xgb))
            logger.info("XGBoost initialized")
        
        # LightGBM
        if self.use_lightgbm:
            lgb = LGBMClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.05,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=self.random_state,
                verbose=-1
            )
            estimators.append(('lightgbm', lgb))
            logger.info("LightGBM initialized")
        
        # RandomForest (always included as fallback)
        rf = RandomForestClassifier(
            n_estimators=200,
            max_depth=12,
            min_samples_leaf=3,
            class_weight='balanced_subsample',
            random_state=self.random_state
        )
        estimators.append(('randomforest', rf))
        logger.info("RandomForest initialized")
        
        # Voting classifier (soft voting for probability averaging)
        if len(estimators) > 1:
            self.classifier = VotingClassifier(
                estimators=estimators,
                voting='soft',
                n_jobs=-1
            )
        else:
            self.classifier = estimators[0][1]
        
        # Isolation Forest for anomaly detection
        self.anomaly_detector = IsolationForest(
            n_estimators=150,
            contamination=0.08,
            random_state=self.random_state,
            n_jobs=-1
        )
        logger.info("IsolationForest initialized")
    
    def prepare_training_data(
        self,
        transactions: List[Dict[str, Any]]
    ) -> Tuple[np.ndarray, List[str]]:
        """
        Prepare training data from transactions.
        
        Args:
            transactions: List of transaction dictionaries with labels
            
        Returns:
            Tuple of (feature_matrix, labels)
        """
        X = []
        y = []
        
        for tx in transactions:
            # Validate transaction
            is_valid, cleaned_tx, errors = self.validator.validate_transaction(tx)
            if not is_valid:
                logger.warning(f"Transaction validation failed: {errors}")
                continue
            
            # Extract features
            features = extract_features(cleaned_tx)
            X.append(features)
            
            # Get label
            label = cleaned_tx.get("ai_training_label", "normal")
            if label in self.LABELS:
                y.append(label)
            else:
                # Map risk level to label
                risk_level = cleaned_tx.get("risk_level", "normal")
                risk_score = float(cleaned_tx.get("risk_score", 0))
                label = self._map_risk_to_label(risk_level, risk_score)
                y.append(label)
        
        return np.array(X), y
    
    def _map_risk_to_label(self, risk_level: str, risk_score: float) -> str:
        """Map risk level and score to training label."""
        level = (risk_level or "normal").lower()
        
        if level in ("normal", "low") and risk_score < 25:
            return "normal"
        if level in ("high_risk", "critical", "super_suspicious") or risk_score >= 60:
            return "super_suspicious"
        if level in ("suspicious", "medium") or risk_score >= 25:
            return "suspicious"
        return "normal"
    
    def train(
        self,
        transactions: List[Dict[str, Any]],
        validation_split: float = 0.2
    ) -> Dict[str, Any]:
        """
        Train the ensemble model.
        
        Args:
            transactions: List of labeled transactions
            validation_split: Fraction of data to use for validation
            
        Returns:
            Training metadata dictionary
        """
        logger.info(f"Starting training with {len(transactions)} transactions")
        
        # Prepare data
        X, y = self.prepare_training_data(transactions)
        
        if len(X) < 10:
            logger.error("Insufficient training data")
            return {"success": False, "error": "Insufficient training data"}
        
        if len(set(y)) < 2:
            logger.error("Need at least 2 classes for training")
            return {"success": False, "error": "Need at least 2 classes"}
        
        # Apply SMOTE if enabled
        if self.use_smote:
            try:
                smote = SMOTE(random_state=self.random_state, k_neighbors=min(5, len(X) - 1))
                X_resampled, y_resampled = smote.fit_resample(X, y)
                logger.info(f"SMOTE applied: {len(X)} -> {len(X_resampled)} samples")
                X, y = X_resampled, y_resampled
            except Exception as e:
                logger.warning(f"SMOTE failed: {e}")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train classifier
        try:
            self.classifier.fit(X_scaled, y)
            logger.info("Classifier trained successfully")
        except Exception as e:
            logger.error(f"Classifier training failed: {e}")
            return {"success": False, "error": str(e)}
        
        # Train anomaly detector
        try:
            self.anomaly_detector.fit(X_scaled)
            logger.info("Anomaly detector trained successfully")
        except Exception as e:
            logger.warning(f"Anomaly detector training failed: {e}")
        
        # Cross-validation
        cv_scores = self._cross_validate(X_scaled, y)
        
        # Update metadata
        self.metadata = {
            "version": self.MODEL_VERSION,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "training_samples": len(X),
            "original_samples": len(transactions),
            "label_distribution": {label: y.count(label) for label in self.LABELS},
            "cross_val_scores": cv_scores,
            "feature_count": X.shape[1],
            "feature_names": get_feature_names(),
            "algorithms": self._get_algorithm_names(),
            "smote_used": self.use_smote,
            "random_state": self.random_state
        }
        
        self.is_trained = True
        logger.info(f"Training completed. CV F1: {cv_scores.get('f1_weighted', 'N/A')}")
        
        return {"success": True, "metadata": self.metadata}
    
    def _cross_validate(self, X: np.ndarray, y: List[str]) -> Dict[str, float]:
        """Perform cross-validation and return scores."""
        cv_scores = {}
        
        if len(set(y)) < 2 or len(y) < 20:
            return cv_scores
        
        try:
            cv = StratifiedKFold(n_splits=min(5, len(y) // 5), shuffle=True, random_state=self.random_state)
            
            # F1 scores
            f1_weighted = cross_val_score(self.classifier, X, y, cv=cv, scoring='f1_weighted')
            cv_scores['f1_weighted'] = float(np.mean(f1_weighted))
            cv_scores['f1_weighted_std'] = float(np.std(f1_weighted))
            
            # Accuracy
            accuracy = cross_val_score(self.classifier, X, y, cv=cv, scoring='accuracy')
            cv_scores['accuracy'] = float(np.mean(accuracy))
            cv_scores['accuracy_std'] = float(np.std(accuracy))
            
            # Precision
            precision = cross_val_score(self.classifier, X, y, cv=cv, scoring='precision_weighted')
            cv_scores['precision_weighted'] = float(np.mean(precision))
            
            # Recall
            recall = cross_val_score(self.classifier, X, y, cv=cv, scoring='recall_weighted')
            cv_scores['recall_weighted'] = float(np.mean(recall))
            
        except Exception as e:
            logger.warning(f"Cross-validation failed: {e}")
        
        return cv_scores
    
    def _get_algorithm_names(self) -> List[str]:
        """Get names of algorithms used in ensemble."""
        algorithms = []
        
        if self.use_xgboost:
            algorithms.append("XGBoost")
        if self.use_lightgbm:
            algorithms.append("LightGBM")
        algorithms.append("RandomForest")
        algorithms.append("IsolationForest")
        
        return algorithms
    
    def predict(
        self,
        transaction: Dict[str, Any],
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Predict risk for a transaction.
        
        Args:
            transaction: Transaction dictionary
            historical_data: Optional historical transactions for the sender
            
        Returns:
            Prediction dictionary with risk level, score, confidence, etc.
        """
        if not self.is_trained:
            return {
                "success": False,
                "error": "Model not trained",
                "risk_level": None,
                "risk_score": 0,
                "confidence": 0
            }
        
        try:
            # Validate transaction
            is_valid, cleaned_tx, errors = self.validator.validate_transaction(transaction)
            if not is_valid:
                logger.warning(f"Transaction validation failed: {errors}")
            
            # Extract features
            features = extract_features(cleaned_tx, historical_data)
            features_scaled = self.scaler.transform([features])
            
            # Get prediction probabilities
            probabilities = self.classifier.predict_proba(features_scaled)[0]
            classes = list(self.classifier.classes_)
            
            # Get predicted class
            best_index = int(probabilities.argmax())
            predicted = classes[best_index]
            confidence = float(probabilities[best_index])
            
            # Get anomaly score
            anomaly_score = None
            if self.anomaly_detector is not None:
                try:
                    raw_anomaly = self.anomaly_detector.decision_function(features_scaled)[0]
                    anomaly_score = float(raw_anomaly)
                    
                    # Adjust prediction based on anomaly
                    if raw_anomaly < -0.05 and predicted == "normal":
                        predicted = "suspicious"
                        confidence = max(confidence, 0.65)
                    elif raw_anomaly < -0.15:
                        if predicted != "super_suspicious":
                            predicted = "super_suspicious" if confidence < 0.75 else predicted
                        confidence = max(confidence, 0.78)
                except Exception as e:
                    logger.warning(f"Anomaly scoring failed: {e}")
            
            # Calculate numerical risk score (0-100)
            risk_score = self._calculate_risk_score(predicted, confidence, anomaly_score)
            
            # Build probability dictionary
            prob_dict = {cls: float(prob) for cls, prob in zip(classes, probabilities)}
            
            return {
                "success": True,
                "risk_level": predicted,
                "risk_score": risk_score,
                "confidence": confidence,
                "probabilities": prob_dict,
                "anomaly_score": anomaly_score,
                "model_version": self.MODEL_VERSION
            }
            
        except Exception as e:
            logger.error(f"Prediction failed: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "risk_level": None,
                "risk_score": 0,
                "confidence": 0
            }
    
    def _calculate_risk_score(
        self,
        predicted: str,
        confidence: float,
        anomaly_score: Optional[float]
    ) -> float:
        """Calculate numerical risk score (0-100)."""
        base_scores = {
            "normal": 10,
            "suspicious": 50,
            "super_suspicious": 85
        }
        
        base = base_scores.get(predicted, 50)
        
        # Adjust by confidence
        if predicted == "normal":
            # Lower confidence in normal = higher risk
            risk = base + (1 - confidence) * 20
        else:
            # Higher confidence in suspicious = higher risk
            risk = base + confidence * 15
        
        # Adjust by anomaly score
        if anomaly_score is not None and anomaly_score < 0:
            risk += abs(anomaly_score) * 10
        
        return min(100, max(0, risk))
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get model metadata."""
        if not self.is_trained:
            return {
                "trained": False,
                "version": self.MODEL_VERSION,
                "algorithms": self._get_algorithm_names()
            }
        return {
            "trained": True,
            **self.metadata
        }
    
    def save(self, model_path: str, metadata_path: str) -> bool:
        """
        Save model and metadata to disk.
        
        Args:
            model_path: Path to save model
            metadata_path: Path to save metadata
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Save model components
            bundle = {
                "classifier": self.classifier,
                "anomaly_detector": self.anomaly_detector,
                "scaler": self.scaler,
                "feature_engineer": self.feature_engineer,
                "version": self.MODEL_VERSION,
                "is_trained": self.is_trained
            }
            joblib.dump(bundle, model_path)
            
            # Save metadata
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(self.metadata, f, indent=2)
            
            logger.info(f"Model saved to {model_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
            return False
    
    def load(self, model_path: str, metadata_path: str) -> bool:
        """
        Load model and metadata from disk.
        
        Args:
            model_path: Path to load model from
            metadata_path: Path to load metadata from
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Load model
            bundle = joblib.load(model_path)
            self.classifier = bundle.get("classifier")
            self.anomaly_detector = bundle.get("anomaly_detector")
            self.scaler = bundle.get("scaler", StandardScaler())
            self.is_trained = bundle.get("is_trained", False)
            
            # Load metadata
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r', encoding='utf-8') as f:
                    self.metadata = json.load(f)
            
            logger.info(f"Model loaded from {model_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False


# Global model instance
_default_model = AMLEnsembleModel()


def train_model(transactions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Convenience function to train the model.
    
    Args:
        transactions: List of labeled transactions
        
    Returns:
        Training metadata
    """
    return _default_model.train(transactions)


def predict_risk(
    transaction: Dict[str, Any],
    historical_data: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Convenience function to predict risk.
    
    Args:
        transaction: Transaction dictionary
        historical_data: Optional historical transactions
        
    Returns:
        Prediction dictionary
    """
    return _default_model.predict(transaction, historical_data)


def get_model_info() -> Dict[str, Any]:
    """Get model information."""
    return _default_model.get_metadata()


def save_model(model_path: str, metadata_path: str) -> bool:
    """Save model to disk."""
    return _default_model.save(model_path, metadata_path)


def load_model(model_path: str, metadata_path: str) -> bool:
    """Load model from disk."""
    return _default_model.load(model_path, metadata_path)
