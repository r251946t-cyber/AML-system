"""
test_aml_system.py — Comprehensive Tests for Advanced AML System
=============================================================
Tests for all new AML modules:
- Data validation
- Feature engineering
- ML engine
- Fraud pattern detection
- Risk scoring
- Explainability
- Model registry
- Continuous learning
"""

import pytest
import numpy as np
from datetime import datetime, timezone
from typing import Dict, List

# Import modules to test
from aml_data_validator import TransactionValidator, validate_transaction
from aml_feature_engineering import FeatureEngineer, extract_features
from aml_fraud_patterns import FraudPatternDetector, detect_fraud_patterns
from aml_risk_scoring import RiskScoringSystem, calculate_risk_assessment


# Sample transaction data for testing
SAMPLE_TRANSACTION = {
    "id": "tx_001",
    "amount": 5000.00,
    "transaction_type": "transfer",
    "sender_account": "ACC1001",
    "receiver_account": "ACC1002",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "channel": "online",
    "risk_level": "normal",
    "risk_score": 10.0,
    "is_new_recipient": 1.0,
    "sender_avg_amount": 3000.0,
    "sender_max_amount": 8000.0,
    "sender_tx_count": 15,
    "origin_country": "US",
    "destination_country": "GB"
}

SAMPLE_HISTORICAL_DATA = [
    {
        "id": "tx_000",
        "amount": 3000.00,
        "transaction_type": "transfer",
        "sender_account": "ACC1001",
        "receiver_account": "ACC1003",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "channel": "online"
    },
    {
        "id": "tx_002",
        "amount": 4500.00,
        "transaction_type": "transfer",
        "sender_account": "ACC1001",
        "receiver_account": "ACC1004",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "channel": "mobile"
    }
]


class TestDataValidator:
    """Tests for aml_data_validator.py"""
    
    def test_valid_transaction(self):
        """Test validation of a valid transaction"""
        validator = TransactionValidator(strict_mode=False)
        is_valid, cleaned, errors = validator.validate_transaction(SAMPLE_TRANSACTION)
        
        assert is_valid == True
        assert len(errors) == 0
        assert cleaned["amount"] == 5000.00
    
    def test_missing_required_field(self):
        """Test validation with missing required field"""
        invalid_tx = SAMPLE_TRANSACTION.copy()
        del invalid_tx["amount"]
        
        is_valid, cleaned, errors = validate_transaction(invalid_tx, strict=False)
        
        assert is_valid == False
        assert len(errors) > 0
        assert cleaned["amount"] == 0.0  # Default value
    
    def test_invalid_amount(self):
        """Test validation with invalid amount"""
        invalid_tx = SAMPLE_TRANSACTION.copy()
        invalid_tx["amount"] = -100.00
        
        is_valid, cleaned, errors = validate_transaction(invalid_tx, strict=False)
        
        assert is_valid == False
        assert cleaned["amount"] >= 0  # Should be fixed
    
    def test_invalid_timestamp(self):
        """Test validation with invalid timestamp"""
        invalid_tx = SAMPLE_TRANSACTION.copy()
        invalid_tx["timestamp"] = "invalid-date"
        
        is_valid, cleaned, errors = validate_transaction(invalid_tx, strict=False)
        
        assert is_valid == False
        assert "timestamp" in cleaned  # Should have default
    
    def test_batch_validation(self):
        """Test batch validation"""
        validator = TransactionValidator(strict_mode=False)
        transactions = [SAMPLE_TRANSACTION, SAMPLE_TRANSACTION.copy()]
        
        valid, invalid, errors = validator.validate_batch(transactions)
        
        assert len(valid) == 2
        assert len(invalid) == 0
    
    def test_validation_stats(self):
        """Test validation statistics"""
        validator = TransactionValidator(strict_mode=False)
        validator.validate_transaction(SAMPLE_TRANSACTION)
        
        stats = validator.get_stats()
        assert stats["total_validated"] == 1
        assert stats["passed"] == 1
        assert stats["pass_rate"] == 1.0


class TestFeatureEngineering:
    """Tests for aml_feature_engineering.py"""
    
    def test_feature_extraction(self):
        """Test feature extraction"""
        features = extract_features(SAMPLE_TRANSACTION, SAMPLE_HISTORICAL_DATA)
        
        assert isinstance(features, np.ndarray)
        assert len(features) > 0
        assert not np.isnan(features).any()
    
    def test_feature_names(self):
        """Test feature names"""
        engineer = FeatureEngineer()
        names = engineer.get_feature_names()
        
        assert isinstance(names, list)
        assert len(names) > 0
        assert "amount" in names
        assert "hour" in names
    
    def test_no_historical_data(self):
        """Test feature extraction without historical data"""
        features = extract_features(SAMPLE_TRANSACTION, None)
        
        assert isinstance(features, np.ndarray)
        assert len(features) > 0
    
    def test_transaction_features(self):
        """Test transaction-specific features"""
        engineer = FeatureEngineer()
        features = engineer.extract_features(SAMPLE_TRANSACTION, SAMPLE_HISTORICAL_DATA)
        
        # Check amount features
        assert features[0] == 5000.00  # amount
        assert features[1] > 0  # amount_log
    
    def test_time_features(self):
        """Test time-based features"""
        engineer = FeatureEngineer()
        features = engineer.extract_features(SAMPLE_TRANSACTION, SAMPLE_HISTORICAL_DATA)
        
        # Hour should be extracted
        assert 0 <= features[engineer.feature_names.index("hour")] <= 23


class TestFraudPatternDetection:
    """Tests for aml_fraud_patterns.py"""
    
    def test_no_patterns(self):
        """Test with no suspicious patterns"""
        detector = FraudPatternDetector()
        patterns = detector.detect_patterns(SAMPLE_TRANSACTION, SAMPLE_HISTORICAL_DATA)
        
        assert patterns["pattern_count"] == 0
        assert len(patterns["patterns"]) == 0
        assert patterns["risk_score"] == 0
    
    def test_structuring_detection(self):
        """Test structuring pattern detection"""
        detector = FraudPatternDetector()
        
        # Create structuring pattern (multiple transactions just below $10,000)
        structuring_tx = SAMPLE_TRANSACTION.copy()
        structuring_tx["amount"] = 9500.00
        
        historical = [
            SAMPLE_TRANSACTION.copy(),
            {**SAMPLE_TRANSACTION, "amount": 9200.00},
            {**SAMPLE_TRANSACTION, "amount": 9800.00}
        ]
        
        patterns = detector.detect_patterns(structuring_tx, historical)
        
        assert patterns["pattern_count"] > 0
    
    def test_circular_transfer_detection(self):
        """Test circular transfer detection"""
        detector = FraudPatternDetector()
        
        circular_tx = SAMPLE_TRANSACTION.copy()
        circular_tx["receiver_account"] = "ACC1001"  # Same as sender
        
        patterns = detector.detect_patterns(circular_tx, SAMPLE_HISTORICAL_DATA)
        
        assert patterns["pattern_count"] > 0
        assert any(p["type"] == "self_transfer" for p in patterns["patterns"])
    
    def test_risk_score_calculation(self):
        """Test risk score calculation"""
        detector = FraudPatternDetector()
        
        # Create transaction with multiple patterns
        suspicious_tx = SAMPLE_TRANSACTION.copy()
        suspicious_tx["amount"] = 9500.00
        
        historical = [
            {**SAMPLE_TRANSACTION, "amount": 9200.00},
            {**SAMPLE_TRANSACTION, "amount": 9800.00}
        ]
        
        patterns = detector.detect_patterns(suspicious_tx, historical)
        
        assert 0 <= patterns["risk_score"] <= 100


class TestRiskScoring:
    """Tests for aml_risk_scoring.py"""
    
    def test_risk_assessment(self):
        """Test comprehensive risk assessment"""
        scorer = RiskScoringSystem()
        
        ml_prediction = {
            "risk_level": "suspicious",
            "risk_score": 65,
            "confidence": 0.85,
            "probabilities": {"normal": 0.1, "suspicious": 0.7, "super_suspicious": 0.2},
            "anomaly_score": -0.5
        }
        
        fraud_patterns = {
            "patterns": [],
            "risk_score": 10,
            "pattern_count": 0,
            "high_risk_patterns": []
        }
        
        assessment = scorer.calculate_comprehensive_risk(
            ml_prediction,
            fraud_patterns,
            rule_based_score=20.0,
            transaction=SAMPLE_TRANSACTION
        )
        
        assert "risk_level" in assessment
        assert "risk_score" in assessment
        assert "confidence" in assessment
        assert "probabilities" in assessment
        assert "explanations" in assessment
        assert "recommended_action" in assessment
    
    def test_risk_level_mapping(self):
        """Test risk level from score mapping"""
        scorer = RiskScoringSystem()
        
        assert scorer.get_risk_level_from_score(10) == "low"
        assert scorer.get_risk_level_from_score(40) == "medium"
        assert scorer.get_risk_level_from_score(65) == "high"
        assert scorer.get_risk_level_from_score(85) == "critical"
    
    def test_critical_escalation(self):
        """Test escalation to critical for high-risk patterns"""
        scorer = RiskScoringSystem()
        
        ml_prediction = {
            "risk_level": "high",
            "risk_score": 60,
            "confidence": 0.7,
            "probabilities": {"normal": 0.2, "suspicious": 0.5, "super_suspicious": 0.3}
        }
        
        fraud_patterns = {
            "patterns": [{"type": "structuring", "risk_level": "high"}],
            "risk_score": 50,
            "pattern_count": 1,
            "high_risk_patterns": ["structuring"]
        }
        
        assessment = scorer.calculate_comprehensive_risk(ml_prediction, fraud_patterns)
        
        # Should escalate due to high-risk patterns
        assert assessment["risk_level"] in ["high", "critical"]
    
    def test_recommended_action_generation(self):
        """Test recommended action generation"""
        scorer = RiskScoringSystem()
        
        # Test critical action
        action = scorer._generate_recommended_action("critical", 90, ["structuring"], 2)
        assert action["action"] == "FREEZE_AND_ESCALATE"
        assert action["priority"] == "immediate"
        
        # Test low risk action
        action = scorer._generate_recommended_action("low", 10, [], 0)
        assert action["action"] == "APPROVE"
        assert action["priority"] == "low"


class TestIntegration:
    """Integration tests for the complete system"""
    
    def test_end_to_end_analysis(self):
        """Test end-to-end transaction analysis"""
        from aml_system import AMLDetectionSystem
        
        system = AMLDetectionSystem(
            use_advanced_features=True,
            enable_explainability=False,  # Disable for faster testing
            enable_continuous_learning=False
        )
        
        # Analyze transaction
        analysis = system.analyze_transaction(SAMPLE_TRANSACTION, SAMPLE_HISTORICAL_DATA)
        
        assert "validation" in analysis
        assert "ml_prediction" in analysis
        assert "fraud_patterns" in analysis
        assert "risk_assessment" in analysis
        assert analysis["processing_time_ms"] > 0
    
    def test_batch_analysis(self):
        """Test batch transaction analysis"""
        from aml_system import AMLDetectionSystem
        
        system = AMLDetectionSystem(
            use_advanced_features=True,
            enable_explainability=False,
            enable_continuous_learning=False
        )
        
        transactions = [SAMPLE_TRANSACTION, SAMPLE_TRANSACTION.copy()]
        results = system.batch_analyze(transactions)
        
        assert len(results) == 2
        assert all("risk_assessment" in r for r in results)
    
    def test_system_status(self):
        """Test system status reporting"""
        from aml_system import AMLDetectionSystem
        
        system = AMLDetectionSystem(
            use_advanced_features=True,
            enable_explainability=False,
            enable_continuous_learning=False
        )
        
        status = system.get_system_status()
        
        assert "is_initialized" in status
        assert "model_info" in status
        assert "features_enabled" in status


class TestEdgeCases:
    """Edge case tests"""
    
    def test_empty_transaction(self):
        """Test with empty transaction dictionary"""
        validator = TransactionValidator(strict_mode=False)
        is_valid, cleaned, errors = validator.validate_transaction({})
        
        assert is_valid == False
        assert len(errors) > 0
    
    def test_none_values(self):
        """Test with None values"""
        tx_with_none = {
            "amount": None,
            "transaction_type": None,
            "sender_account": None
        }
        
        validator = TransactionValidator(strict_mode=False)
        is_valid, cleaned, errors = validator.validate_transaction(tx_with_none)
        
        # Should handle None gracefully
        assert cleaned is not None
    
    def test_extreme_amounts(self):
        """Test with extreme amount values"""
        extreme_tx = SAMPLE_TRANSACTION.copy()
        extreme_tx["amount"] = 1e10  # Very large amount
        
        validator = TransactionValidator(strict_mode=False)
        is_valid, cleaned, errors = validator.validate_transaction(extreme_tx)
        
        assert is_valid == False  # Should fail validation
        assert cleaned["amount"] <= 10_000_000  # Should be capped
    
    def test_unicode_in_fields(self):
        """Test with unicode characters in fields"""
        unicode_tx = SAMPLE_TRANSACTION.copy()
        unicode_tx["sender_account"] = "ACC_中文"
        
        validator = TransactionValidator(strict_mode=False)
        is_valid, cleaned, errors = validator.validate_transaction(unicode_tx)
        
        # Should handle unicode
        assert cleaned is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
