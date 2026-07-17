"""
aml_feature_engineering.py — Comprehensive Feature Engineering for AML Detection
===============================================================================
Extracts 50+ meaningful features from transaction data for ML models.
Includes transaction, behavioral, relationship, geographic, channel, time, velocity, and network features.
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import logging

logger = logging.getLogger(__name__)


class FeatureEngineer:
    """
    Extracts comprehensive AML features from transaction data.
    
    Feature Categories:
    - Transaction Features: amount, frequency, velocity, statistics
    - Behavioral Features: spending changes, unusual times, bursts
    - Relationship Features: beneficiaries, circular transactions, shared accounts
    - Account Risk Features: age, history, flags
    - Geographic Features: countries, cross-border, risk scores
    - Channel Features: ATM, mobile, branch, online, etc.
    - Time Features: hour, day, month, holidays
    - Velocity Features: recent activity metrics
    - Network Features: mule detection, layering, structuring
    """
    
    # High-risk jurisdictions (ISO country codes)
    HIGH_RISK_COUNTRIES = {
        "AF", "KP", "IR", "SY", "MM", "LR", "SS", "YE", "CU", "VE",
        "IQ", "SD", "SO", "CD", "CI", "ZW", "BY", "RU", "UA"
    }
    
    # Medium-risk jurisdictions
    MEDIUM_RISK_COUNTRIES = {
        "PK", "BD", "NG", "KE", "UG", "TZ", "MZ", "AO", "DZ", "MA",
        "EG", "TR", "SA", "AE", "QA", "KW", "BA", "AL", "MK", "RS"
    }
    
    # Channel encoding
    CHANNEL_ENCODING = {
        "online": 0, "mobile": 1, "atm": 2, "branch": 3,
        "card": 4, "ach": 5, "wire": 6, "swift": 7, "pos": 8, "api": 9
    }
    
    # Transaction type encoding
    TX_TYPE_ENCODING = {
        "deposit": 0, "withdraw": 1, "transfer": 2, 
        "payment": 3, "wire": 4
    }
    
    def __init__(self, historical_window_days: int = 90):
        """
        Initialize feature engineer.
        
        Args:
            historical_window_days: Days of historical data to consider for features
        """
        self.historical_window_days = historical_window_days
        self.feature_names = []
        self._build_feature_names()
    
    def _build_feature_names(self) -> None:
        """Build list of all feature names for documentation."""
        self.feature_names = [
            # Transaction Features
            "amount", "amount_log", "amount_sqrt",
            "transaction_type_deposit", "transaction_type_withdraw", "transaction_type_transfer",
            "transaction_type_payment", "transaction_type_wire",
            
            # Behavioral Features
            "amount_to_sender_avg", "amount_to_sender_max", "amount_to_sender_median",
            "sender_tx_count", "sender_avg_amount", "sender_max_amount", "sender_median_amount",
            "sender_amount_std", "sender_amount_skew",
            "amount_deviation_from_avg", "amount_deviation_from_max",
            
            # Time Features
            "hour", "day_of_week", "day_of_month", "month", "is_weekend",
            "is_night", "is_early_morning", "is_business_hours",
            "is_holiday", "is_salary_day",
            
            # Velocity Features
            "sender_tx_count_1h", "sender_tx_count_24h", "sender_tx_count_7d",
            "sender_volume_1h", "sender_volume_24h", "sender_volume_7d",
            "amount_to_sender_volume_24h", "amount_to_sender_volume_7d",
            "velocity_ratio_1h", "velocity_ratio_24h",
            
            # Relationship Features
            "is_new_recipient", "recipient_reuse_count", "unique_recipients_24h",
            "unique_recipients_7d", "is_self_transfer", "is_circular_transfer",
            "shared_recipient_count", "recipient_risk_score",
            
            # Geographic Features
            "is_cross_border", "origin_country_risk", "destination_country_risk",
            "country_risk_difference", "high_risk_country_involved",
            
            # Channel Features
            "channel_online", "channel_mobile", "channel_atm", "channel_branch",
            "channel_card", "channel_wire", "channel_swift",
            
            # Account Risk Features
            "account_age_days", "is_dormant_account", "dormancy_period_days",
            "previous_alert_count", "previous_sar_count",
            "is_pep", "is_sanctioned", "is_high_risk_customer",
            "kyc_status_verified", "kyc_status_pending", "kyc_status_rejected",
            
            # Network Features
            "is_layering_pattern", "is_structuring_pattern", "is_smurfing_pattern",
            "is_funnel_account", "is_rapid_movement", "is_hub_account",
            "network_centrality", "cluster_density",
            
            # Composite Features
            "risk_score_composite", "anomaly_score_composite",
            "behavioral_drift_score", "velocity_spike_score"
        ]
    
    def extract_features(
        self, 
        transaction: Dict[str, Any], 
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> np.ndarray:
        """
        Extract comprehensive features from a transaction.
        
        Args:
            transaction: Current transaction dictionary
            historical_data: List of historical transactions for the sender
            
        Returns:
            Numpy array of feature values
        """
        if historical_data is None:
            historical_data = []
        
        features = {}
        
        # Transaction Features
        self._extract_transaction_features(transaction, features)
        
        # Behavioral Features
        self._extract_behavioral_features(transaction, historical_data, features)
        
        # Time Features
        self._extract_time_features(transaction, features)
        
        # Velocity Features
        self._extract_velocity_features(transaction, historical_data, features)
        
        # Relationship Features
        self._extract_relationship_features(transaction, historical_data, features)
        
        # Geographic Features
        self._extract_geographic_features(transaction, features)
        
        # Channel Features
        self._extract_channel_features(transaction, features)
        
        # Account Risk Features
        self._extract_account_risk_features(transaction, historical_data, features)
        
        # Network Features
        self._extract_network_features(transaction, historical_data, features)
        
        # Composite Features
        self._extract_composite_features(features)
        
        # Convert to numpy array in consistent order
        feature_vector = np.array([features.get(name, 0.0) for name in self.feature_names])
        
        # Handle NaN/Inf values
        feature_vector = np.nan_to_num(feature_vector, nan=0.0, posinf=0.0, neginf=0.0)
        
        return feature_vector
    
    def _extract_transaction_features(self, transaction: Dict[str, Any], features: Dict[str, float]) -> None:
        """Extract basic transaction features."""
        amount = float(transaction.get("amount", 0))
        tx_type = transaction.get("transaction_type", "transfer").lower()
        
        features["amount"] = amount
        features["amount_log"] = np.log1p(amount)
        features["amount_sqrt"] = np.sqrt(amount)
        
        # One-hot encode transaction type
        for t in ["deposit", "withdraw", "transfer", "payment", "wire"]:
            features[f"transaction_type_{t}"] = 1.0 if tx_type == t else 0.0
    
    def _extract_behavioral_features(
        self, 
        transaction: Dict[str, Any], 
        historical_data: List[Dict[str, Any]], 
        features: Dict[str, float]
    ) -> None:
        """Extract behavioral features from historical data."""
        amount = float(transaction.get("amount", 0))
        
        if not historical_data:
            # Default values when no history
            features["sender_tx_count"] = 0.0
            features["sender_avg_amount"] = amount
            features["sender_max_amount"] = amount
            features["sender_median_amount"] = amount
            features["sender_amount_std"] = 0.0
            features["sender_amount_skew"] = 0.0
            features["amount_to_sender_avg"] = 1.0
            features["amount_to_sender_max"] = 1.0
            features["amount_to_sender_median"] = 1.0
            features["amount_deviation_from_avg"] = 0.0
            features["amount_deviation_from_max"] = 0.0
            return
        
        amounts = [float(tx.get("amount", 0)) for tx in historical_data]
        amounts.append(amount)
        
        features["sender_tx_count"] = len(amounts)
        features["sender_avg_amount"] = np.mean(amounts)
        features["sender_max_amount"] = np.max(amounts)
        features["sender_median_amount"] = np.median(amounts)
        
        if len(amounts) > 1:
            features["sender_amount_std"] = np.std(amounts)
            features["sender_amount_skew"] = self._calculate_skewness(amounts)
        else:
            features["sender_amount_std"] = 0.0
            features["sender_amount_skew"] = 0.0
        
        # Ratios
        avg_amount = features["sender_avg_amount"]
        max_amount = features["sender_max_amount"]
        median_amount = features["sender_median_amount"]
        
        features["amount_to_sender_avg"] = amount / avg_amount if avg_amount > 0 else 1.0
        features["amount_to_sender_max"] = amount / max_amount if max_amount > 0 else 1.0
        features["amount_to_sender_median"] = amount / median_amount if median_amount > 0 else 1.0
        
        # Deviation scores
        features["amount_deviation_from_avg"] = abs(amount - avg_amount) / avg_amount if avg_amount > 0 else 0.0
        features["amount_deviation_from_max"] = abs(amount - max_amount) / max_amount if max_amount > 0 else 0.0
    
    def _extract_time_features(self, transaction: Dict[str, Any], features: Dict[str, float]) -> None:
        """Extract time-based features."""
        timestamp_str = transaction.get("timestamp", "")
        
        try:
            if isinstance(timestamp_str, str):
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                timestamp = timestamp_str
            
            # Ensure timezone-aware
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            
            features["hour"] = float(timestamp.hour)
            features["day_of_week"] = float(timestamp.weekday())  # 0=Monday, 6=Sunday
            features["day_of_month"] = float(timestamp.day)
            features["month"] = float(timestamp.month)
            
            # Derived time features
            features["is_weekend"] = 1.0 if timestamp.weekday() >= 5 else 0.0
            features["is_night"] = 1.0 if timestamp.hour < 5 or timestamp.hour >= 23 else 0.0
            features["is_early_morning"] = 1.0 if 5 <= timestamp.hour < 8 else 0.0
            features["is_business_hours"] = 1.0 if 9 <= timestamp.hour < 17 else 0.0
            
            # Holiday detection (simplified - in production, use holidays library)
            features["is_holiday"] = 0.0  # Would check against holiday calendar
            
            # Salary day detection (typically 1st and 15th of month)
            features["is_salary_day"] = 1.0 if timestamp.day in [1, 15] else 0.0
            
        except (ValueError, TypeError):
            # Default values if timestamp parsing fails
            features["hour"] = 12.0
            features["day_of_week"] = 0.0
            features["day_of_month"] = 1.0
            features["month"] = 1.0
            features["is_weekend"] = 0.0
            features["is_night"] = 0.0
            features["is_early_morning"] = 0.0
            features["is_business_hours"] = 1.0
            features["is_holiday"] = 0.0
            features["is_salary_day"] = 0.0
    
    def _extract_velocity_features(
        self, 
        transaction: Dict[str, Any], 
        historical_data: List[Dict[str, Any]], 
        features: Dict[str, float]
    ) -> None:
        """Extract velocity features (recent activity metrics)."""
        amount = float(transaction.get("amount", 0))
        timestamp_str = transaction.get("timestamp", "")
        
        try:
            if isinstance(timestamp_str, str):
                current_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                current_time = timestamp_str
            
            if current_time.tzinfo is None:
                current_time = current_time.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            current_time = datetime.now(timezone.utc)
        
        # Filter historical data by time windows
        tx_1h = []
        tx_24h = []
        tx_7d = []
        
        for tx in historical_data:
            try:
                tx_time_str = tx.get("timestamp", "")
                if isinstance(tx_time_str, str):
                    tx_time = datetime.fromisoformat(tx_time_str.replace('Z', '+00:00'))
                else:
                    tx_time = tx_time_str
                
                if tx_time.tzinfo is None:
                    tx_time = tx_time.replace(tzinfo=timezone.utc)
                
                time_diff = (current_time - tx_time).total_seconds()
                
                if time_diff <= 3600:  # 1 hour
                    tx_1h.append(tx)
                if time_diff <= 86400:  # 24 hours
                    tx_24h.append(tx)
                if time_diff <= 604800:  # 7 days
                    tx_7d.append(tx)
            except (ValueError, TypeError):
                continue
        
        # Calculate velocity metrics
        features["sender_tx_count_1h"] = float(len(tx_1h))
        features["sender_tx_count_24h"] = float(len(tx_24h))
        features["sender_tx_count_7d"] = float(len(tx_7d))
        
        features["sender_volume_1h"] = sum(float(tx.get("amount", 0)) for tx in tx_1h)
        features["sender_volume_24h"] = sum(float(tx.get("amount", 0)) for tx in tx_24h)
        features["sender_volume_7d"] = sum(float(tx.get("amount", 0)) for tx in tx_7d)
        
        # Ratios
        vol_24h = features["sender_volume_24h"]
        vol_7d = features["sender_volume_7d"]
        
        features["amount_to_sender_volume_24h"] = amount / vol_24h if vol_24h > 0 else 1.0
        features["amount_to_sender_volume_7d"] = amount / vol_7d if vol_7d > 0 else 1.0
        
        # Velocity ratios (current vs historical average)
        if len(tx_24h) > 0:
            avg_tx_24h = vol_24h / len(tx_24h)
            features["velocity_ratio_24h"] = amount / avg_tx_24h if avg_tx_24h > 0 else 1.0
        else:
            features["velocity_ratio_24h"] = 1.0
        
        if len(tx_1h) > 0:
            avg_tx_1h = features["sender_volume_1h"] / len(tx_1h)
            features["velocity_ratio_1h"] = amount / avg_tx_1h if avg_tx_1h > 0 else 1.0
        else:
            features["velocity_ratio_1h"] = 1.0
    
    def _extract_relationship_features(
        self, 
        transaction: Dict[str, Any], 
        historical_data: List[Dict[str, Any]], 
        features: Dict[str, float]
    ) -> None:
        """Extract relationship features (beneficiaries, circular transfers)."""
        sender = transaction.get("sender_account", "")
        receiver = transaction.get("receiver_account", "")
        
        # Self-transfer detection
        features["is_self_transfer"] = 1.0 if sender == receiver else 0.0
        
        if not historical_data:
            features["is_new_recipient"] = 1.0
            features["recipient_reuse_count"] = 0.0
            features["unique_recipients_24h"] = 0.0
            features["unique_recipients_7d"] = 0.0
            features["shared_recipient_count"] = 0.0
            features["recipient_risk_score"] = 0.0
            features["is_circular_transfer"] = 0.0
            return
        
        # Check if recipient is new
        past_recipients = {tx.get("receiver_account", "") for tx in historical_data}
        features["is_new_recipient"] = 0.0 if receiver in past_recipients else 1.0
        
        # Count recipient reuse
        features["recipient_reuse_count"] = sum(
            1 for tx in historical_data if tx.get("receiver_account", "") == receiver
        )
        
        # Count unique recipients in time windows
        timestamp_str = transaction.get("timestamp", "")
        try:
            if isinstance(timestamp_str, str):
                current_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                current_time = timestamp_str
            
            if current_time.tzinfo is None:
                current_time = current_time.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            current_time = datetime.now(timezone.utc)
        
        recipients_24h = set()
        recipients_7d = set()
        
        for tx in historical_data:
            try:
                tx_time_str = tx.get("timestamp", "")
                if isinstance(tx_time_str, str):
                    tx_time = datetime.fromisoformat(tx_time_str.replace('Z', '+00:00'))
                else:
                    tx_time = tx_time_str
                
                if tx_time.tzinfo is None:
                    tx_time = tx_time.replace(tzinfo=timezone.utc)
                
                time_diff = (current_time - tx_time).total_seconds()
                
                if time_diff <= 86400:
                    recipients_24h.add(tx.get("receiver_account", ""))
                if time_diff <= 604800:
                    recipients_7d.add(tx.get("receiver_account", ""))
            except (ValueError, TypeError):
                continue
        
        features["unique_recipients_24h"] = float(len(recipients_24h))
        features["unique_recipients_7d"] = float(len(recipients_7d))
        
        # Shared recipient count (how many senders use this recipient)
        # In production, this would query the database
        features["shared_recipient_count"] = 0.0
        
        # Recipient risk score (from watchlist, sanctions, etc.)
        features["recipient_risk_score"] = float(transaction.get("recipient_risk_score", 0))
        
        # Circular transfer detection (A->B, B->A pattern)
        features["is_circular_transfer"] = 0.0
        for tx in historical_data:
            if (tx.get("sender_account", "") == receiver and 
                tx.get("receiver_account", "") == sender):
                features["is_circular_transfer"] = 1.0
                break
    
    def _extract_geographic_features(self, transaction: Dict[str, Any], features: Dict[str, float]) -> None:
        """Extract geographic features."""
        origin_country = transaction.get("origin_country", "").upper()
        destination_country = transaction.get("destination_country", "").upper()
        
        # Cross-border detection
        features["is_cross_border"] = 1.0 if origin_country and destination_country and origin_country != destination_country else 0.0
        
        # Country risk scores
        features["origin_country_risk"] = self._get_country_risk_score(origin_country)
        features["destination_country_risk"] = self._get_country_risk_score(destination_country)
        
        # Risk difference
        features["country_risk_difference"] = abs(
            features["origin_country_risk"] - features["destination_country_risk"]
        )
        
        # High-risk country involvement
        features["high_risk_country_involved"] = 1.0 if (
            origin_country in self.HIGH_RISK_COUNTRIES or 
            destination_country in self.HIGH_RISK_COUNTRIES
        ) else 0.0
    
    def _extract_channel_features(self, transaction: Dict[str, Any], features: Dict[str, float]) -> None:
        """Extract channel features."""
        channel = transaction.get("channel", "online").lower()
        
        # One-hot encode channels
        for ch in ["online", "mobile", "atm", "branch", "card", "wire", "swift"]:
            features[f"channel_{ch}"] = 1.0 if channel == ch else 0.0
    
    def _extract_account_risk_features(
        self, 
        transaction: Dict[str, Any], 
        historical_data: List[Dict[str, Any]], 
        features: Dict[str, float]
    ) -> None:
        """Extract account risk features."""
        # Account age
        created_at_str = transaction.get("account_created_at", "")
        try:
            if isinstance(created_at_str, str):
                created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
            else:
                created_at = created_at_str
            
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            
            account_age = (datetime.now(timezone.utc) - created_at).days
            features["account_age_days"] = float(max(0, account_age))
        except (ValueError, TypeError):
            features["account_age_days"] = 365.0  # Default to 1 year
        
        # Dormancy detection
        if historical_data:
            last_tx = max(historical_data, key=lambda x: x.get("timestamp", ""))
            try:
                last_tx_str = last_tx.get("timestamp", "")
                if isinstance(last_tx_str, str):
                    last_tx_time = datetime.fromisoformat(last_tx_str.replace('Z', '+00:00'))
                else:
                    last_tx_time = last_tx_str
                
                if last_tx_time.tzinfo is None:
                    last_tx_time = last_tx_time.replace(tzinfo=timezone.utc)
                
                dormancy_days = (datetime.now(timezone.utc) - last_tx_time).days
                features["dormancy_period_days"] = float(max(0, dormancy_days))
                features["is_dormant_account"] = 1.0 if dormancy_days > 90 else 0.0
            except (ValueError, TypeError):
                features["dormancy_period_days"] = 0.0
                features["is_dormant_account"] = 0.0
        else:
            features["dormancy_period_days"] = 0.0
            features["is_dormant_account"] = 0.0
        
        # Previous alerts and SARs
        features["previous_alert_count"] = float(transaction.get("previous_alert_count", 0))
        features["previous_sar_count"] = float(transaction.get("previous_sar_count", 0))
        
        # Risk flags
        features["is_pep"] = 1.0 if transaction.get("pep_flag") else 0.0
        features["is_sanctioned"] = 1.0 if transaction.get("sanctioned_flag") else 0.0
        features["is_high_risk_customer"] = 1.0 if transaction.get("high_risk_flag") else 0.0
        
        # KYC status
        kyc_status = transaction.get("kyc_status", "pending").lower()
        features["kyc_status_verified"] = 1.0 if kyc_status == "verified" else 0.0
        features["kyc_status_pending"] = 1.0 if kyc_status == "pending" else 0.0
        features["kyc_status_rejected"] = 1.0 if kyc_status == "rejected" else 0.0
    
    def _extract_network_features(
        self, 
        transaction: Dict[str, Any], 
        historical_data: List[Dict[str, Any]], 
        features: Dict[str, float]
    ) -> None:
        """Extract network features (mule detection, layering, structuring)."""
        amount = float(transaction.get("amount", 0))
        
        if not historical_data:
            features["is_layering_pattern"] = 0.0
            features["is_structuring_pattern"] = 0.0
            features["is_smurfing_pattern"] = 0.0
            features["is_funnel_account"] = 0.0
            features["is_rapid_movement"] = 0.0
            features["is_hub_account"] = 0.0
            features["network_centrality"] = 0.0
            features["cluster_density"] = 0.0
            return
        
        # Layering pattern: multiple rapid transfers between accounts
        recent_transfers = [tx for tx in historical_data if tx.get("transaction_type") == "transfer"]
        if len(recent_transfers) >= 3:
            features["is_layering_pattern"] = 1.0
        else:
            features["is_layering_pattern"] = 0.0
        
        # Structuring/Smurfing: multiple small transactions just below threshold
        small_amounts = [tx for tx in historical_data if 8000 <= float(tx.get("amount", 0)) <= 9999]
        if len(small_amounts) >= 2:
            features["is_structuring_pattern"] = 1.0
            features["is_smurfing_pattern"] = 1.0
        else:
            features["is_structuring_pattern"] = 0.0
            features["is_smurfing_pattern"] = 0.0
        
        # Funnel account: receives from many, sends to few
        recipients = [tx.get("receiver_account", "") for tx in historical_data]
        senders = [tx.get("sender_account", "") for tx in historical_data]
        
        if len(set(recipients)) < len(set(senders)) / 2:
            features["is_funnel_account"] = 1.0
        else:
            features["is_funnel_account"] = 0.0
        
        # Rapid movement: large amount moved quickly
        if amount > 50000 and features.get("sender_tx_count_24h", 0) >= 5:
            features["is_rapid_movement"] = 1.0
        else:
            features["is_rapid_movement"] = 0.0
        
        # Hub account: high degree centrality
        unique_connections = len(set(recipients + senders))
        features["is_hub_account"] = 1.0 if unique_connections > 10 else 0.0
        features["network_centrality"] = float(unique_connections)
        
        # Cluster density (simplified)
        features["cluster_density"] = min(1.0, unique_connections / 20.0)
    
    def _extract_composite_features(self, features: Dict[str, float]) -> None:
        """Extract composite features from existing features."""
        # Risk score composite
        risk_components = [
            features.get("is_high_risk_customer", 0),
            features.get("is_pep", 0),
            features.get("is_sanctioned", 0),
            features.get("high_risk_country_involved", 0),
            features.get("is_structuring_pattern", 0),
            features.get("is_layering_pattern", 0),
        ]
        features["risk_score_composite"] = sum(risk_components) / len(risk_components)
        
        # Anomaly score composite
        anomaly_components = [
            features.get("amount_deviation_from_avg", 0),
            features.get("velocity_ratio_24h", 0),
            features.get("is_new_recipient", 0),
            features.get("is_night", 0),
        ]
        features["anomaly_score_composite"] = sum(anomaly_components) / len(anomaly_components)
        
        # Behavioral drift score
        features["behavioral_drift_score"] = (
            features.get("amount_deviation_from_avg", 0) * 0.4 +
            features.get("velocity_ratio_24h", 0) * 0.3 +
            features.get("is_new_recipient", 0) * 0.3
        )
        
        # Velocity spike score
        features["velocity_spike_score"] = max(
            features.get("velocity_ratio_1h", 0),
            features.get("velocity_ratio_24h", 0)
        )
    
    def _get_country_risk_score(self, country_code: str) -> float:
        """Get risk score for a country (0-1 scale)."""
        if not country_code:
            return 0.0
        
        country_code = country_code.upper()
        
        if country_code in self.HIGH_RISK_COUNTRIES:
            return 1.0
        elif country_code in self.MEDIUM_RISK_COUNTRIES:
            return 0.5
        else:
            return 0.0
    
    def _calculate_skewness(self, values: List[float]) -> float:
        """Calculate skewness of values."""
        if len(values) < 3:
            return 0.0
        
        values = np.array(values)
        mean = np.mean(values)
        std = np.std(values)
        
        if std == 0:
            return 0.0
        
        skewness = np.mean(((values - mean) / std) ** 3)
        return float(skewness)
    
    def get_feature_names(self) -> List[str]:
        """Get list of all feature names."""
        return self.feature_names.copy()


# Global feature engineer instance
_default_engineer = FeatureEngineer()


def extract_features(
    transaction: Dict[str, Any], 
    historical_data: Optional[List[Dict[str, Any]]] = None
) -> np.ndarray:
    """
    Convenience function to extract features from a transaction.
    
    Args:
        transaction: Transaction dictionary
        historical_data: Optional historical transactions for the sender
        
    Returns:
        Numpy array of feature values
    """
    return _default_engineer.extract_features(transaction, historical_data)


def get_feature_names() -> List[str]:
    """Get list of all feature names."""
    return _default_engineer.get_feature_names()
