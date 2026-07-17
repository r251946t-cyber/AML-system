"""
aml_fraud_patterns.py — Fraud Pattern Detection for AML
=======================================================
Detects common AML typologies and fraud patterns including:
- Structuring/Smurfing
- Layering
- Funnel accounts
- Circular transfers
- Money mule behavior
- Rapid movement of funds
- Round-tripping
- Self-laundering
- Dormant account activation
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


class FraudPatternDetector:
    """
    Detects AML fraud patterns in transaction sequences.
    
    Implements detection rules for common money laundering typologies.
    """
    
    # Structuring threshold (just below $10,000 reporting threshold)
    STRUCTURING_MIN = 8000
    STRUCTURING_MAX = 9999
    
    # Rapid movement threshold
    RAPID_MOVEMENT_AMOUNT = 50000
    RAPID_MOVEMENT_TIME_HOURS = 24
    
    # Dormancy threshold (days)
    DORMANCY_THRESHOLD = 90
    
    # High-risk transaction count threshold
    HIGH_TX_COUNT_THRESHOLD = 10
    
    def __init__(self):
        """Initialize the fraud pattern detector."""
        self.patterns_detected = []
    
    def detect_patterns(
        self,
        transaction: Dict[str, Any],
        historical_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Detect fraud patterns in a transaction given historical context.
        
        Args:
            transaction: Current transaction
            historical_data: Historical transactions for the account
            
        Returns:
            Dictionary with detected patterns and risk indicators
        """
        self.patterns_detected = []
        risk_indicators = {
            "patterns": [],
            "risk_score": 0,
            "pattern_count": 0,
            "high_risk_patterns": []
        }
        
        # Run all pattern detectors
        self._detect_structuring(transaction, historical_data, risk_indicators)
        self._detect_layering(transaction, historical_data, risk_indicators)
        self._detect_funnel_account(transaction, historical_data, risk_indicators)
        self._detect_circular_transfers(transaction, historical_data, risk_indicators)
        self._detect_money_mule(transaction, historical_data, risk_indicators)
        self._detect_rapid_movement(transaction, historical_data, risk_indicators)
        self._detect_round_tripping(transaction, historical_data, risk_indicators)
        self._detect_self_laundering(transaction, historical_data, risk_indicators)
        self._detect_dormant_activation(transaction, historical_data, risk_indicators)
        self._detect_transaction_burst(transaction, historical_data, risk_indicators)
        self._detect_shell_company_behavior(transaction, historical_data, risk_indicators)
        
        # Calculate overall pattern risk score
        risk_indicators["pattern_count"] = len(risk_indicators["patterns"])
        risk_indicators["risk_score"] = self._calculate_pattern_risk_score(risk_indicators)
        
        return risk_indicators
    
    def _detect_structuring(
        self,
        transaction: Dict[str, Any],
        historical_data: List[Dict[str, Any]],
        risk_indicators: Dict[str, Any]
    ) -> None:
        """
        Detect structuring (smurfing) - breaking large transactions into smaller amounts
        just below reporting thresholds.
        """
        amount = float(transaction.get("amount", 0))
        
        # Check if current transaction is in structuring range
        if self.STRUCTURING_MIN <= amount <= self.STRUCTURING_MAX:
            # Check for similar transactions in historical data
            similar_txs = [
                tx for tx in historical_data
                if self.STRUCTURING_MIN <= float(tx.get("amount", 0)) <= self.STRUCTURING_MAX
            ]
            
            if len(similar_txs) >= 2:
                pattern = {
                    "type": "structuring",
                    "description": "Multiple transactions just below reporting threshold",
                    "count": len(similar_txs) + 1,
                    "total_amount": sum(float(tx.get("amount", 0)) for tx in similar_txs) + amount,
                    "risk_level": "high"
                }
                risk_indicators["patterns"].append(pattern)
                risk_indicators["high_risk_patterns"].append("structuring")
    
    def _detect_layering(
        self,
        transaction: Dict[str, Any],
        historical_data: List[Dict[str, Any]],
        risk_indicators: Dict[str, Any]
    ) -> None:
        """
        Detect layering - rapid movement of funds through multiple accounts
        to obscure the audit trail.
        """
        sender = transaction.get("sender_account", "")
        receiver = transaction.get("receiver_account", "")
        tx_type = transaction.get("transaction_type", "").lower()
        
        if tx_type != "transfer":
            return
        
        # Look for chains of transfers
        recent_transfers = [
            tx for tx in historical_data
            if tx.get("transaction_type", "").lower() == "transfer"
        ]
        
        # Check for rapid sequential transfers
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
        
        # Count transfers in last hour
        recent_hour = []
        for tx in recent_transfers:
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
                    recent_hour.append(tx)
            except (ValueError, TypeError):
                continue
        
        # Check for layering pattern
        if len(recent_hour) >= 3:
            unique_recipients = set(tx.get("receiver_account", "") for tx in recent_hour)
            if len(unique_recipients) >= 2:
                pattern = {
                    "type": "layering",
                    "description": "Rapid transfers to multiple accounts (layering)",
                    "transfer_count": len(recent_hour) + 1,
                    "unique_recipients": len(unique_recipients),
                    "time_window_hours": 1,
                    "risk_level": "high"
                }
                risk_indicators["patterns"].append(pattern)
                risk_indicators["high_risk_patterns"].append("layering")
    
    def _detect_funnel_account(
        self,
        transaction: Dict[str, Any],
        historical_data: List[Dict[str, Any]],
        risk_indicators: Dict[str, Any]
    ) -> None:
        """
        Detect funnel accounts - accounts that receive from many sources
        and send to few destinations (consolidation).
        """
        receiver = transaction.get("receiver_account", "")
        
        if not historical_data:
            return
        
        # Count unique senders and receivers for this account
        incoming = [tx for tx in historical_data if tx.get("receiver_account", "") == receiver]
        outgoing = [tx for tx in historical_data if tx.get("sender_account", "") == receiver]
        
        unique_senders = set(tx.get("sender_account", "") for tx in incoming)
        unique_receivers = set(tx.get("receiver_account", "") for tx in outgoing)
        
        # Funnel pattern: receives from many, sends to few
        if len(unique_senders) >= 5 and len(unique_receivers) <= 2:
            pattern = {
                "type": "funnel_account",
                "description": "Account receives from many sources and sends to few (funneling)",
                "unique_senders": len(unique_senders),
                "unique_receivers": len(unique_receivers),
                "ratio": len(unique_senders) / max(1, len(unique_receivers)),
                "risk_level": "high"
            }
            risk_indicators["patterns"].append(pattern)
            risk_indicators["high_risk_patterns"].append("funnel_account")
    
    def _detect_circular_transfers(
        self,
        transaction: Dict[str, Any],
        historical_data: List[Dict[str, Any]],
        risk_indicators: Dict[str, Any]
    ) -> None:
        """
        Detect circular transfers - funds moving in a circle (A->B->C->A)
        to create false appearance of legitimate activity.
        """
        sender = transaction.get("sender_account", "")
        receiver = transaction.get("receiver_account", "")
        
        if sender == receiver:
            # Self-transfer
            pattern = {
                "type": "self_transfer",
                "description": "Transfer to same account",
                "risk_level": "medium"
            }
            risk_indicators["patterns"].append(pattern)
            return
        
        # Check for reverse transfers in history
        for tx in historical_data:
            if (tx.get("sender_account", "") == receiver and 
                tx.get("receiver_account", "") == sender):
                pattern = {
                    "type": "circular_transfer",
                    "description": "Circular transfer pattern detected",
                    "counterpart": receiver,
                    "risk_level": "high"
                }
                risk_indicators["patterns"].append(pattern)
                risk_indicators["high_risk_patterns"].append("circular_transfer")
                break
    
    def _detect_money_mule(
        self,
        transaction: Dict[str, Any],
        historical_data: List[Dict[str, Any]],
        risk_indicators: Dict[str, Any]
    ) -> None:
        """
        Detect money mule behavior - account receives funds and quickly
        forwards them to other accounts, keeping little to no balance.
        """
        sender = transaction.get("sender_account", "")
        amount = float(transaction.get("amount", 0))
        
        if not historical_data:
            return
        
        # Look for receive-then-forward pattern
        incoming = [tx for tx in historical_data if tx.get("receiver_account", "") == sender]
        outgoing = [tx for tx in historical_data if tx.get("sender_account", "") == sender]
        
        if len(incoming) >= 3 and len(outgoing) >= 3:
            # Check if outgoing amounts are similar to incoming (pass-through)
            incoming_amounts = [float(tx.get("amount", 0)) for tx in incoming]
            outgoing_amounts = [float(tx.get("amount", 0)) for tx in outgoing]
            
            total_in = sum(incoming_amounts)
            total_out = sum(outgoing_amounts)
            
            # If most money is passed through quickly
            if total_out >= total_in * 0.8:
                pattern = {
                    "type": "money_mule",
                    "description": "Account passes through most received funds (mule behavior)",
                    "total_in": total_in,
                    "total_out": total_out,
                    "pass_through_ratio": total_out / total_in if total_in > 0 else 0,
                    "risk_level": "high"
                }
                risk_indicators["patterns"].append(pattern)
                risk_indicators["high_risk_patterns"].append("money_mule")
    
    def _detect_rapid_movement(
        self,
        transaction: Dict[str, Any],
        historical_data: List[Dict[str, Any]],
        risk_indicators: Dict[str, Any]
    ) -> None:
        """
        Detect rapid movement of large amounts - characteristic of
        trying to move funds quickly before detection.
        """
        amount = float(transaction.get("amount", 0))
        
        if amount < self.RAPID_MOVEMENT_AMOUNT:
            return
        
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
        
        # Check for other large transactions in recent window
        large_recent = []
        for tx in historical_data:
            try:
                tx_amount = float(tx.get("amount", 0))
                if tx_amount >= self.RAPID_MOVEMENT_AMOUNT * 0.5:  # At least half threshold
                    tx_time_str = tx.get("timestamp", "")
                    if isinstance(tx_time_str, str):
                        tx_time = datetime.fromisoformat(tx_time_str.replace('Z', '+00:00'))
                    else:
                        tx_time = tx_time_str
                    
                    if tx_time.tzinfo is None:
                        tx_time = tx_time.replace(tzinfo=timezone.utc)
                    
                    time_diff = (current_time - tx_time).total_seconds()
                    if time_diff <= self.RAPID_MOVEMENT_TIME_HOURS * 3600:
                        large_recent.append(tx)
            except (ValueError, TypeError):
                continue
        
        if len(large_recent) >= 2:
            total_moved = sum(float(tx.get("amount", 0)) for tx in large_recent) + amount
            pattern = {
                "type": "rapid_movement",
                "description": "Rapid movement of large amounts",
                "total_amount": total_moved,
                "transaction_count": len(large_recent) + 1,
                "time_window_hours": self.RAPID_MOVEMENT_TIME_HOURS,
                "risk_level": "high"
            }
            risk_indicators["patterns"].append(pattern)
            risk_indicators["high_risk_patterns"].append("rapid_movement")
    
    def _detect_round_tripping(
        self,
        transaction: Dict[str, Any],
        historical_data: List[Dict[str, Any]],
        risk_indicators: Dict[str, Any]
    ) -> None:
        """
        Detect round-tripping - funds sent out and returned to create
        false appearance of legitimate business activity.
        """
        sender = transaction.get("sender_account", "")
        receiver = transaction.get("receiver_account", "")
        amount = float(transaction.get("amount", 0))
        
        if not historical_data:
            return
        
        # Look for return transfers
        for tx in historical_data:
            if (tx.get("sender_account", "") == receiver and 
                tx.get("receiver_account", "") == sender):
                return_amount = float(tx.get("amount", 0))
                
                # If amounts are similar (round-trip)
                if abs(return_amount - amount) / max(amount, 1) < 0.1:
                    pattern = {
                        "type": "round_tripping",
                        "description": "Round-trip transaction detected",
                        "outbound_amount": amount,
                        "return_amount": return_amount,
                        "counterpart": receiver,
                        "risk_level": "high"
                    }
                    risk_indicators["patterns"].append(pattern)
                    risk_indicators["high_risk_patterns"].append("round_tripping")
                    break
    
    def _detect_self_laundering(
        self,
        transaction: Dict[str, Any],
        historical_data: List[Dict[str, Any]],
        risk_indicators: Dict[str, Any]
    ) -> None:
        """
        Detect self-laundering - using own accounts to move funds
        through complex transactions to obscure origin.
        """
        sender = transaction.get("sender_account", "")
        receiver = transaction.get("receiver_account", "")
        
        if not historical_data:
            return
        
        # Check if sender and receiver are linked (same customer)
        # In production, this would check account ownership
        sender_customer = transaction.get("sender_customer_id", "")
        receiver_customer = transaction.get("receiver_customer_id", "")
        
        if sender_customer and receiver_customer and sender_customer == receiver_customer:
            pattern = {
                "type": "self_laundering",
                "description": "Transfer between accounts of same customer",
                "customer_id": sender_customer,
                "risk_level": "medium"
            }
            risk_indicators["patterns"].append(pattern)
    
    def _detect_dormant_activation(
        self,
        transaction: Dict[str, Any],
        historical_data: List[Dict[str, Any]],
        risk_indicators: Dict[str, Any]
    ) -> None:
        """
        Detect dormant account activation - sudden activity on an account
        that has been inactive for a long period.
        """
        if not historical_data:
            # First transaction - check account age
            created_at_str = transaction.get("account_created_at", "")
            try:
                if isinstance(created_at_str, str):
                    created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                else:
                    created_at = created_at_str
                
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                
                account_age_days = (datetime.now(timezone.utc) - created_at).days
                if account_age_days > self.DORMANCY_THRESHOLD:
                    pattern = {
                        "type": "dormant_activation",
                        "description": "First transaction on old account",
                        "account_age_days": account_age_days,
                        "risk_level": "medium"
                    }
                    risk_indicators["patterns"].append(pattern)
            except (ValueError, TypeError):
                pass
            return
        
        # Check time since last transaction
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
        
        # Find most recent transaction
        most_recent = None
        for tx in historical_data:
            try:
                tx_time_str = tx.get("timestamp", "")
                if isinstance(tx_time_str, str):
                    tx_time = datetime.fromisoformat(tx_time_str.replace('Z', '+00:00'))
                else:
                    tx_time = tx_time_str
                
                if tx_time.tzinfo is None:
                    tx_time = tx_time.replace(tzinfo=timezone.utc)
                
                if most_recent is None or tx_time > most_recent:
                    most_recent = tx_time
            except (ValueError, TypeError):
                continue
        
        if most_recent:
            dormancy_days = (current_time - most_recent).days
            if dormancy_days > self.DORMANCY_THRESHOLD:
                pattern = {
                    "type": "dormant_activation",
                    "description": "Activity on dormant account",
                    "dormancy_days": dormancy_days,
                    "risk_level": "medium"
                }
                risk_indicators["patterns"].append(pattern)
    
    def _detect_transaction_burst(
        self,
        transaction: Dict[str, Any],
        historical_data: List[Dict[str, Any]],
        risk_indicators: Dict[str, Any]
    ) -> None:
        """
        Detect transaction bursts - unusually high frequency of transactions
        in a short time period.
        """
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
        
        # Count transactions in different time windows
        tx_1h = []
        tx_24h = []
        
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
                
                if time_diff <= 3600:
                    tx_1h.append(tx)
                if time_diff <= 86400:
                    tx_24h.append(tx)
            except (ValueError, TypeError):
                continue
        
        # Check for burst patterns
        if len(tx_1h) >= 10:
            pattern = {
                "type": "transaction_burst",
                "description": "High transaction frequency in 1 hour",
                "count_1h": len(tx_1h) + 1,
                "time_window": "1 hour",
                "risk_level": "high"
            }
            risk_indicators["patterns"].append(pattern)
            risk_indicators["high_risk_patterns"].append("transaction_burst")
        elif len(tx_24h) >= self.HIGH_TX_COUNT_THRESHOLD:
            pattern = {
                "type": "transaction_burst",
                "description": "High transaction frequency in 24 hours",
                "count_24h": len(tx_24h) + 1,
                "time_window": "24 hours",
                "risk_level": "medium"
            }
            risk_indicators["patterns"].append(pattern)
    
    def _detect_shell_company_behavior(
        self,
        transaction: Dict[str, Any],
        historical_data: List[Dict[str, Any]],
        risk_indicators: Dict[str, Any]
    ) -> None:
        """
        Detect shell company behavior - transactions with characteristics
        typical of shell companies (high volume, low diversity, etc.).
        """
        if not historical_data:
            return
        
        # Check for consistent high-value transactions
        amounts = [float(tx.get("amount", 0)) for tx in historical_data]
        amounts.append(float(transaction.get("amount", 0)))
        
        if len(amounts) < 5:
            return
        
        avg_amount = sum(amounts) / len(amounts)
        std_amount = (sum((x - avg_amount) ** 2 for x in amounts) / len(amounts)) ** 0.5
        
        # Low variation: consistent amounts (characteristic of shell companies)
        if avg_amount > 10000 and std_amount / avg_amount < 0.2:
            pattern = {
                "type": "shell_company_behavior",
                "description": "Consistent high-value transactions (shell company pattern)",
                "average_amount": avg_amount,
                "variation_coefficient": std_amount / avg_amount,
                "risk_level": "medium"
            }
            risk_indicators["patterns"].append(pattern)
    
    def _calculate_pattern_risk_score(self, risk_indicators: Dict[str, Any]) -> float:
        """
        Calculate overall risk score based on detected patterns.
        
        Args:
            risk_indicators: Dictionary with detected patterns
            
        Returns:
            Risk score (0-100)
        """
        base_score = 0
        
        for pattern in risk_indicators["patterns"]:
            risk_level = pattern.get("risk_level", "low")
            
            if risk_level == "high":
                base_score += 25
            elif risk_level == "medium":
                base_score += 15
            else:
                base_score += 5
        
        # Bonus for multiple high-risk patterns
        high_risk_count = len(risk_indicators["high_risk_patterns"])
        if high_risk_count >= 2:
            base_score += 10
        if high_risk_count >= 3:
            base_score += 10
        
        return min(100, base_score)


# Global detector instance
_default_detector = FraudPatternDetector()


def detect_fraud_patterns(
    transaction: Dict[str, Any],
    historical_data: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Convenience function to detect fraud patterns.
    
    Args:
        transaction: Current transaction
        historical_data: Historical transactions for the account
        
    Returns:
        Dictionary with detected patterns and risk indicators
    """
    return _default_detector.detect_patterns(transaction, historical_data)
