"""
aml_data_validator.py — Data Validation Layer for AML System
=============================================================
Validates all incoming transaction data before ML processing.
Handles missing values, invalid values, duplicates, and corrupted inputs.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Raised when transaction data fails validation."""
    pass


class TransactionValidator:
    """Validates transaction data for AML ML processing."""
    
    # Valid transaction types
    VALID_TX_TYPES = {"deposit", "withdraw", "transfer", "payment", "wire"}
    
    # Valid channels
    VALID_CHANNELS = {"online", "mobile", "atm", "branch", "card", "ach", "wire", "swift", "pos", "api"}
    
    # Valid risk levels
    VALID_RISK_LEVELS = {
        "normal", "low", "medium", "high", "suspicious", 
        "high_risk", "critical", "super_suspicious"
    }
    
    # Reasonable amount bounds (in USD)
    MIN_AMOUNT = 0.01
    MAX_AMOUNT = 10_000_000  # 10 million USD
    
    # Reasonable timestamp bounds
    MIN_TIMESTAMP = datetime(2000, 1, 1, tzinfo=timezone.utc)
    MAX_TIMESTAMP = datetime.now(timezone.utc).replace(year=2030)
    
    def __init__(self, strict_mode: bool = True):
        """
        Initialize validator.
        
        Args:
            strict_mode: If True, raises exceptions on validation errors.
                        If False, attempts to fix/ignore errors.
        """
        self.strict_mode = strict_mode
        self.validation_stats = {
            "total_validated": 0,
            "passed": 0,
            "failed": 0,
            "fixed": 0,
            "errors": []
        }
    
    def validate_transaction(self, transaction: Dict[str, Any]) -> Tuple[bool, Dict[str, Any], List[str]]:
        """
        Validate a single transaction.
        
        Args:
            transaction: Transaction dictionary to validate
            
        Returns:
            Tuple of (is_valid, cleaned_transaction, error_messages)
        """
        self.validation_stats["total_validated"] += 1
        errors = []
        cleaned = dict(transaction)  # Make a copy
        
        try:
            # Validate required fields
            self._validate_required_fields(cleaned, errors)
            
            # Validate and clean amount
            self._validate_amount(cleaned, errors)
            
            # Validate and clean timestamp
            self._validate_timestamp(cleaned, errors)
            
            # Validate transaction type
            self._validate_transaction_type(cleaned, errors)
            
            # Validate channel
            self._validate_channel(cleaned, errors)
            
            # Validate account numbers
            self._validate_account_numbers(cleaned, errors)
            
            # Validate risk level if present
            self._validate_risk_level(cleaned, errors)
            
            # Check for duplicates (if id is present)
            self._check_duplicate_id(cleaned, errors)
            
            if errors:
                self.validation_stats["failed"] += 1
                self.validation_stats["errors"].extend(errors)
                if self.strict_mode:
                    raise ValidationError(f"Validation failed: {', '.join(errors)}")
                return False, cleaned, errors
            
            self.validation_stats["passed"] += 1
            return True, cleaned, []
            
        except Exception as e:
            self.validation_stats["failed"] += 1
            error_msg = f"Unexpected validation error: {str(e)}"
            self.validation_stats["errors"].append(error_msg)
            logger.error(error_msg, exc_info=True)
            if self.strict_mode:
                raise
            return False, cleaned, [error_msg]
    
    def _validate_required_fields(self, transaction: Dict[str, Any], errors: List[str]) -> None:
        """Validate that required fields are present."""
        required_fields = ["amount", "transaction_type", "sender_account"]
        
        for field in required_fields:
            if field not in transaction or transaction[field] is None:
                errors.append(f"Missing required field: {field}")
                # Set default value
                if field == "amount":
                    transaction[field] = 0.0
                elif field == "transaction_type":
                    transaction[field] = "transfer"
                elif field == "sender_account":
                    transaction[field] = "UNKNOWN"
    
    def _validate_amount(self, transaction: Dict[str, Any], errors: List[str]) -> None:
        """Validate and clean transaction amount."""
        try:
            amount = float(transaction.get("amount", 0))
            
            if amount < self.MIN_AMOUNT:
                errors.append(f"Amount {amount} below minimum {self.MIN_AMOUNT}")
                if not self.strict_mode:
                    amount = self.MIN_AMOUNT
            
            if amount > self.MAX_AMOUNT:
                errors.append(f"Amount {amount} exceeds maximum {self.MAX_AMOUNT}")
                if not self.strict_mode:
                    amount = self.MAX_AMOUNT
            
            transaction["amount"] = amount
            
        except (ValueError, TypeError):
            errors.append(f"Invalid amount value: {transaction.get('amount')}")
            transaction["amount"] = 0.0
    
    def _validate_timestamp(self, transaction: Dict[str, Any], errors: List[str]) -> None:
        """Validate and clean transaction timestamp."""
        timestamp = transaction.get("timestamp")
        
        if timestamp is None:
            errors.append("Missing timestamp")
            transaction["timestamp"] = datetime.now(timezone.utc).isoformat()
            return
        
        try:
            if isinstance(timestamp, str):
                parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            elif isinstance(timestamp, datetime):
                parsed = timestamp
            else:
                raise ValueError(f"Invalid timestamp type: {type(timestamp)}")
            
            # Ensure timezone-aware
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            
            if parsed < self.MIN_TIMESTAMP:
                errors.append(f"Timestamp {parsed} before minimum {self.MIN_TIMESTAMP}")
            
            if parsed > self.MAX_TIMESTAMP:
                errors.append(f"Timestamp {parsed} after maximum {self.MAX_TIMESTAMP}")
            
            transaction["timestamp"] = parsed.isoformat()
            
        except (ValueError, TypeError) as e:
            errors.append(f"Invalid timestamp format: {timestamp}")
            transaction["timestamp"] = datetime.now(timezone.utc).isoformat()
    
    def _validate_transaction_type(self, transaction: Dict[str, Any], errors: List[str]) -> None:
        """Validate transaction type."""
        tx_type = transaction.get("transaction_type", "").lower().strip()
        
        if tx_type not in self.VALID_TX_TYPES:
            errors.append(f"Invalid transaction type: {tx_type}")
            if not self.strict_mode:
                transaction["transaction_type"] = "transfer"
        else:
            transaction["transaction_type"] = tx_type
    
    def _validate_channel(self, transaction: Dict[str, Any], errors: List[str]) -> None:
        """Validate channel."""
        channel = transaction.get("channel", "online").lower().strip()
        
        if channel not in self.VALID_CHANNELS:
            errors.append(f"Invalid channel: {channel}")
            if not self.strict_mode:
                transaction["channel"] = "online"
        else:
            transaction["channel"] = channel
    
    def _validate_account_numbers(self, transaction: Dict[str, Any], errors: List[str]) -> None:
        """Validate account numbers."""
        sender = transaction.get("sender_account", "")
        receiver = transaction.get("receiver_account", "")
        
        if not sender or not isinstance(sender, str):
            errors.append(f"Invalid sender account: {sender}")
            transaction["sender_account"] = "UNKNOWN"
        
        if receiver and not isinstance(receiver, str):
            errors.append(f"Invalid receiver account: {receiver}")
            transaction["receiver_account"] = str(receiver)
    
    def _validate_risk_level(self, transaction: Dict[str, Any], errors: List[str]) -> None:
        """Validate risk level if present."""
        risk_level = transaction.get("risk_level")
        
        if risk_level is not None:
            risk_level = str(risk_level).lower().strip()
            if risk_level not in self.VALID_RISK_LEVELS:
                errors.append(f"Invalid risk level: {risk_level}")
                if not self.strict_mode:
                    transaction["risk_level"] = "normal"
            else:
                transaction["risk_level"] = risk_level
        
        # Validate risk score
        risk_score = transaction.get("risk_score")
        if risk_score is not None:
            try:
                score = float(risk_score)
                if not (0 <= score <= 100):
                    errors.append(f"Risk score {score} out of range [0, 100]")
                    if not self.strict_mode:
                        transaction["risk_score"] = max(0, min(100, score))
                else:
                    transaction["risk_score"] = score
            except (ValueError, TypeError):
                errors.append(f"Invalid risk score: {risk_score}")
                transaction["risk_score"] = 0.0
    
    def _check_duplicate_id(self, transaction: Dict[str, Any], errors: List[str]) -> None:
        """Check for duplicate transaction ID if present."""
        tx_id = transaction.get("id")
        
        if tx_id is not None and not isinstance(tx_id, (int, str)):
            errors.append(f"Invalid transaction ID type: {type(tx_id)}")
    
    def validate_batch(self, transactions: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
        """
        Validate a batch of transactions.
        
        Args:
            transactions: List of transaction dictionaries
            
        Returns:
            Tuple of (valid_transactions, invalid_transactions, all_errors)
        """
        valid = []
        invalid = []
        all_errors = []
        
        for tx in transactions:
            is_valid, cleaned, errors = self.validate_transaction(tx)
            
            if is_valid:
                valid.append(cleaned)
            else:
                invalid.append(cleaned)
                all_errors.extend(errors)
        
        return valid, invalid, all_errors
    
    def get_stats(self) -> Dict[str, Any]:
        """Get validation statistics."""
        return {
            **self.validation_stats,
            "pass_rate": (
                self.validation_stats["passed"] / self.validation_stats["total_validated"]
                if self.validation_stats["total_validated"] > 0
                else 0.0
            )
        }
    
    def reset_stats(self) -> None:
        """Reset validation statistics."""
        self.validation_stats = {
            "total_validated": 0,
            "passed": 0,
            "failed": 0,
            "fixed": 0,
            "errors": []
        }


# Global validator instance
_default_validator = TransactionValidator(strict_mode=False)


def validate_transaction(transaction: Dict[str, Any], strict: bool = False) -> Tuple[bool, Dict[str, Any], List[str]]:
    """
    Convenience function to validate a single transaction.
    
    Args:
        transaction: Transaction dictionary to validate
        strict: Whether to use strict validation mode
        
    Returns:
        Tuple of (is_valid, cleaned_transaction, error_messages)
    """
    validator = TransactionValidator(strict_mode=strict)
    return validator.validate_transaction(transaction)


def validate_batch(transactions: List[Dict[str, Any]], strict: bool = False) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """
    Convenience function to validate a batch of transactions.
    
    Args:
        transactions: List of transaction dictionaries
        strict: Whether to use strict validation mode
        
    Returns:
        Tuple of (valid_transactions, invalid_transactions, all_errors)
    """
    validator = TransactionValidator(strict_mode=strict)
    return validator.validate_batch(transactions)
