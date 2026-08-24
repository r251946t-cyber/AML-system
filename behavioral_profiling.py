"""
behavioral_profiling.py — Behavioral Profiling Module

This module handles customer behavioral profiling for AML risk assessment.
It integrates with the ai_core BehavioralProfiler to:
- Load and save customer behavioral profiles
- Build or update profiles from transaction history
- Assess transaction risk using behavioral analysis

Functions:
    - get_customer_behavioral_profile: Load profile from database
    - save_customer_behavioral_profile: Save profile to database
    - build_or_update_customer_profile: Build/update from history
    - assess_transaction_behavioral_risk: Assess risk using behavioral analysis
"""

import json
from typing import Optional, Dict, Any, Tuple, List
from ai_core import (
    behavioral_profiler,
    CustomerBehavioralProfile,
    TransactionAnomaly,
)


def get_customer_behavioral_profile(conn, account_number: str) -> Optional[CustomerBehavioralProfile]:
    """
    Load customer's behavioral profile from database.
    
    Args:
        conn: Database connection
        account_number: Customer account number
    
    Returns:
        CustomerBehavioralProfile or None if not found
    """
    row = conn.execute(
        "SELECT profile_data FROM behavioral_profiles WHERE account_number=?",
        (account_number,)
    ).fetchone()
    
    if not row or not row["profile_data"]:
        return None
    
    try:
        profile_data = json.loads(row["profile_data"])
        return behavioral_profiler.dict_to_profile(profile_data)
    except (json.JSONDecodeError, TypeError):
        return None


def save_customer_behavioral_profile(conn, profile: CustomerBehavioralProfile):
    """
    Save customer's behavioral profile to database.
    
    Args:
        conn: Database connection
        profile: CustomerBehavioralProfile to save
    """
    profile_dict = behavioral_profiler.profile_to_dict(profile)
    profile_json = json.dumps(profile_dict)
    
    existing = conn.execute(
        "SELECT account_number FROM behavioral_profiles WHERE account_number=?",
        (profile.account_number,)
    ).fetchone()
    
    if existing:
        conn.execute(
            "UPDATE behavioral_profiles SET profile_data=?, last_updated=?, total_transactions=? WHERE account_number=?",
            (profile_json, profile.last_updated, profile.total_transactions, profile.account_number)
        )
    else:
        conn.execute(
            "INSERT INTO behavioral_profiles (account_number, profile_data, last_updated, total_transactions) VALUES (?, ?, ?, ?)",
            (profile.account_number, profile_json, profile.last_updated, profile.total_transactions)
        )


def build_or_update_customer_profile(
    conn, account_number: str, exclude_transaction_id=None, reference_timestamp=None
) -> Optional[CustomerBehavioralProfile]:
    """
    Build or update customer's behavioral profile from transaction history.
    
    Args:
        conn: Database connection
        account_number: Customer account number
        exclude_transaction_id: Transaction ID to exclude from history
        reference_timestamp: Timestamp reference for history query
    
    Returns:
        CustomerBehavioralProfile or None if insufficient data
    """
    # Get customer's transaction history
    transactions = conn.execute(
        """
        SELECT id, amount, transaction_type, sender_account, receiver_account, 
               channel, timestamp, destination_country
        FROM transactions
        WHERE (sender_account=? OR receiver_account=?)
          AND (? IS NULL OR id<>?)
          AND (? IS NULL OR timestamp<?)
        ORDER BY timestamp DESC
        LIMIT 500
        """,
        (account_number, account_number, exclude_transaction_id, exclude_transaction_id,
         reference_timestamp, reference_timestamp)
    ).fetchall()
    
    if not transactions:
        return None
    
    # Convert to list of dicts
    tx_list = [dict(tx) for tx in transactions]
    
    # Extract profile (balance history not available from transactions table)
    profile = behavioral_profiler.extract_profile_from_history(
        account_number, tx_list, None
    )
    
    if profile:
        save_customer_behavioral_profile(conn, profile)
    
    return profile


def assess_transaction_behavioral_risk(
    conn,
    transaction: Dict[str, Any],
    sender_account: str
) -> Tuple[float, str, str, List[str]]:
    """
    Assess transaction risk using behavioral profiling.
    
    Engineering Constraint: No Circular Flagging
    - Behavioral scoring is based strictly on statistical anomalies (velocity, amount deviation, counterparty network)
    - Past alerts, alert counts, or historical risk ratings are NOT used in scoring
    - Cold-start grace period: Users with < 5 transactions get neutral baseline, rely on global ML model
    
    Args:
        conn: Database connection
        transaction: Transaction dictionary
        sender_account: Sender account number
    
    Returns:
        Tuple of (risk_score, risk_level, reason, anomaly_reasons)
    """
    # Get or build customer profile
    profile = get_customer_behavioral_profile(conn, sender_account)
    
    if not profile:
        # Try to build profile from history
        profile = build_or_update_customer_profile(
            conn, sender_account, exclude_transaction_id=transaction.get("id"), 
            reference_timestamp=transaction.get("timestamp")
        )
    
    if not profile:
        # Insufficient data for behavioral analysis - cold start
        # Return neutral baseline to rely on global ML model (ai_core.py)
        return 0, "normal", "Cold-start: insufficient transaction history for behavioral analysis (< 5 transactions)", []
    
    # Cold-start grace period: check if user has < 5 transactions
    if profile.total_transactions < 5:
        # Return neutral baseline to rely on global ML model
        return 0, "normal", f"Cold-start: building behavioral baseline ({profile.total_transactions}/5 transactions)", []
    
    # Detect anomaly using statistical features only (velocity, amount deviation, counterparty network)
    anomaly = behavioral_profiler.detect_anomaly(profile, transaction)
    
    # Update profile with this transaction (pass anomaly score for adaptive learning)
    updated_profile = behavioral_profiler.update_profile(profile, transaction, anomaly.overall_anomaly_score)
    save_customer_behavioral_profile(conn, updated_profile)
    
    # Convert anomaly score to risk score (0-100)
    risk_score = int(anomaly.overall_anomaly_score)
    
    # Map anomaly risk level to standard risk levels
    risk_level_mapping = {
        "normal": "normal",
        "low": "low", 
        "medium": "suspicious",
        "high": "high_risk",
        "critical": "critical"
    }
    risk_level = risk_level_mapping.get(anomaly.risk_level, "normal")
    
    # Build reason
    reason = anomaly.behavioral_context
    if anomaly.anomaly_reasons:
        reason += " " + "; ".join(anomaly.anomaly_reasons)
    
    return risk_score, risk_level, reason, anomaly.anomaly_reasons
