"""
transactions.py — Transaction Processing Module

This module handles transaction-related operations for the AML system including:
- Risk level calculation from scores
- Risk calibration for generated transactions
- Rule and AI risk combination
- Transaction event processing

Functions:
    - _risk_level_from_score: Convert risk score to risk level
    - _calibrate_generated_transaction_risk: Calibrate risk for synthetic transactions
    - _combine_rule_ai_risk: Combine rule-based and AI risk assessments
"""

# Flag to disable rule-based engine for AI-only testing
_RULE_ENGINE_ENABLED = False

RISK_RANK = {
    "normal": 0,
    "low": 1,
    "suspicious": 2,
    "super_suspicious": 3,
    "high_risk": 3,
    "critical": 4,
}

AI_RISK_SCORES = {
    "normal": 10,
    "suspicious": 55,
    "super_suspicious": 90,
}


def set_rule_engine_enabled(enabled: bool):
    """
    Enable or disable the rule-based engine for AI-only testing.
    
    Args:
        enabled: Boolean to enable/disable rule engine
    """
    global _RULE_ENGINE_ENABLED
    _RULE_ENGINE_ENABLED = enabled


def is_rule_engine_enabled():
    """
    Check if rule-based engine is enabled.
    
    Returns:
        Boolean indicating if rule engine is enabled
    """
    return _RULE_ENGINE_ENABLED


def _risk_level_from_score(score):
    """
    Convert risk score to risk level.
    
    Args:
        score: Risk score (0-100)
    
    Returns:
        Risk level string
    """
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high_risk"
    if score >= 40:
        return "suspicious"
    if score >= 25:
        return "low"
    return "normal"


def _calibrate_generated_transaction_risk(label, risk_score, risk_level, reason, mandatory=False):
    """
    Keep synthetic generation labels aligned with the intended AML split.
    
    Args:
        label: Generated label (normal, suspicious, super_suspicious)
        risk_score: Calculated risk score
        risk_level: Calculated risk level
        reason: Risk reason
        mandatory: Whether transaction is mandatory for review
    
    Returns:
        Tuple of (calibrated_score, calibrated_level, calibrated_reason)
    """
    label = (label or "normal").lower()

    if label == "normal":
        if mandatory:
            calibrated_score = max(risk_score, 35)
            calibrated_level = "high_risk" if calibrated_score >= 60 else "suspicious"
            return calibrated_score, calibrated_level, reason
        return 20, "normal", "Synthetic normal transaction preserved as normal."

    if label == "suspicious":
        calibrated_score = max(risk_score, 45)
        calibrated_level = "high_risk" if calibrated_score >= 60 else "suspicious"
        return calibrated_score, calibrated_level, reason

    calibrated_score = max(risk_score, 70)
    calibrated_level = "critical" if calibrated_score >= 80 else "high_risk"
    return calibrated_score, calibrated_level, reason


def _combine_rule_ai_risk(rule_score, rule_level, rule_reason, triggered_rules, ai_level, ai_confidence):
    """
    Combine rule-based and AI risk assessments into final risk.
    
    Args:
        rule_score: Rule-based risk score
        rule_level: Rule-based risk level
        rule_reason: Rule-based reason
        triggered_rules: List of triggered rules
        ai_level: AI-predicted risk level
        ai_confidence: AI confidence score
    
    Returns:
        Tuple of (final_score, final_level, final_reason, ai_reason)
    """
    # Simplified - mandatory check now based on screening severity only
    mandatory = any(r.get("severity") == "critical" for r in triggered_rules) if triggered_rules else False

    rule_rank = RISK_RANK.get(rule_level, 0)

    ai_reason = "AI model unavailable or not confident enough to affect final risk."

    final_score = rule_score
    final_level = rule_level
    final_reason = rule_reason

    if ai_level:
        ai_reason = (
            f"AI behavior model predicted {ai_level.replace('_', ' ')} "
            f"with {ai_confidence:.0%} confidence."
        )

    if ai_level and ai_confidence >= 0.50:
        ai_score = AI_RISK_SCORES.get(ai_level, rule_score)
        ai_rank = RISK_RANK.get(ai_level, 0)

        if not mandatory:
            ai_weight = min(0.85, max(0.65, ai_confidence))
            rule_weight = 1 - ai_weight
            blended_score = round((ai_score * ai_weight) + (rule_score * rule_weight))

            if ai_level == "normal" and ai_confidence >= 0.85 and rule_rank < RISK_RANK["low"]:
                final_score = min(blended_score, 24)
                final_level = "normal"
                final_reason = (
                    f"AI-led behavior model recognized this as normal for the sender "
                    f"({ai_confidence:.0%} confidence), so non-mandatory rule risk was reduced. "
                    f"Rule review: {rule_reason}"
                )
            else:
                if ai_level == "normal" and rule_rank >= RISK_RANK["suspicious"]:
                    blended_score = max(rule_score, blended_score)
                final_score = max(0, min(100, blended_score))
                final_level = _risk_level_from_score(final_score)

                if ai_level == "normal" and rule_rank >= RISK_RANK["suspicious"]:
                    ai_direction = "reviewed but did not downgrade"
                else:
                    ai_direction = "increased" if ai_rank > rule_rank else "tempered"
                final_reason = (
                    f"AI-led behavior model {ai_direction} the behavioral risk "
                    f"({ai_confidence:.0%} confidence, {ai_weight:.0%} AI weighting). "
                    f"Rule review: {rule_reason}"
                )

        elif ai_level == "normal":
            final_reason = (
                f"Mandatory compliance rule preserved despite AI normal prediction "
                f"({ai_confidence:.0%} confidence). Rule review: {rule_reason}"
            )

        elif ai_rank > rule_rank:
            final_score = max(rule_score, ai_score)
            final_level = _risk_level_from_score(final_score)
            final_reason = (
                f"Mandatory compliance rule preserved and AI behavior model added elevated context "
                f"({ai_confidence:.0%} confidence). Rule review: {rule_reason}"
            )

    if mandatory and RISK_RANK.get(final_level, 0) < RISK_RANK.get(rule_level, 0):
        final_score = rule_score
        final_level = rule_level
        final_reason = f"Mandatory compliance rule preserved. {rule_reason}"

    return final_score, final_level, final_reason, ai_reason


def get_transaction_by_id(conn, transaction_id):
    """
    Retrieve a transaction by its ID.
    
    Args:
        conn: Database connection
        transaction_id: Transaction ID
    
    Returns:
        Transaction row or None
    """
    return conn.execute("SELECT * FROM transactions WHERE id=?", (transaction_id,)).fetchone()


def get_transactions_by_account(conn, account_number, limit=50):
    """
    Retrieve transactions for a specific account.
    
    Args:
        conn: Database connection
        account_number: Account number
        limit: Maximum number of transactions to return
    
    Returns:
        List of transaction rows
    """
    return conn.execute(
        "SELECT * FROM transactions WHERE sender_account=? OR receiver_account=? ORDER BY timestamp DESC LIMIT ?",
        (account_number, account_number, limit)
    ).fetchall()


def get_all_transactions(conn, limit=100, offset=0):
    """
    Retrieve all transactions with pagination.
    
    Args:
        conn: Database connection
        limit: Maximum number of transactions to return
        offset: Number of transactions to skip
    
    Returns:
        List of transaction rows
    """
    return conn.execute(
        "SELECT * FROM transactions ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (limit, offset)
    ).fetchall()


def get_transactions_by_risk_level(conn, risk_level, limit=100):
    """
    Retrieve transactions by risk level.
    
    Args:
        conn: Database connection
        risk_level: Risk level to filter by
        limit: Maximum number of transactions to return
    
    Returns:
        List of transaction rows
    """
    return conn.execute(
        "SELECT * FROM transactions WHERE risk_level=? ORDER BY timestamp DESC LIMIT ?",
        (risk_level, limit)
    ).fetchall()


def get_transaction_statistics(conn):
    """
    Get transaction statistics for dashboard.
    
    Args:
        conn: Database connection
    
    Returns:
        Dictionary with transaction statistics
    """
    total = conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
    normal = conn.execute("SELECT COUNT(*) FROM transactions WHERE risk_level='normal'").fetchone()[0]
    suspicious = conn.execute("SELECT COUNT(*) FROM transactions WHERE risk_level='suspicious'").fetchone()[0]
    high_risk = conn.execute("SELECT COUNT(*) FROM transactions WHERE risk_level='high_risk'").fetchone()[0]
    critical = conn.execute("SELECT COUNT(*) FROM transactions WHERE risk_level='critical'").fetchone()[0]
    
    total_amount = conn.execute("SELECT COALESCE(SUM(amount), 0) FROM transactions").fetchone()[0]
    
    return {
        'total': total,
        'normal': normal,
        'suspicious': suspicious,
        'high_risk': high_risk,
        'critical': critical,
        'total_amount': float(total_amount) if total_amount else 0.0
    }
