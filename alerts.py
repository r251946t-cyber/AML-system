"""
alerts.py — Alert Management Module

This module handles alert-related operations for the AML system including:
- Creating alerts for suspicious transactions
- Updating alert status and assignments
- Broadcasting alert updates via real-time events
- Customer risk rating updates based on alert actions

Functions:
    - create_alert_if_needed: Create alert if transaction meets criteria
    - broadcast_alert_update: Broadcast alert update events
    - update_customer_risk_rating: Update customer risk based on alert action
    - _generate_sar_ref: Generate SAR reference number
    - _generate_ctr_ref: Generate CTR reference number
"""

import random
from datetime import datetime, timezone


def create_alert_if_needed(conn, transaction_id, account_number, risk_score, risk_level, reason, rules_json, timestamp):
    """
    Create an alert if the transaction meets suspicious criteria.
    
    Args:
        conn: Database connection
        transaction_id: Transaction ID
        account_number: Account number
        risk_score: Risk score (0-100)
        risk_level: Risk level (normal, low, suspicious, high_risk, critical)
        reason: Alert reason
        rules_json: JSON string of triggered rules
        timestamp: Transaction timestamp
    
    Returns:
        Alert ID if created, None otherwise
    """
    existing = conn.execute("SELECT id FROM alerts WHERE transaction_id=?", (transaction_id,)).fetchone()

    # Low scores are retained for trend analysis but do not interrupt analysts.
    # Alerts require a material, explainable signal (score >= 40).
    if existing is None and risk_level in ("suspicious", "high_risk", "critical"):
        conn.execute(
            """
            INSERT INTO alerts (transaction_id, account_number, risk_score, risk_level, reason,
                                rules_triggered, status, timestamp)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (transaction_id, account_number, risk_score, risk_level, reason, rules_json, 'open', timestamp),
        )
        return get_last_insert_id(conn)
    return None


def get_last_insert_id(conn):
    """
    Get the last inserted row ID from the database connection.
    
    Args:
        conn: Database connection
    
    Returns:
        Last inserted row ID
    """
    cursor = conn.execute("SELECT last_insert_rowid()")
    return cursor.fetchone()[0]


def update_customer_risk_rating(db, account_number, action, current_risk):
    """
    Update customer risk rating based on alert action.
    
    Args:
        db: Database connection
        account_number: Account number
        action: Action taken (resolve, escalate, file_sar)
        current_risk: Current risk rating
    
    Returns:
        New risk rating
    """
    risk_levels = ["standard", "medium", "high", "critical"]
    
    try:
        current_idx = risk_levels.index(current_risk.lower()) if current_risk.lower() in risk_levels else 0
    except:
        current_idx = 0
    
    if action == "resolve":
        # Reduce risk level on resolve
        new_idx = max(0, current_idx - 1)
    elif action == "escalate":
        # Increase risk level on escalate
        new_idx = min(len(risk_levels) - 1, current_idx + 1)
    elif action == "file_sar":
        # Set to high or critical on SAR
        new_idx = min(len(risk_levels) - 1, current_idx + 2)
    else:
        return current_risk
    
    new_risk = risk_levels[new_idx]
    
    # Update database (caller will commit)
    db.execute("UPDATE users SET risk_rating=? WHERE account_number=?", (new_risk, account_number))
    
    return new_risk


def _generate_sar_ref():
    """
    Generate a unique SAR (Suspicious Activity Report) reference number.
    
    Returns:
        SAR reference string
    """
    ts = datetime.now(timezone.utc)
    return f"SAR-{ts.year}-{ts.strftime('%m%d')}-{random.randint(1000,9999)}"


def _generate_ctr_ref():
    """
    Generate a unique CTR (Currency Transaction Report) reference number.
    
    Returns:
        CTR reference string
    """
    ts = datetime.now(timezone.utc)
    return f"CTR-{ts.year}-{ts.strftime('%m%d')}-{random.randint(1000,9999)}"


def get_alert_by_id(conn, alert_id):
    """
    Retrieve an alert by its ID.
    
    Args:
        conn: Database connection
        alert_id: Alert ID
    
    Returns:
        Alert row or None
    """
    return conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()


def get_alerts_by_account(conn, account_number, limit=50):
    """
    Retrieve alerts for a specific account.
    
    Args:
        conn: Database connection
        account_number: Account number
        limit: Maximum number of alerts to return
    
    Returns:
        List of alert rows
    """
    return conn.execute(
        "SELECT * FROM alerts WHERE account_number=? ORDER BY timestamp DESC LIMIT ?",
        (account_number, limit)
    ).fetchall()


def get_open_alerts(conn, limit=100):
    """
    Retrieve all open alerts.
    
    Args:
        conn: Database connection
        limit: Maximum number of alerts to return
    
    Returns:
        List of alert rows
    """
    return conn.execute(
        "SELECT * FROM alerts WHERE status='open' ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    ).fetchall()


def update_alert_status(conn, alert_id, status, assigned_to=None, resolved_by=None):
    """
    Update alert status and assignment.
    
    Args:
        conn: Database connection
        alert_id: Alert ID
        status: New status (open, investigating, resolved, closed)
        assigned_to: User assigned to alert (optional)
        resolved_by: User who resolved alert (optional)
    """
    if status in ('resolved', 'closed'):
        resolved_at = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE alerts SET status=?, resolved_by=?, resolved_at=? WHERE id=?",
            (status, resolved_by, resolved_at, alert_id)
        )
    else:
        conn.execute(
            "UPDATE alerts SET status=?, assigned_to=? WHERE id=?",
            (status, assigned_to, alert_id)
        )


def get_alert_statistics(conn):
    """
    Get alert statistics for dashboard.
    
    Args:
        conn: Database connection
    
    Returns:
        Dictionary with alert statistics
    """
    total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    open_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
    investigating = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='investigating'").fetchone()[0]
    resolved = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='resolved'").fetchone()[0]
    closed = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='closed'").fetchone()[0]
    
    return {
        'total': total,
        'open': open_count,
        'investigating': investigating,
        'resolved': resolved,
        'closed': closed
    }
