"""
reports.py — Report Generation Module

This module handles SAR (Suspicious Activity Report) and CTR (Currency Transaction Report)
generation and management for the AML system.

Functions:
    - create_sar_report: Create a new SAR report
    - create_ctr_report: Create a new CTR report
    - get_sar_reports: Retrieve SAR reports
    - get_ctr_reports: Retrieve CTR reports
    - update_sar_status: Update SAR report status
    - update_ctr_status: Update CTR report status
"""

from datetime import datetime, timezone
from utils import get_last_insert_id
from alerts import _generate_sar_ref, _generate_ctr_ref


def create_sar_report(conn, transaction_id, account_number, filing_reason, filed_by):
    """
    Create a new Suspicious Activity Report.
    
    Args:
        conn: Database connection
        transaction_id: Associated transaction ID
        account_number: Account number
        filing_reason: Reason for filing SAR
        filed_by: User who filed the report
    
    Returns:
        SAR report ID if successful, None otherwise
    """
    reference_number = _generate_sar_ref()
    
    conn.execute(
        """
        INSERT INTO sar_reports (reference_number, transaction_id, account_number, filing_reason, filed_by, filed_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (reference_number, transaction_id, account_number, filing_reason, filed_by, datetime.now(timezone.utc).isoformat())
    )
    
    # Get last insert ID
    return get_last_insert_id(conn)


def create_ctr_report(conn, account_number, total_amount, transaction_count, filing_date, filed_by):
    """
    Create a new Currency Transaction Report.
    
    Args:
        conn: Database connection
        account_number: Account number
        total_amount: Total amount for CTR
        transaction_count: Number of transactions
        filing_date: Filing date
        filed_by: User who filed the report
    
    Returns:
        CTR report ID if successful, None otherwise
    """
    reference_number = _generate_ctr_ref()
    
    conn.execute(
        """
        INSERT INTO ctr_reports (reference_number, account_number, total_amount, transaction_count, filing_date, filed_by, filed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (reference_number, account_number, total_amount, transaction_count, filing_date, filed_by, datetime.now(timezone.utc).isoformat())
    )
    
    # Get last insert ID
    return get_last_insert_id(conn)


def get_sar_reports(conn, limit=100):
    """
    Retrieve SAR reports.
    
    Args:
        conn: Database connection
        limit: Maximum number of reports to return
    
    Returns:
        List of SAR report rows
    """
    return conn.execute(
        "SELECT * FROM sar_reports ORDER BY filed_at DESC LIMIT ?",
        (limit,)
    ).fetchall()


def get_sar_reports_by_account(conn, account_number, limit=50):
    """
    Retrieve SAR reports for a specific account.
    
    Args:
        conn: Database connection
        account_number: Account number
        limit: Maximum number of reports to return
    
    Returns:
        List of SAR report rows
    """
    return conn.execute(
        "SELECT * FROM sar_reports WHERE account_number=? ORDER BY filed_at DESC LIMIT ?",
        (account_number, limit)
    ).fetchall()


def get_sar_by_id(conn, sar_id):
    """
    Retrieve a SAR report by ID.
    
    Args:
        conn: Database connection
        sar_id: SAR report ID
    
    Returns:
        SAR report row or None
    """
    return conn.execute("SELECT * FROM sar_reports WHERE id=?", (sar_id,)).fetchone()


def get_ctr_reports(conn, limit=100):
    """
    Retrieve CTR reports.
    
    Args:
        conn: Database connection
        limit: Maximum number of reports to return
    
    Returns:
        List of CTR report rows
    """
    return conn.execute(
        "SELECT * FROM ctr_reports ORDER BY filed_at DESC LIMIT ?",
        (limit,)
    ).fetchall()


def get_ctr_reports_by_account(conn, account_number, limit=50):
    """
    Retrieve CTR reports for a specific account.
    
    Args:
        conn: Database connection
        account_number: Account number
        limit: Maximum number of reports to return
    
    Returns:
        List of CTR report rows
    """
    return conn.execute(
        "SELECT * FROM ctr_reports WHERE account_number=? ORDER BY filed_at DESC LIMIT ?",
        (account_number, limit)
    ).fetchall()


def get_ctr_by_id(conn, ctr_id):
    """
    Retrieve a CTR report by ID.
    
    Args:
        conn: Database connection
        ctr_id: CTR report ID
    
    Returns:
        CTR report row or None
    """
    return conn.execute("SELECT * FROM ctr_reports WHERE id=?", (ctr_id,)).fetchone()


def update_sar_status(conn, sar_id, status):
    """
    Update SAR report status.
    
    Args:
        conn: Database connection
        sar_id: SAR report ID
        status: New status
    """
    conn.execute(
        "UPDATE sar_reports SET status=? WHERE id=?",
        (status, sar_id)
    )


def update_ctr_status(conn, ctr_id, status):
    """
    Update CTR report status.
    
    Args:
        conn: Database connection
        ctr_id: CTR report ID
        status: New status
    """
    conn.execute(
        "UPDATE ctr_reports SET status=? WHERE id=?",
        (status, ctr_id)
    )


def get_report_statistics(conn):
    """
    Get report statistics for dashboard.
    
    Args:
        conn: Database connection
    
    Returns:
        Dictionary with report statistics
    """
    sar_total = conn.execute("SELECT COUNT(*) FROM sar_reports").fetchone()[0]
    sar_filed = conn.execute("SELECT COUNT(*) FROM sar_reports WHERE status='filed'").fetchone()[0]
    sar_reviewed = conn.execute("SELECT COUNT(*) FROM sar_reports WHERE status='reviewed'").fetchone()[0]
    
    ctr_total = conn.execute("SELECT COUNT(*) FROM ctr_reports").fetchone()[0]
    ctr_filed = conn.execute("SELECT COUNT(*) FROM ctr_reports WHERE status='filed'").fetchone()[0]
    
    return {
        'sar_total': sar_total,
        'sar_filed': sar_filed,
        'sar_reviewed': sar_reviewed,
        'ctr_total': ctr_total,
        'ctr_filed': ctr_filed
    }


def log_system_activity(conn, user_id, action, details, ip_address=None):
    """
    Log system activity for audit trail.
    
    Args:
        conn: Database connection
        user_id: User ID performing the action
        action: Action performed
        details: Action details
        ip_address: IP address (optional)
    """
    conn.execute(
        """
        INSERT INTO system_activity_log (user_id, action, details, ip_address, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, action, details, ip_address, datetime.now(timezone.utc).isoformat())
    )


def get_activity_log(conn, limit=100, user_id=None):
    """
    Retrieve system activity log.
    
    Args:
        conn: Database connection
        limit: Maximum number of entries to return
        user_id: Filter by user ID (optional)
    
    Returns:
        List of activity log rows
    """
    if user_id:
        return conn.execute(
            "SELECT * FROM system_activity_log WHERE user_id=? ORDER BY timestamp DESC LIMIT ?",
            (user_id, limit)
        ).fetchall()
    return conn.execute(
        "SELECT * FROM system_activity_log ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    ).fetchall()
