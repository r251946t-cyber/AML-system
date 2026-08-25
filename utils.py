"""
utils.py — Utility Functions Module

This module provides utility functions for the AML system including:
- Data serialization for JSON responses
- Event broadcasting helpers
- Pagination helpers
- JSON safe conversion
- SMTP email sending

Functions:
    - serialize_value: Convert value to JSON-serializable format
    - serialize_row: Convert database row to dict with serialized values
    - serialize_rows: Convert list of rows to serialized dicts
    - _json_safe: Convert value to JSON-safe format
    - request_page: Get page number from request args
    - _user_balance_payload: Create user balance payload for broadcasting
    - send_email: Send email using SMTP configuration from environment
"""

import os
import smtplib
import logging
from datetime import datetime, timezone
from decimal import Decimal
from email.message import EmailMessage
from flask import request


def serialize_value(value):
    """
    Convert a value to a JSON-serializable format.
    
    Args:
        value: Value to serialize
    
    Returns:
        JSON-serializable value
    """
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def serialize_row(row):
    """
    Convert a database row to a dictionary with serialized values.
    
    Args:
        row: Database row (dict-like)
    
    Returns:
        Dictionary with serialized values
    """
    return {key: serialize_value(row[key]) for key in row.keys()}


def serialize_rows(rows):
    """
    Convert a list of database rows to serialized dictionaries.
    
    Args:
        rows: List of database rows
    
    Returns:
        List of serialized dictionaries
    """
    return [serialize_row(row) for row in rows]


def _json_safe(value):
    """
    Convert a value to a JSON-safe format.
    
    Args:
        value: Value to convert
    
    Returns:
        JSON-safe value
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    try:
        return float(value)
    except (TypeError, ValueError):
        return str(value)


def request_page(parameter="page", default=1):
    """
    Get page number from request arguments.
    
    Args:
        parameter: Query parameter name
        default: Default page number
    
    Returns:
        Page number (minimum 1)
    """
    try:
        page = int(request.args.get(parameter, default))
    except (TypeError, ValueError):
        return default
    return max(1, page)


def _user_balance_payload(row):
    """
    Create a user balance payload for broadcasting.
    
    Args:
        row: User database row
    
    Returns:
        Dictionary with user balance information
    """
    return {
        "user_id": row["id"],
        "username": row["username"],
        "account_number": row["account_number"],
        "balance": float(row["balance"] or 0),
        "kyc_status": row["kyc_status"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _transaction_payload(row):
    """
    Create a transaction payload for broadcasting.
    
    Args:
        row: Transaction database row
    
    Returns:
        Dictionary with transaction information
    """
    confidence = row["ai_confidence"] if "ai_confidence" in row.keys() else 0
    ctr_required = row["ctr_required"] if "ctr_required" in row.keys() else 0
    sar_required = row["sar_required"] if "sar_required" in row.keys() else 0

    return {
        "id": row["id"],
        "sender_account": row["sender_account"],
        "receiver_account": row["receiver_account"],
        "amount": float(row["amount"]),
        "type": row["transaction_type"],
        "transaction_type": row["transaction_type"],
        "timestamp": row["timestamp"],
        "risk_level": row["risk_level"],
        "risk_score": float(row["risk_score"] or 0),
        "rule_level": row["rule_level"] or "normal",
        "rule_score": float(row["rule_score"] or 0),
        "ai_risk_level": row["ai_risk_level"] or "unavailable",
        "ai_confidence": float(confidence or 0),
        "ctr_required": bool(ctr_required),
        "sar_required": bool(sar_required),
        "channel": row["channel"] if "channel" in row.keys() else "online",
        "description": row["description"] or "",
    }


def _stats_payload(conn):
    """
    Create a statistics payload for broadcasting.
    
    Args:
        conn: Database connection
    
    Returns:
        Dictionary with system statistics
    """
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_transactions = conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
    open_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
    
    return {
        "total_users": total_users,
        "total_transactions": total_transactions,
        "open_alerts": open_alerts,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def send_email(to_email, subject, body, html_body=None):
    """
    Send email using SMTP configuration from environment variables.
    
    Reads SMTP configuration from:
    - SMTP_EMAIL: Sender email address
    - SMTP_PASSWORD: SMTP password or app-specific password
    - SMTP_SERVER: SMTP server hostname (default: smtp.gmail.com)
    - SMTP_PORT: SMTP port (default: 587 for TLS)
    
    Args:
        to_email: Recipient email address
        subject: Email subject
        body: Plain text email body
        html_body: Optional HTML email body
    
    Returns:
        bool: True if email sent successfully, False otherwise
    """
    smtp_email = os.environ.get("SMTP_EMAIL")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    
    # Check if SMTP is configured
    if not smtp_email or not smtp_password:
        logging.warning("SMTP not configured: SMTP_EMAIL or SMTP_PASSWORD not set")
        return False
    
    try:
        msg = EmailMessage()
        msg["From"] = smtp_email
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)
        
        if html_body:
            msg.add_alternative(html_body, subtype="html")
        
        # Connect to SMTP server and send
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Secure the connection
            server.login(smtp_email, smtp_password)
            server.send_message(msg)
        
        logging.info(f"Email sent successfully to {to_email}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to send email to {to_email}: {e}")
        return False
