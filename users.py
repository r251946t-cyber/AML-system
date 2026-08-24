"""
users.py — User Management Module

This module handles user-related operations for the AML system including:
- User creation and validation
- User authentication
- User profile management
- Staff account management

Functions:
    - validate_id_number: Validate Zimbabwe ID number format
    - create_user: Create a new user account
    - get_user_by_account_number: Retrieve user by account number
    - get_user_by_username: Retrieve user by username
    - update_user_balance: Update user account balance
    - get_staff_accounts: Get predefined staff accounts
"""

import re
import os
from werkzeug.security import generate_password_hash


ID_NUMBER_PATTERN = re.compile(r"^\d{2}-\d{6,7}[A-Z]\d{2}$")
ID_NUMBER_FORMAT_MESSAGE = "ID number must use the format 00-000000A00, for example 08-995728P34."

STAFF_ACCOUNTS = {
    "Admin": {
        "password": os.environ.get("ADMIN_PASSWORD", "Admin123"),
        "role": "admin",
        "email": os.environ.get("ADMIN_EMAIL", "admin@example.com"),
        "id_number": "63-1000001A01",
        "account_number": "ACC1001",
    },
    "Compliance": {
        "password": os.environ.get("COMPLIANCE_PASSWORD", "Compliance123"),
        "role": "compliance",
        "email": os.environ.get("COMPLIANCE_EMAIL", "compliance@example.com"),
        "id_number": "63-1000002A02",
        "account_number": "ACC1002",
    },
}

RESERVED_STAFF_USERNAMES = {username.lower() for username in STAFF_ACCOUNTS}


def validate_id_number(id_number):
    """
    Validate Zimbabwe ID number format.
    
    Args:
        id_number: ID number string to validate
    
    Returns:
        Tuple of (is_valid: bool, message: str)
    """
    if not id_number:
        return False, "ID number is required"
    
    if not ID_NUMBER_PATTERN.match(id_number):
        return False, ID_NUMBER_FORMAT_MESSAGE
    
    return True, None


def is_username_reserved(username):
    """
    Check if username is reserved for staff accounts.
    
    Args:
        username: Username to check
    
    Returns:
        Boolean indicating if username is reserved
    """
    return username.lower() in RESERVED_STAFF_USERNAMES


def get_staff_accounts():
    """
    Get predefined staff accounts.
    
    Returns:
        Dictionary of staff account configurations
    """
    return STAFF_ACCOUNTS


def create_user(conn, username, password, account_number, id_number=None, email=None, role="customer"):
    """
    Create a new user account.
    
    Args:
        conn: Database connection
        username: Username
        password: Plain text password (will be hashed)
        account_number: Account number
        id_number: ID number (optional)
        email: Email address (optional)
        role: User role (default: customer)
    
    Returns:
        User ID if successful, None otherwise
    """
    password_hash = generate_password_hash(password)
    
    conn.execute(
        """
        INSERT INTO users (username, password_hash, account_number, id_number, email, role)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (username, password_hash, account_number, id_number, email, role)
    )
    
    # Get last insert ID
    cursor = conn.execute("SELECT last_insert_rowid()")
    return cursor.fetchone()[0]


def get_user_by_account_number(conn, account_number):
    """
    Retrieve user by account number.
    
    Args:
        conn: Database connection
        account_number: Account number
    
    Returns:
        User row or None
    """
    return conn.execute(
        "SELECT * FROM users WHERE account_number=?",
        (account_number,)
    ).fetchone()


def get_user_by_username(conn, username):
    """
    Retrieve user by username.
    
    Args:
        conn: Database connection
        username: Username
    
    Returns:
        User row or None
    """
    return conn.execute(
        "SELECT * FROM users WHERE username=?",
        (username,)
    ).fetchone()


def get_user_by_id(conn, user_id):
    """
    Retrieve user by ID.
    
    Args:
        conn: Database connection
        user_id: User ID
    
    Returns:
        User row or None
    """
    return conn.execute(
        "SELECT * FROM users WHERE id=?",
        (user_id,)
    ).fetchone()


def update_user_balance(conn, account_number, new_balance):
    """
    Update user account balance.
    
    Args:
        conn: Database connection
        account_number: Account number
        new_balance: New balance amount
    """
    conn.execute(
        "UPDATE users SET balance=? WHERE account_number=?",
        (new_balance, account_number)
    )


def update_user_kyc_status(conn, account_number, kyc_status):
    """
    Update user KYC status.
    
    Args:
        conn: Database connection
        account_number: Account number
        kyc_status: New KYC status
    """
    conn.execute(
        "UPDATE users SET kyc_status=? WHERE account_number=?",
        (kyc_status, account_number)
    )


def update_user_risk_rating(conn, account_number, risk_rating):
    """
    Update user risk rating.
    
    Args:
        conn: Database connection
        account_number: Account number
        risk_rating: New risk rating
    """
    conn.execute(
        "UPDATE users SET risk_rating=? WHERE account_number=?",
        (risk_rating, account_number)
    )


def get_all_users(conn, limit=100, offset=0):
    """
    Retrieve all users with pagination.
    
    Args:
        conn: Database connection
        limit: Maximum number of users to return
        offset: Number of users to skip
    
    Returns:
        List of user rows
    """
    return conn.execute(
        "SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (limit, offset)
    ).fetchall()


def get_users_by_role(conn, role, limit=100):
    """
    Retrieve users by role.
    
    Args:
        conn: Database connection
        role: User role
        limit: Maximum number of users to return
    
    Returns:
        List of user rows
    """
    return conn.execute(
        "SELECT * FROM users WHERE role=? ORDER BY created_at DESC LIMIT ?",
        (role, limit)
    ).fetchall()


def update_user_last_login(conn, user_id):
    """
    Update user's last login timestamp.
    
    Args:
        conn: Database connection
        user_id: User ID
    """
    from datetime import datetime, timezone
    conn.execute(
        "UPDATE users SET last_login=? WHERE id=?",
        (datetime.now(timezone.utc).isoformat(), user_id)
    )


def verify_password(conn, username, password):
    """
    Verify user password.
    
    Args:
        conn: Database connection
        username: Username
        password: Plain text password to verify
    
    Returns:
        User row if password matches, None otherwise
    """
    from werkzeug.security import check_password_hash
    
    user = get_user_by_username(conn, username)
    if user and check_password_hash(user["password_hash"], password):
        return user
    return None
