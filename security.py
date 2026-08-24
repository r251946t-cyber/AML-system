"""
security.py — Security Module

This module provides security functions for the AML system including:
- Rate limiting for login attempts
- Account lockout mechanisms
- Secure HTTP headers
- Password hashing utilities

Functions:
    - check_login_attempts: Check if identifier is locked out
    - record_login_attempt: Record login attempt for rate limiting
    - add_security_headers: Add security headers to Flask responses
"""

import time
from collections import defaultdict
from flask import Response


# Security: Rate limiting for login attempts
_login_attempts = defaultdict(list)
_account_lockouts = defaultdict(dict)
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 minutes
RATE_LIMIT_WINDOW = 300  # 5 minutes


def check_login_attempts(identifier):
    """
    Check if identifier is locked out due to too many failed attempts.
    
    Args:
        identifier: User identifier (username, email, or IP address)
    
    Returns:
        Tuple of (allowed: bool, message: str or None)
    """
    if identifier in _account_lockouts:
        lockout_data = _account_lockouts[identifier]
        if time.time() < lockout_data['until']:
            remaining_time = int(lockout_data['until'] - time.time())
            return False, f"Account locked. Try again in {remaining_time} seconds."
        else:
            # Lockout expired, clear it
            del _account_lockouts[identifier]
            _login_attempts[identifier] = []
    return True, None


def record_login_attempt(identifier, success):
    """
    Record login attempt for rate limiting.
    
    Args:
        identifier: User identifier (username, email, or IP address)
        success: Boolean indicating if login was successful
    
    Returns:
        Boolean indicating if account is now locked
    """
    current_time = time.time()
    
    # Clean old attempts outside the rate limit window
    _login_attempts[identifier] = [
        attempt for attempt in _login_attempts[identifier]
        if current_time - attempt < RATE_LIMIT_WINDOW
    ]
    
    if success:
        # Clear failed attempts on successful login
        _login_attempts[identifier] = []
        if identifier in _account_lockouts:
            del _account_lockouts[identifier]
    else:
        # Record failed attempt
        _login_attempts[identifier].append(current_time)
        
        # Check if should lockout
        if len(_login_attempts[identifier]) >= MAX_LOGIN_ATTEMPTS:
            _account_lockouts[identifier] = {
                'until': current_time + LOCKOUT_DURATION
            }
            return True  # Account is now locked
    
    return False  # Account not locked


def add_security_headers(response):
    """
    Add security headers to Flask response.
    
    Args:
        response: Flask Response object
    
    Returns:
        Response with security headers added
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


def is_account_locked(identifier):
    """
    Check if an account is currently locked without modifying state.
    
    Args:
        identifier: User identifier
    
    Returns:
        Boolean indicating if account is locked
    """
    if identifier in _account_lockouts:
        lockout_data = _account_lockouts[identifier]
        if time.time() < lockout_data['until']:
            return True
        else:
            # Lockout expired, clean up
            del _account_lockouts[identifier]
            _login_attempts[identifier] = []
    return False


def get_remaining_lockout_time(identifier):
    """
    Get remaining lockout time for an identifier.
    
    Args:
        identifier: User identifier
    
    Returns:
        Remaining seconds, or 0 if not locked
    """
    if identifier in _account_lockouts:
        lockout_data = _account_lockouts[identifier]
        remaining = lockout_data['until'] - time.time()
        return max(0, int(remaining))
    return 0


def clear_login_attempts(identifier):
    """
    Clear all login attempts and lockouts for an identifier.
    
    Args:
        identifier: User identifier
    """
    if identifier in _login_attempts:
        del _login_attempts[identifier]
    if identifier in _account_lockouts:
        del _account_lockouts[identifier]
