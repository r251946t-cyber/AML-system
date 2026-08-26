#!/usr/bin/env python3
"""
Test script to verify SMTP configuration and email sending.
Run this script to diagnose SMTP issues.
"""

import os
import smtplib
from email.message import EmailMessage

def test_smtp():
    print("=" * 60)
    print("SMTP Configuration Test")
    print("=" * 60)
    
    # Load environment variables
    smtp_email = os.environ.get("SMTP_EMAIL")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    
    print(f"\nConfiguration:")
    print(f"  SMTP_EMAIL: {smtp_email}")
    print(f"  SMTP_PASSWORD: {'SET' if smtp_password else 'NOT SET'}")
    print(f"  SMTP_SERVER: {smtp_server}")
    print(f"  SMTP_PORT: {smtp_port}")
    
    # Check if credentials are set
    if not smtp_email or not smtp_password:
        print("\n❌ ERROR: SMTP_EMAIL or SMTP_PASSWORD not set in environment variables")
        print("\nPlease add these to your .env file:")
        print("  SMTP_EMAIL=your-gmail@gmail.com")
        print("  SMTP_PASSWORD=your-gmail-app-password")
        return False
    
    print("\n✓ Environment variables are set")
    
    # Test network connectivity
    print(f"\nTesting network connectivity to {smtp_server}...")
    try:
        import socket
        socket.create_connection((smtp_server, smtp_port), timeout=10)
        print(f"✓ Can connect to {smtp_server}:{smtp_port}")
    except socket.timeout:
        print(f"❌ ERROR: Connection timeout to {smtp_server}:{smtp_port}")
        print("  Check your internet connection or firewall settings")
        return False
    except socket.gaierror as e:
        print(f"❌ ERROR: DNS resolution failed for {smtp_server}: {e}")
        print("  Check your internet connection")
        return False
    except OSError as e:
        print(f"❌ ERROR: Network error: {e}")
        print("  Check your internet connection or VPN settings")
        return False
    
    # Test SMTP connection
    print(f"\nTesting SMTP connection...")
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            print(f"✓ Connected to SMTP server")
            
            # Test EHLO
            server.ehlo()
            print(f"✓ EHLO successful")
            
            # Test STARTTLS
            server.starttls()
            print(f"✓ STARTTLS successful")
            
            # Test login
            server.login(smtp_email, smtp_password)
            print(f"✓ Login successful")
            
    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ ERROR: Authentication failed: {e}")
        print("\nPossible causes:")
        print("  1. Incorrect SMTP_PASSWORD (use Gmail App Password, not regular password)")
        print("  2. 2-Step Verification not enabled on Gmail account")
        print("  3. App Password not generated correctly")
        print("\nTo get a Gmail App Password:")
        print("  1. Go to Google Account → Security")
        print("  2. Enable 2-Step Verification")
        print("  3. Go to App passwords")
        print("  4. Generate a new app password for 'Mail'")
        print("  5. Use that 16-character password as SMTP_PASSWORD")
        return False
    except smtplib.SMTPException as e:
        print(f"❌ ERROR: SMTP error: {e}")
        return False
    except Exception as e:
        print(f"❌ ERROR: Unexpected error: {e}")
        return False
    
    print("\n✓ All SMTP tests passed!")
    print("\nYour SMTP configuration is correct.")
    print("If emails still don't send, check your Gmail spam folder or sending limits.")
    return True

if __name__ == "__main__":
    # Load .env file if it exists
    env_file = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_file):
        print(f"Loading environment variables from {env_file}")
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ[key] = value
        print()
    
    success = test_smtp()
    exit(0 if success else 1)
