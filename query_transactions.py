import os
from dotenv import load_dotenv

load_dotenv()

db_url = os.environ.get("DATABASE_URL", "mysql://aml:aml123@127.0.0.1:3306/aml")
print(f"Database URL: {db_url}")

try:
    import mysql.connector
    
    # Parse the connection string
    # Format: mysql://user:password@host:port/database
    parts = db_url.replace("mysql://", "").split("@")
    user_pass = parts[0].split(":")
    host_db = parts[1].split("/")
    host_port = host_db[0].split(":")
    
    config = {
        "user": user_pass[0],
        "password": user_pass[1],
        "host": host_port[0],
        "port": int(host_port[1]) if len(host_port) > 1 else 3306,
        "database": host_db[1],
        "autocommit": True
    }
    
    print(f"\nConnecting to {config['host']}:{config['port']}/{config['database']}...")
    conn = mysql.connector.connect(**config)
    cursor = conn.cursor(dictionary=True)
    
    # Get last 6 transactions
    cursor.execute("""
        SELECT id, amount, transaction_type, sender_account, risk_score, risk_level, 
               ai_risk_level, ai_confidence, ai_reason, rule_score, rule_reason, 
               timestamp
        FROM transactions
        ORDER BY timestamp DESC
        LIMIT 6
    """)
    
    transactions = cursor.fetchall()
    
    print("\n" + "=" * 140)
    print("LAST 6 TRANSACTIONS (most recent first)")
    print("=" * 140)
    
    if not transactions:
        print("No transactions found in database.")
    else:
        for i, tx in enumerate(transactions):
            print(f"\n[Transaction #{6-i}]")
            print(f"  ID: {tx['id']}")
            print(f"  Amount: ${tx['amount']:,.2f}")
            print(f"  Type: {tx['transaction_type']}")
            print(f"  Sender: {tx['sender_account']}")
            print(f"  Timestamp: {tx['timestamp']}")
            print(f"  Risk Score: {tx['risk_score']} → Risk Level: {tx['risk_level']}")
            print(f"  Rule Score: {tx['rule_score']} → Rule Reason: {tx['rule_reason']}")
            print(f"  AI Risk Level: {tx['ai_risk_level']} (Confidence: {tx['ai_confidence']})")
            print(f"  AI Reason: {tx['ai_reason']}")
    
    cursor.close()
    conn.close()
    
except Exception as e:
    print(f"Error: {e}")
    print("\nMake sure MySQL is running and the credentials are correct.")
