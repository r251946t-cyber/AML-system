import sqlite3
import json

conn = sqlite3.connect('aml.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Get last 6 transactions ordered by timestamp
cursor.execute("""
    SELECT id, amount, transaction_type, sender_account, risk_score, risk_level, 
           ai_risk_level, ai_confidence, ai_reason, rule_score, rule_reason, 
           timestamp
    FROM transactions
    ORDER BY timestamp DESC
    LIMIT 6
""")

transactions = cursor.fetchall()
print("=" * 120)
print("LAST 6 TRANSACTIONS (most recent first)")
print("=" * 120)

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

conn.close()
