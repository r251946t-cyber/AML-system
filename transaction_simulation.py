"""
transaction_simulation.py — Transaction Simulation Module

This module handles the generation of simulated banking transactions for AML testing.
It provides realistic transaction scenarios including normal, suspicious, and highly suspicious
transactions based on money laundering typologies.

Functions:
    - _random_transaction_amount: Generate random transaction amounts
    - _simulation_plan: Create class distribution for AML training data
    - _simulation_timestamp: Generate realistic timestamps
    - _scenario_amount: Generate scenario-specific amounts
    - _simulation_segment_multiplier: Apply wealth segment multipliers
    - _simulation_transaction: Generate a single transaction
    - _simulation_reason: Generate simulation reasons
    - _history_profile: Build transaction history profile
    - _ai_profile_for_transaction: Build AI profile for transaction
"""

import random
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional


# Default profile features for AI model
PROFILE_FEATURE_DEFAULTS = {
    "sender_avg_amount": 0.0,
    "sender_max_amount": 0.0,
    "sender_tx_count": 0,
    "amount_to_sender_avg": 1.0,
    "amount_to_sender_max": 1.0,
    "sender_tx_count_24h": 0,
    "sender_volume_24h": 0.0,
    "amount_to_sender_volume_24h": 1.0,
    "is_new_recipient": 1.0,
    "same_day_count": 0,
    "same_day_total": 0.0,
    "same_recipient_count": 0,
    "rapid_transfer_count": 0,
}


def _random_transaction_amount(tx_type):
    """Generate random transaction amount based on type."""
    if tx_type == "transfer":
        return random.choice([25, 75, 150, 500, 950, 1500, 2500, 5000, 9000])
    if tx_type == "withdraw":
        return random.choice([20, 60, 120, 300, 1000, 3500, 10000])
    return random.choice([50, 100, 250, 450, 1000, 3000, 9999, 10000])


def _simulation_plan(count):
    """Create a realistic class distribution for AML training data.

    The majority of transactions should be ordinary activity, while the
    remaining minority consists of suspicious and highly suspicious cases.
    The split is tuned to support model training without overwhelming the
    dataset with rare anomalies.
    """
    if count <= 0:
        return []

    normal_count = max(1, int(count * 0.60))
    suspicious_count = max(0, int(count * 0.25))
    super_count = count - normal_count - suspicious_count

    if super_count < 0:
        super_count = 0

    labels = ["normal"] * normal_count + ["suspicious"] * suspicious_count + ["super_suspicious"] * super_count
    random.shuffle(labels)
    return labels


def _simulation_timestamp(hour):
    """Generate realistic timestamp within the last 30 days."""
    now = datetime.now(timezone.utc)
    days_back = random.randint(1, 30)

    candidate = now - timedelta(
        days=days_back,
        minutes=random.randint(0, 23 * 60 + 59),
    )

    return candidate.replace(
        hour=hour,
        minute=random.randint(0, 59),
        second=random.randint(0, 59),
        microsecond=0,
    ).isoformat()


# Normal transaction scenarios representing everyday banking activities
NORMAL_TRANSACTION_SCENARIOS = [
    {
        "type": "deposit",
        "amount": (850, 4200),
        "channel": "ach",
        "hours": list(range(8, 17)),
        "description": "Payroll credit from registered employer",
    },
    {
        "type": "withdraw",
        "amount": (12, 180),
        "channel": "card",
        "hours": list(range(7, 22)),
        "description": "Point-of-sale card purchase at local merchant",
    },
    {
        "type": "withdraw",
        "amount": (20, 500),
        "channel": "atm",
        "hours": list(range(6, 23)),
        "description": "ATM cash withdrawal at bank terminal",
    },
    {
        "type": "transfer",
        "amount": (35, 950),
        "channel": "mobile",
        "hours": list(range(7, 22)),
        "description": "Mobile transfer for household payment",
    },
    {
        "type": "transfer",
        "amount": (120, 1800),
        "channel": "online",
        "hours": list(range(8, 20)),
        "description": "Online bill payment to regular beneficiary",
    },
]


# Suspicious transaction scenarios representing potential money laundering
SUSPICIOUS_TRANSACTION_SCENARIOS = [
    {
        "type": "deposit",
        "amount": (9200, 9900),
        "channel": "branch",
        "hours": list(range(9, 16)),
        "description": "Cash deposit just below currency reporting threshold",
        "reason": "Possible structuring: cash deposit below the CTR threshold",
    },
    {
        "type": "transfer",
        "amount": (1400, 6800),
        "channel": "online",
        "hours": [0, 1, 2, 3, 22, 23],
        "description": "Unusual off-hours transfer to recently added beneficiary",
        "reason": "Off-hours transfer pattern inconsistent with normal customer activity",
    },
    {
        "type": "withdraw",
        "amount": (1500, 6500),
        "channel": "atm",
        "hours": [0, 1, 2, 3, 4, 22, 23],
        "description": "High-value ATM cash withdrawal outside normal banking hours",
        "reason": "Large cash withdrawal during unusual hours",
    },
    {
        "type": "transfer",
        "amount": (2500, 7400),
        "channel": "mobile",
        "hours": list(range(6, 23)),
        "description": "Multiple rapid mobile transfers to another customer account",
        "reason": "Potential layering through repeated customer-to-customer transfers",
    },
    {
        "type": "transfer",
        "amount": (3000, 8500),
        "channel": "online",
        "hours": list(range(9, 17)),
        "description": "Transfer to third-party account with no prior relationship",
        "reason": "Third-party payment: transfer to unrelated beneficiary",
    },
    {
        "type": "transfer",
        "amount": (4500, 9500),
        "channel": "mobile",
        "hours": list(range(8, 20)),
        "description": "Multiple payments to different third-party accounts",
        "reason": "Third-party funneling: payments to multiple unrelated accounts",
    },
    {
        "type": "transfer",
        "amount": (8000, 18000),
        "channel": "swift",
        "hours": list(range(9, 16)),
        "destination_country": "KY",
        "description": "Transfer to offshore corporate account with no business purpose",
        "reason": "Shell company: transfer to offshore entity with no legitimate business reason",
    },
    {
        "type": "transfer",
        "amount": (12000, 25000),
        "channel": "swift",
        "hours": list(range(9, 16)),
        "destination_country": "BZ",
        "description": "Large transfer to newly incorporated business entity",
        "reason": "Shell company: transfer to recently created corporate entity",
    },
    {
        "type": "transfer",
        "amount": (15000, 35000),
        "channel": "swift",
        "hours": list(range(9, 16)),
        "destination_country": "CN",
        "description": "Over-invoiced international trade payment",
        "reason": "Trade-based laundering: payment amount inconsistent with typical trade values",
    },
    {
        "type": "transfer",
        "amount": (5000, 12000),
        "channel": "online",
        "hours": list(range(9, 16)),
        "description": "Multiple small payments to same business entity",
        "reason": "Trade-based structuring: breaking large payments into smaller amounts",
    },
    {
        "type": "transfer",
        "amount": (3000, 8000),
        "channel": "online",
        "hours": [0, 1, 2, 3, 22, 23],
        "description": "Transfer to cryptocurrency exchange platform",
        "reason": "Crypto-related: transfer to digital asset exchange during off-hours",
    },
    {
        "type": "transfer",
        "amount": (7000, 15000),
        "channel": "online",
        "hours": list(range(9, 16)),
        "description": "Rapid transfers between crypto exchange accounts",
        "reason": "Crypto layering: rapid movement through digital asset platforms",
    },
]


# Highly suspicious transaction scenarios representing severe AML risks
SUPER_SUSPICIOUS_TRANSACTION_SCENARIOS = [
    {
        "type": "deposit",
        "amount": (10000, 28000),
        "channel": "branch",
        "hours": list(range(9, 16)),
        "description": "Large cash deposit requiring currency transaction review",
        "reason": "Cash transaction exceeds the CTR threshold and requires enhanced review",
    },
    {
        "type": "transfer",
        "amount": (12000, 52000),
        "channel": "swift",
        "hours": [0, 1, 2, 3, 23],
        "destination_country": "IR",
        "description": "High-value SWIFT transfer to high-risk jurisdiction",
        "reason": "High-value off-hours transfer to FATF grey-list jurisdiction",
    },
    {
        "type": "withdraw",
        "amount": (10000, 24000),
        "channel": "branch",
        "hours": list(range(9, 16)),
        "description": "Large over-the-counter cash withdrawal",
        "reason": "Large cash withdrawal meets threshold for immediate compliance review",
    },
    {
        "type": "deposit",
        "amount": (4500, 4900),
        "channel": "branch",
        "hours": list(range(9, 16)),
        "description": "Multiple cash deposits just below half CTR threshold",
        "reason": "Smurfing pattern: multiple deposits below $5000 to avoid reporting",
    },
    {
        "type": "deposit",
        "amount": (2500, 2900),
        "channel": "atm",
        "hours": list(range(9, 16)),
        "description": "Frequent small cash deposits via ATM",
        "reason": "Structuring through small ATM deposits to avoid detection",
    },
    {
        "type": "transfer",
        "amount": (8000, 15000),
        "channel": "online",
        "hours": list(range(9, 16)),
        "description": "Rapid sequential transfers to multiple accounts",
        "reason": "Layering: rapid movement of funds through multiple accounts",
    },
    {
        "type": "transfer",
        "amount": (3000, 7000),
        "channel": "mobile",
        "hours": list(range(9, 16)),
        "description": "Circular transfer pattern between related accounts",
        "reason": "Layering: circular transfers to obscure audit trail",
    },
    {
        "type": "transfer",
        "amount": (50000, 150000),
        "channel": "swift",
        "hours": list(range(9, 16)),
        "destination_country": "AE",
        "description": "Large transfer to real estate development company",
        "reason": "Real estate laundering: large payment to property development entity",
    },
    {
        "type": "transfer",
        "amount": (25000, 75000),
        "channel": "swift",
        "hours": list(range(9, 16)),
        "destination_country": "PA",
        "description": "Multiple transfers to property holding companies",
        "reason": "Real estate structuring: payments to multiple property holding entities",
    },
    {
        "type": "transfer",
        "amount": (15000, 40000),
        "channel": "online",
        "hours": [0, 1, 2, 3, 22, 23],
        "description": "Large transfer to online gambling platform",
        "reason": "Casino laundering: transfer to gambling platform during off-hours",
    },
    {
        "type": "transfer",
        "amount": (8000, 20000),
        "channel": "online",
        "hours": list(range(9, 16)),
        "description": "Rapid deposits and withdrawals from casino accounts",
        "reason": "Casino layering: rapid movement through gambling platforms",
    },
    {
        "type": "transfer",
        "amount": (20000, 50000),
        "channel": "swift",
        "hours": list(range(9, 16)),
        "destination_country": "RU",
        "description": "Transfer to entity linked to politically exposed person",
        "reason": "PEP-related: transfer to entity associated with foreign official",
    },
    {
        "type": "transfer",
        "amount": (30000, 80000),
        "channel": "swift",
        "hours": [0, 1, 2, 3, 23],
        "destination_country": "NG",
        "description": "Off-hours transfer to offshore trust structure",
        "reason": "Corruption: transfer to offshore trust structure during unusual hours",
    },
    {
        "type": "transfer",
        "amount": (5000, 15000),
        "channel": "mobile",
        "hours": [0, 1, 2, 3, 22, 23],
        "description": "Small rapid transfers to high-risk region accounts",
        "reason": "Terrorist financing: small rapid transfers to high-risk jurisdictions",
    },
    {
        "type": "transfer",
        "amount": (10000, 25000),
        "channel": "online",
        "hours": list(range(9, 16)),
        "description": "Transfer to charity organization in conflict zone",
        "reason": "Terrorist financing: transfer to charitable entity in high-risk region",
    },
]


def _scenario_amount(low, high, label):
    """Generate scenario-specific amount with realistic rounding."""
    amount = random.triangular(low, high, low + ((high - low) * 0.35))

    if label == "normal":
        return round(amount, 2)

    if low >= 9000:
        return round(amount / 50) * 50

    return round(amount / 10) * 10


def _simulation_segment_multiplier(segment, label):
    """Apply wealth segment multiplier to transaction amounts."""
    segment = (segment or "average").lower()

    multipliers = {
        "low": {"normal": 0.6, "suspicious": 0.75, "super_suspicious": 0.9},
        "average": {"normal": 1.0, "suspicious": 1.0, "super_suspicious": 1.0},
        "high": {"normal": 1.5, "suspicious": 1.1, "super_suspicious": 1.2},
        "ultra_high": {"normal": 2.0, "suspicious": 1.2, "super_suspicious": 1.3},
    }

    return multipliers.get(segment, multipliers["average"]).get(label, 1.0)


def _parse_timestamp(value):
    """Parse timestamp string to datetime object."""
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)


def _simulation_transaction(label, users):
    """Generate one transaction that reflects laundering typologies."""
    if label == "normal":
        scenario = random.choice(NORMAL_TRANSACTION_SCENARIOS)
    elif label == "suspicious":
        scenario = random.choice(SUSPICIOUS_TRANSACTION_SCENARIOS)
    else:
        scenario = random.choice(SUPER_SUSPICIOUS_TRANSACTION_SCENARIOS)

    tx_type = scenario["type"]
    sender = random.choice(users)
    hour = random.choice(scenario["hours"])
    dest_country = scenario.get("destination_country", "ZW")
    description = scenario["description"]
    scenario_reason = scenario.get("reason")

    base_dt = _parse_timestamp(_simulation_timestamp(hour))

    amount = round(
        _scenario_amount(*scenario["amount"], label)
        * _simulation_segment_multiplier(sender["wealth_segment"] or "average", label),
        2,
    )

    if tx_type in ("withdraw", "transfer") and sender["balance"] is not None:
        balance = float(sender["balance"] or 0)
        if balance > 0 and amount > balance * 0.85:
            amount = round(balance * random.uniform(0.35, 0.75), 2)
            amount = max(amount, 1.0)

    recipient = sender
    if tx_type == "transfer" and len(users) > 1:
        recipient = random.choice([user for user in users if user["id"] != sender["id"]])

    timestamp = _simulation_timestamp(hour)
    return [
        (
            sender, recipient, tx_type, amount, timestamp,
            scenario["channel"], description, scenario_reason, dest_country,
        )
    ]


def _simulation_reason(label, amount, tx_type, scenario_reason=None):
    """Generate simulation reason based on transaction label."""
    if label == "normal":
        return "Routine customer activity consistent with known banking behaviour"

    if label == "suspicious":
        return f"{scenario_reason or 'Suspicious transaction pattern'} involving a {tx_type} of ${amount:,.2f}"

    return f"{scenario_reason or 'High-risk AML pattern'} involving a {tx_type} of ${amount:,.2f}"


def _history_profile(amount, receiver_account, timestamp, history):
    """Build transaction history profile for AI model."""
    amounts = history.get("amounts", [])
    recipients = history.get("recipients", set())
    events = history.get("events", [])
    prior_transactions = history.get("transactions", [])

    amount = float(amount)
    avg_amount = sum(amounts) / len(amounts) if amounts else 0.0
    max_amount = max(amounts) if amounts else 0.0

    current_time = _parse_timestamp(timestamp)
    cutoff = current_time - timedelta(hours=24)
    recent_amounts = [
        float(event_amount)
        for event_time, event_amount in events
        if event_time >= cutoff
    ]
    volume_24h = sum(recent_amounts)

    same_day_count = 0
    same_day_total = 0.0
    same_recipient_count = 0
    rapid_transfer_count = 0

    for prior_tx in prior_transactions:
        try:
            prior_time = _parse_timestamp(prior_tx.get("timestamp"))
            if current_time.date() == prior_time.date():
                same_day_count += 1
                same_day_total += float(prior_tx.get("amount", 0) or 0)
            if prior_time >= cutoff and prior_tx.get("receiver_account") == receiver_account:
                same_recipient_count += 1
            if 0 < (current_time - prior_time).total_seconds() <= 600:
                rapid_transfer_count += 1
        except (TypeError, ValueError):
            continue

    profile = dict(PROFILE_FEATURE_DEFAULTS)
    profile.update({
        "sender_avg_amount": avg_amount,
        "sender_max_amount": max_amount,
        "sender_tx_count": len(amounts),
        "amount_to_sender_avg": amount / avg_amount if avg_amount > 0 else 1.0,
        "amount_to_sender_max": amount / max_amount if max_amount > 0 else 1.0,
        "sender_tx_count_24h": len(recent_amounts),
        "sender_volume_24h": volume_24h,
        "amount_to_sender_volume_24h": amount / volume_24h if volume_24h > 0 else 1.0,
        "is_new_recipient": 0.0 if receiver_account in recipients else 1.0,
        "same_day_count": same_day_count,
        "same_day_total": same_day_total,
        "same_recipient_count": same_recipient_count,
        "rapid_transfer_count": rapid_transfer_count,
    })

    return profile


def _ai_profile_for_transaction(conn, transaction_id, sender_account, receiver_account, amount, timestamp):
    """Build AI profile features for a transaction from database history."""
    cutoff = (_parse_timestamp(timestamp) - timedelta(hours=24)).isoformat()
    tx_date = _parse_timestamp(timestamp).date()

    prior = conn.execute(
        """
        SELECT
            COUNT(*) AS tx_count,
            COALESCE(AVG(amount), 0) AS avg_amount,
            COALESCE(MAX(amount), 0) AS max_amount,
            COALESCE(u.wealth_segment, 'average') AS wealth_segment
        FROM transactions t
        LEFT JOIN users u ON t.sender_account = u.account_number
        WHERE sender_account=? AND (? IS NULL OR t.id<>?) AND timestamp<?
        """,
        (sender_account, transaction_id, transaction_id, timestamp),
    ).fetchone()

    recent = conn.execute(
        """
        SELECT COUNT(*) AS tx_count, COALESCE(SUM(amount), 0) AS volume
        FROM transactions t
        WHERE sender_account=? AND (? IS NULL OR t.id<>?) AND timestamp>=? AND timestamp<?
        """,
        (sender_account, transaction_id, transaction_id, cutoff, timestamp),
    ).fetchone()

    recipient_seen = conn.execute(
        """
        SELECT id FROM transactions t
        WHERE sender_account=? AND receiver_account=? AND (? IS NULL OR t.id<>?) AND timestamp<?
        LIMIT 1
        """,
        (sender_account, receiver_account, transaction_id, transaction_id, timestamp),
    ).fetchone()

    # New structuring and layering features
    same_day_txs = conn.execute(
        """
        SELECT COUNT(*) AS count, COALESCE(SUM(amount), 0) AS total
        FROM transactions t
        WHERE sender_account=? AND (? IS NULL OR t.id<>?) AND DATE(timestamp)=DATE(?)
        """,
        (sender_account, transaction_id, transaction_id, timestamp),
    ).fetchone()

    same_recipient_24h = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM transactions t
        WHERE sender_account=? AND receiver_account=? AND (? IS NULL OR t.id<>?) AND timestamp>=? AND timestamp<?
        """,
        (sender_account, receiver_account, transaction_id, transaction_id, cutoff, timestamp),
    ).fetchone()

    rapid_transfers = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM transactions t
        WHERE sender_account=? AND (? IS NULL OR t.id<>?) AND timestamp>=? AND timestamp<?
        ORDER BY timestamp DESC
        """,
        (sender_account, transaction_id, transaction_id, cutoff, timestamp),
    ).fetchall()

    rapid_count = 0
    if len(rapid_transfers) > 1:
        for i in range(len(rapid_transfers) - 1):
            try:
                curr_time = _parse_timestamp(rapid_transfers[i]["timestamp"])
                prev_time = _parse_timestamp(rapid_transfers[i + 1]["timestamp"])
                if 0 < (curr_time - prev_time).total_seconds() <= 600:
                    rapid_count += 1
            except (TypeError, ValueError):
                continue

    profile = dict(PROFILE_FEATURE_DEFAULTS)
    profile.update({
        "sender_avg_amount": float(prior["avg_amount"] or 0),
        "sender_max_amount": float(prior["max_amount"] or 0),
        "sender_tx_count": prior["tx_count"] or 0,
        "amount_to_sender_avg": amount / float(prior["avg_amount"] or 1) if prior["avg_amount"] else 1.0,
        "amount_to_sender_max": amount / float(prior["max_amount"] or 1) if prior["max_amount"] else 1.0,
        "sender_tx_count_24h": recent["tx_count"] or 0,
        "sender_volume_24h": float(recent["volume"] or 0),
        "amount_to_sender_volume_24h": amount / float(recent["volume"] or 1) if recent["volume"] else 1.0,
        "is_new_recipient": 0.0 if recipient_seen else 1.0,
        "same_day_count": same_day_txs["count"] or 0,
        "same_day_total": float(same_day_txs["total"] or 0),
        "same_recipient_count": same_recipient_24h["count"] or 0,
        "rapid_transfer_count": rapid_count,
    })

    return profile
