"""
aml_logic.py — ZB Bank AML Detection Engine
============================================
Industry-grade rule engine aligned with:
  • FATF Recommendations 10, 20, 23, 29
  • Basel AML Index typologies
  • ZIMRA / FIU-Zimbabwe reporting thresholds
  • FinCEN structuring / layering / integration detection

Rule architecture:
  Each rule returns (score_delta: int, triggered: bool, reason: str)
  Rules are composable and individually auditable.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Regulatory thresholds (USD-equivalent)
# Adjust per jurisdiction — currently set for ZW/USD dual-currency regime
# ---------------------------------------------------------------------------
CTR_THRESHOLD = 10_000          # Currency Transaction Report threshold
SAR_AUTO_THRESHOLD = 5_000      # Auto-flag for SAR review if suspicious
HIGH_VALUE_TRANSFER_THRESHOLD = 1_000
STRUCTURING_BAND_LOW = 8_500    # Watch-band for structuring below CTR
STRUCTURING_BAND_HIGH = 9_999
LARGE_CASH_THRESHOLD = 3_000    # Enhanced due diligence trigger
VELOCITY_WINDOW_MINUTES = 60    # Rolling window for velocity checks
VELOCITY_WINDOW_DAILY = 1_440   # 24-hour window
MAX_NORMAL_DAILY_VOLUME = 20_000
RAPID_FIRE_COUNT = 5            # Transactions within velocity window = rapid-fire flag
SMURFING_TX_COUNT = 3           # Min deposits to flag smurfing
SMURFING_AMOUNT_CEILING = 500   # Each deposit below this = smurfing candidate
FAN_OUT_RECIPIENT_COUNT = 3     # Unique recipients within window = fan-out
HIGH_RISK_COUNTRIES = {         # FATF grey/black list (illustrative subset)
    "IR", "KP", "MM", "RU", "SY", "YE", "ML", "BF", "SO",
}

@dataclass
class RuleResult:
    rule_id: str
    triggered: bool
    score_delta: int
    reason: str
    severity: str = "info"          # info | warning | critical
    typology: str = ""              # FATF typology tag
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    risk_score: int
    risk_level: str                 # normal | low | medium | suspicious | high_risk | critical
    primary_reason: str
    rules_triggered: list[RuleResult]
    sar_recommended: bool
    ctr_required: bool
    typologies: list[str]
    evidence_summary: dict[str, Any]


# ---------------------------------------------------------------------------
# Helper: fetch transaction history windows
# ---------------------------------------------------------------------------

def _fetch_window(conn, account: str, minutes: int) -> list[dict]:
    """Return recent transactions for *account* within *minutes* back."""
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    rows = conn.execute(
        """
        SELECT id, amount, transaction_type, sender_account, receiver_account,
               timestamp, risk_level
        FROM transactions
        WHERE (sender_account = ? OR receiver_account = ?)
          AND timestamp >= ?
        ORDER BY timestamp DESC
        LIMIT 100
        """,
        (account, account, cutoff),
    ).fetchall()
    return [dict(r) for r in rows]


def _fetch_peer_transfers(conn, account: str, minutes: int) -> list[dict]:
    """Transfers *sent* by account within window."""
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    rows = conn.execute(
        """
        SELECT id, amount, receiver_account, timestamp
        FROM transactions
        WHERE sender_account = ?
          AND transaction_type = 'transfer'
          AND timestamp >= ?
        ORDER BY timestamp DESC
        LIMIT 100
        """,
        (account, cutoff),
    ).fetchall()
    return [dict(r) for r in rows]


def _daily_totals(conn, account: str) -> dict[str, float]:
    """Return total sent/received in last 24 h."""
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=VELOCITY_WINDOW_DAILY)).isoformat()
    sent = conn.execute(
        "SELECT COALESCE(SUM(amount),0) as t FROM transactions WHERE sender_account=? AND timestamp>=?",
        (account, cutoff),
    ).fetchone()
    received = conn.execute(
        "SELECT COALESCE(SUM(amount),0) as t FROM transactions WHERE receiver_account=? AND timestamp>=?",
        (account, cutoff),
    ).fetchone()
    return {
        "sent": float(sent["t"] if sent else 0),
        "received": float(received["t"] if received else 0),
    }


def _prior_alerts(conn, account: str, days: int = 30) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    row = conn.execute(
        "SELECT COUNT(*) as c FROM alerts WHERE account_number=? AND timestamp>=?",
        (account, cutoff),
    ).fetchone()
    return int(row["c"]) if row else 0


# ---------------------------------------------------------------------------
# Individual AML rules
# ---------------------------------------------------------------------------

def rule_large_cash(amount: float, tx_type: str) -> RuleResult:
    """R01 — Large cash / CTR threshold (FATF Rec. 10)."""
    if tx_type in ("deposit", "withdraw") and amount >= CTR_THRESHOLD:
        return RuleResult(
            rule_id="R01",
            triggered=True,
            score_delta=45,
            reason=f"Cash transaction of ${amount:,.2f} meets or exceeds CTR threshold (${CTR_THRESHOLD:,})",
            severity="critical",
            typology="Large Cash",
            evidence={"amount": amount, "threshold": CTR_THRESHOLD},
        )
    if tx_type in ("deposit", "withdraw") and amount >= LARGE_CASH_THRESHOLD:
        return RuleResult(
            rule_id="R01",
            triggered=True,
            score_delta=20,
            reason=f"Large cash transaction of ${amount:,.2f} — enhanced due diligence required",
            severity="warning",
            typology="Large Cash",
            evidence={"amount": amount},
        )
    return RuleResult(rule_id="R01", triggered=False, score_delta=0, reason="")


def rule_structuring(amount: float, tx_type: str, conn, sender: str) -> RuleResult:
    """R02 — Structuring / smurfing below CTR (FATF Rec. 10, FinCEN)."""
    if tx_type not in ("deposit", "withdraw", "transfer"):
        return RuleResult(rule_id="R02", triggered=False, score_delta=0, reason="")

    # Single transaction just below CTR threshold
    if STRUCTURING_BAND_LOW <= amount <= STRUCTURING_BAND_HIGH:
        return RuleResult(
            rule_id="R02",
            triggered=True,
            score_delta=50,
            reason=f"Transaction of ${amount:,.2f} falls within structuring watch-band (${STRUCTURING_BAND_LOW:,}–${STRUCTURING_BAND_HIGH:,})",
            severity="critical",
            typology="Structuring",
            evidence={"amount": amount},
        )

    # Multiple small deposits (smurfing)
    if tx_type == "deposit" and amount < SMURFING_AMOUNT_CEILING:
        window = _fetch_window(conn, sender, VELOCITY_WINDOW_MINUTES)
        small_deposits = [t for t in window if t["transaction_type"] == "deposit"
                          and float(t["amount"]) < SMURFING_AMOUNT_CEILING]
        if len(small_deposits) >= SMURFING_TX_COUNT:
            total = sum(float(t["amount"]) for t in small_deposits)
            return RuleResult(
                rule_id="R02",
                triggered=True,
                score_delta=40,
                reason=f"{len(small_deposits)} small deposits totalling ${total:,.2f} within {VELOCITY_WINDOW_MINUTES} min — smurfing pattern",
                severity="critical",
                typology="Smurfing",
                evidence={"count": len(small_deposits), "total": total},
            )
    return RuleResult(rule_id="R02", triggered=False, score_delta=0, reason="")


def rule_velocity(conn, account: str, amount: float, tx_type: str) -> RuleResult:
    """R03 — Rapid transaction velocity (layering indicator)."""
    window = _fetch_window(conn, account, VELOCITY_WINDOW_MINUTES)
    if len(window) >= RAPID_FIRE_COUNT:
        volume = sum(float(t["amount"]) for t in window)
        return RuleResult(
            rule_id="R03",
            triggered=True,
            score_delta=35,
            reason=f"{len(window)} transactions (${volume:,.2f}) within {VELOCITY_WINDOW_MINUTES} min — high-velocity layering pattern",
            severity="critical",
            typology="Layering / Velocity",
            evidence={"tx_count": len(window), "volume": volume, "window_minutes": VELOCITY_WINDOW_MINUTES},
        )
    return RuleResult(rule_id="R03", triggered=False, score_delta=0, reason="")


def rule_daily_volume(conn, account: str, amount: float) -> RuleResult:
    """R04 — Daily volume exceeds normal behaviour threshold."""
    totals = _daily_totals(conn, account)
    projected_sent = totals["sent"] + amount
    if projected_sent > MAX_NORMAL_DAILY_VOLUME:
        return RuleResult(
            rule_id="R04",
            triggered=True,
            score_delta=30,
            reason=f"Daily outflow of ${projected_sent:,.2f} exceeds normal threshold (${MAX_NORMAL_DAILY_VOLUME:,})",
            severity="warning",
            typology="Unusual Volume",
            evidence={"daily_sent": totals["sent"], "this_tx": amount, "limit": MAX_NORMAL_DAILY_VOLUME},
        )
    return RuleResult(rule_id="R04", triggered=False, score_delta=0, reason="")


def rule_fan_out(conn, sender: str, receiver: str, tx_type: str) -> RuleResult:
    """R05 — Fan-out: transfers to many unique recipients (layering)."""
    if tx_type != "transfer":
        return RuleResult(rule_id="R05", triggered=False, score_delta=0, reason="")
    recent = _fetch_peer_transfers(conn, sender, VELOCITY_WINDOW_MINUTES)
    recipients = {t["receiver_account"] for t in recent} | {receiver}
    if len(recipients) >= FAN_OUT_RECIPIENT_COUNT:
        return RuleResult(
            rule_id="R05",
            triggered=True,
            score_delta=35,
            reason=f"Funds transferred to {len(recipients)} distinct accounts within {VELOCITY_WINDOW_MINUTES} min — fan-out / layering",
            severity="critical",
            typology="Fan-Out / Layering",
            evidence={"unique_recipients": len(recipients)},
        )
    return RuleResult(rule_id="R05", triggered=False, score_delta=0, reason="")


def rule_round_amount(amount: float, tx_type: str) -> RuleResult:
    """R06 — Round-number transactions (common money-laundering indicator)."""
    if tx_type == "transfer" and amount >= 1000 and amount % 1000 == 0:
        return RuleResult(
            rule_id="R06",
            triggered=True,
            score_delta=15,
            reason=f"Round-number transfer of ${amount:,.0f} — common structuring indicator",
            severity="info",
            typology="Round Amount",
            evidence={"amount": amount},
        )
    return RuleResult(rule_id="R06", triggered=False, score_delta=0, reason="")


def rule_self_transfer(sender: str, receiver: str) -> RuleResult:
    """R07 — Self-transfer (identity layering / integration)."""
    if sender == receiver:
        return RuleResult(
            rule_id="R07",
            triggered=True,
            score_delta=20,
            reason="Self-transfer detected — account used as pass-through",
            severity="warning",
            typology="Self-Transfer",
            evidence={},
        )
    return RuleResult(rule_id="R07", triggered=False, score_delta=0, reason="")


def rule_repeat_offender(conn, account: str) -> RuleResult:
    """R08 — Account with recent alert history (elevated risk profile)."""
    count = _prior_alerts(conn, account, days=30)
    if count >= 5:
        return RuleResult(
            rule_id="R08",
            triggered=True,
            score_delta=25,
            reason=f"Account has {count} alerts in past 30 days — elevated risk profile",
            severity="critical",
            typology="Repeat Offender",
            evidence={"alert_count_30d": count},
        )
    if count >= 2:
        return RuleResult(
            rule_id="R08",
            triggered=True,
            score_delta=12,
            reason=f"Account has {count} prior alerts in past 30 days",
            severity="warning",
            typology="Repeat Offender",
            evidence={"alert_count_30d": count},
        )
    return RuleResult(rule_id="R08", triggered=False, score_delta=0, reason="")


def rule_sar_threshold(amount: float, tx_type: str) -> RuleResult:
    """R09 — SAR reporting threshold (FATF Rec. 20)."""
    if tx_type == "transfer" and amount >= SAR_AUTO_THRESHOLD:
        return RuleResult(
            rule_id="R09",
            triggered=True,
            score_delta=30,
            reason=f"Transfer of ${amount:,.2f} meets SAR auto-review threshold (${SAR_AUTO_THRESHOLD:,})",
            severity="critical",
            typology="SAR Trigger",
            evidence={"amount": amount, "sar_threshold": SAR_AUTO_THRESHOLD},
        )
    if tx_type == "transfer" and amount >= HIGH_VALUE_TRANSFER_THRESHOLD:
        return RuleResult(
            rule_id="R12",
            triggered=True,
            score_delta=40,
            reason=f"High-value transfer of ${amount:,.2f} meets monitoring threshold (${HIGH_VALUE_TRANSFER_THRESHOLD:,})",
            severity="warning",
            typology="High-Value Transfer",
            evidence={"amount": amount, "threshold": HIGH_VALUE_TRANSFER_THRESHOLD},
        )
    return RuleResult(rule_id="R09", triggered=False, score_delta=0, reason="")


def rule_night_transaction(timestamp_str: str, amount: float) -> RuleResult:
    """R10 — Off-hours high-value transaction (unusual behaviour)."""
    try:
        ts = datetime.fromisoformat(timestamp_str)
        hour = ts.hour
        if amount >= 1000 and (hour >= 23 or hour < 5):
            return RuleResult(
                rule_id="R10",
                triggered=True,
                score_delta=20,
                reason=f"High-value transaction of ${amount:,.2f} at {hour:02d}:00 (off-hours activity)",
                severity="warning",
                typology="Off-Hours Activity",
                evidence={"hour": hour, "amount": amount},
            )
    except (ValueError, TypeError):
        pass
    return RuleResult(rule_id="R10", triggered=False, score_delta=0, reason="")


def rule_high_risk_jurisdiction(destination_country: str, amount: float, tx_type: str) -> RuleResult:
    """R13 — Cross-border transfer to FATF high-risk jurisdiction."""
    country = (destination_country or "ZW").upper().strip()
    if tx_type == "transfer" and country in HIGH_RISK_COUNTRIES and amount >= 500:
        return RuleResult(
            rule_id="R13",
            triggered=True,
            score_delta=45,
            reason=f"Cross-border transfer of ${amount:,.2f} to high-risk jurisdiction ({country})",
            severity="critical",
            typology="High-Risk Jurisdiction",
            evidence={"destination_country": country, "amount": amount},
        )
    if tx_type == "transfer" and country not in ("ZW", "US", "GB", "ZA", "") and amount >= 2000:
        return RuleResult(
            rule_id="R13",
            triggered=True,
            score_delta=20,
            reason=f"International transfer of ${amount:,.2f} to {country} — enhanced monitoring",
            severity="warning",
            typology="Cross-Border Transfer",
            evidence={"destination_country": country, "amount": amount},
        )
    return RuleResult(rule_id="R13", triggered=False, score_delta=0, reason="")


def rule_rapid_balance_drain(conn, account: str, amount: float, tx_type: str) -> RuleResult:
    """R11 — Account balance draining rapidly (exit scam / fraud indicator)."""
    if tx_type not in ("withdraw", "transfer"):
        return RuleResult(rule_id="R11", triggered=False, score_delta=0, reason="")
    totals = _daily_totals(conn, account)
    user = conn.execute(
        "SELECT balance FROM users WHERE account_number=?", (account,)
    ).fetchone()
    if user and float(user["balance"]) > 0:
        drain_pct = (totals["sent"] + amount) / float(user["balance"]) * 100
        if drain_pct >= 80:
            return RuleResult(
                rule_id="R11",
                triggered=True,
                score_delta=30,
                reason=f"Account is being drained: {drain_pct:.0f}% of balance sent today",
                severity="critical",
                typology="Account Draining",
                evidence={"drain_pct": round(drain_pct, 1), "balance": float(user["balance"])},
            )
    return RuleResult(rule_id="R11", triggered=False, score_delta=0, reason="")


# ---------------------------------------------------------------------------
# Master scoring function
# ---------------------------------------------------------------------------

def analyze_transaction(
    conn,
    tx_type: str,
    amount: float,
    sender: str,
    receiver: str,
    timestamp: str,
    destination_country: str = "ZW",
) -> tuple[int, str, str]:
    """
    Evaluate all AML rules and return (risk_score, risk_level, primary_reason).

    risk_level values (FATF-aligned):
        normal      — score 0–24
        low         — score 25–39
        suspicious  — score 40–59
        high_risk   — score 60–79
        critical    — score 80–100
    """
    rules: list[RuleResult] = [
        rule_large_cash(amount, tx_type),
        rule_structuring(amount, tx_type, conn, sender),
        rule_velocity(conn, sender, amount, tx_type),
        rule_daily_volume(conn, sender, amount),
        rule_fan_out(conn, sender, receiver, tx_type),
        rule_round_amount(amount, tx_type),
        rule_self_transfer(sender, receiver),
        rule_repeat_offender(conn, sender),
        rule_sar_threshold(amount, tx_type),
        rule_night_transaction(timestamp, amount),
        rule_rapid_balance_drain(conn, sender, amount, tx_type),
        rule_high_risk_jurisdiction(destination_country, amount, tx_type),
    ]

    # Base score: small amount for any outbound
    base = 5 if tx_type in ("transfer", "withdraw") else 2
    triggered = [r for r in rules if r.triggered]
    total = base + sum(r.score_delta for r in triggered)
    risk_score = min(int(total), 100)

    # Determine level
    if risk_score >= 80:
        risk_level = "critical"
    elif risk_score >= 60:
        risk_level = "high_risk"
    elif risk_score >= 40:
        risk_level = "suspicious"
    elif risk_score >= 25:
        risk_level = "low"
    else:
        risk_level = "normal"

    # Primary reason: highest-severity triggered rule
    severity_order = {"critical": 3, "warning": 2, "info": 1}
    if triggered:
        top_rule = max(triggered, key=lambda r: (severity_order.get(r.severity, 0), r.score_delta))
        primary_reason = top_rule.reason
    else:
        primary_reason = "Routine transaction — no anomalies detected"

    # SAR / CTR flags (stored as metadata — surface to caller via risk_level prefix)
    needs_sar = risk_score >= 60 or any(r.rule_id == "R09" for r in triggered)
    needs_ctr = any(r.rule_id == "R01" and amount >= CTR_THRESHOLD for r in triggered)

    # Encode SAR/CTR into reason for backward compat with existing alert table
    flags = []
    if needs_ctr:
        flags.append("[CTR REQUIRED]")
    if needs_sar:
        flags.append("[SAR REVIEW]")
    if flags:
        primary_reason = " ".join(flags) + " " + primary_reason

    return risk_score, risk_level, primary_reason


def get_triggered_rules(
    conn,
    tx_type: str,
    amount: float,
    sender: str,
    receiver: str,
    timestamp: str,
    destination_country: str = "ZW",
) -> list[RuleResult]:
    """Return full rule results for detailed audit logging."""
    rules = [
        rule_large_cash(amount, tx_type),
        rule_structuring(amount, tx_type, conn, sender),
        rule_velocity(conn, sender, amount, tx_type),
        rule_daily_volume(conn, sender, amount),
        rule_fan_out(conn, sender, receiver, tx_type),
        rule_round_amount(amount, tx_type),
        rule_self_transfer(sender, receiver),
        rule_repeat_offender(conn, sender),
        rule_sar_threshold(amount, tx_type),
        rule_night_transaction(timestamp, amount),
        rule_rapid_balance_drain(conn, sender, amount, tx_type),
        rule_high_risk_jurisdiction(destination_country, amount, tx_type),
    ]
    return [r for r in rules if r.triggered]
