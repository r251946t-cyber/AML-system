"""
screening.py — AML Name & Entity Screening Engine
====================================================
Industry-standard watchlist / PEP / sanctions screening aligned with:
  • FATF Recommendation 10 (CDD including PEPs)
  • Wolfsberg Group screening principles
  • OFAC / UN / EU sanctions list matching patterns

Supports exact ID/account matching and fuzzy name matching (Levenshtein ratio)
for typo-tolerant screening at onboarding and transaction time.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Any


FUZZY_NAME_THRESHOLD = 0.82
PARTIAL_NAME_THRESHOLD = 0.70

LIST_TYPE_SEVERITY = {
    "sanctions": ("critical", 55),
    "pep": ("warning", 35),
    "internal": ("warning", 40),
    "adverse_media": ("info", 20),
}


@dataclass
class ScreeningHit:
    source: str
    list_type: str
    matched_name: str
    match_type: str
    match_score: float
    reason: str
    severity: str
    score_delta: int
    evidence: dict[str, Any] = field(default_factory=dict)


def normalize_name(name: str) -> str:
    if not name:
        return ""
    cleaned = re.sub(r"[^A-Za-z0-9\s]", " ", name.upper())
    return " ".join(cleaned.split())


def fuzzy_name_score(query: str, candidate: str) -> float:
    q = normalize_name(query)
    c = normalize_name(candidate)
    if not q or not c:
        return 0.0
    if q == c:
        return 1.0
    ratio = difflib.SequenceMatcher(None, q, c).ratio()
    q_tokens = set(q.split())
    c_tokens = set(c.split())
    if q_tokens and c_tokens:
        token_overlap = len(q_tokens & c_tokens) / max(len(q_tokens), len(c_tokens))
        ratio = max(ratio, token_overlap * 0.95)
    return ratio


def _hit_from_watchlist(row, match_type: str, match_score: float) -> ScreeningHit:
    list_type = row.get("list_type") or "internal"
    severity, score_delta = LIST_TYPE_SEVERITY.get(list_type, ("warning", 30))
    return ScreeningHit(
        source="watchlist",
        list_type=list_type,
        matched_name=row.get("name") or "",
        match_type=match_type,
        match_score=match_score,
        reason=row.get("reason") or f"Watchlist match ({list_type})",
        severity=severity,
        score_delta=score_delta,
        evidence={
            "watchlist_id": row.get("id"),
            "id_number": row.get("id_number"),
            "account_number": row.get("account_number"),
        },
    )


def screen_entity(
    conn,
    *,
    name: str | None = None,
    id_number: str | None = None,
    account_number: str | None = None,
) -> list[ScreeningHit]:
    """Screen a party against internal watchlist and PEP flags."""
    hits: list[ScreeningHit] = []
    normalized_id = (id_number or "").strip().upper()
    normalized_acct = (account_number or "").strip().upper()
    normalized_name = normalize_name(name or "")

    watchlist_rows = conn.execute("SELECT * FROM watchlist").fetchall()
    for row in watchlist_rows:
        entry = dict(row)
        wl_id = (entry.get("id_number") or "").strip().upper()
        wl_acct = (entry.get("account_number") or "").strip().upper()
        wl_name = entry.get("name") or ""

        if normalized_id and wl_id and normalized_id == wl_id:
            hits.append(_hit_from_watchlist(entry, "exact_id", 1.0))
            continue
        if normalized_acct and wl_acct and normalized_acct == wl_acct:
            hits.append(_hit_from_watchlist(entry, "exact_account", 1.0))
            continue
        if normalized_name and wl_name:
            score = fuzzy_name_score(normalized_name, wl_name)
            if score >= FUZZY_NAME_THRESHOLD:
                hits.append(_hit_from_watchlist(entry, "fuzzy_name", score))
            elif score >= PARTIAL_NAME_THRESHOLD and len(normalized_name.split()) >= 2:
                hit = _hit_from_watchlist(entry, "partial_name", score)
                hit.score_delta = max(15, hit.score_delta - 10)
                hits.append(hit)

    if normalized_acct:
        user = conn.execute(
            "SELECT username, id_number, pep_flag, risk_rating FROM users WHERE account_number=?",
            (normalized_acct,),
        ).fetchone()
        if user:
            user_dict = dict(user)
            if user_dict.get("pep_flag"):
                hits.append(ScreeningHit(
                    source="pep_registry",
                    list_type="pep",
                    matched_name=user_dict.get("username") or normalized_acct,
                    match_type="pep_flag",
                    match_score=1.0,
                    reason="Account holder flagged as Politically Exposed Person (PEP)",
                    severity="warning",
                    score_delta=35,
                    evidence={"account_number": normalized_acct},
                ))
            if user_dict.get("risk_rating") == "high":
                hits.append(ScreeningHit(
                    source="customer_risk",
                    list_type="internal",
                    matched_name=user_dict.get("username") or normalized_acct,
                    match_type="high_risk_customer",
                    match_score=1.0,
                    reason="Account on enhanced due diligence (EDD) monitoring",
                    severity="warning",
                    score_delta=20,
                    evidence={"account_number": normalized_acct},
                ))

    hits.sort(key=lambda h: h.score_delta, reverse=True)
    return hits


def screening_summary(hits: list[ScreeningHit]) -> tuple[int, str, list[dict]]:
    """Return (score_delta, reason_text, serializable_hits)."""
    if not hits:
        return 0, "", []

    total_delta = min(sum(h.score_delta for h in hits), 80)
    top = hits[0]
    reasons = [f"[{h.list_type.upper()}] {h.reason} ({h.match_type}, {h.match_score:.0%})" for h in hits[:3]]
    reason = "Screening hit: " + "; ".join(reasons)
    serialized = [
        {
            "source": h.source,
            "list_type": h.list_type,
            "matched_name": h.matched_name,
            "match_type": h.match_type,
            "match_score": round(h.match_score, 3),
            "reason": h.reason,
            "severity": h.severity,
            "score_delta": h.score_delta,
        }
        for h in hits
    ]
    return total_delta, reason, serialized


def is_registration_blocked(hits: list[ScreeningHit]) -> bool:
    """Block onboarding for sanctions hits (regulatory requirement)."""
    return any(h.list_type == "sanctions" for h in hits)
