"""
behavioral_profiler.py — Customer-Specific Behavioral Learning for AML
========================================================================
This module implements customer-specific behavioral profiling for AML detection.
Instead of using fixed rules, it learns each customer's normal transaction patterns
and flags anomalies based on deviations from their individual behavioral baseline.

Key Features:
- Individual customer behavioral profiles
- Continuous learning from transaction history
- Anomaly detection based on behavioral deviation
- Adaptive learning for legitimate behavior changes
- Individualized risk assessment
"""

from __future__ import annotations

import json
import math
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
import statistics


@dataclass
class CustomerBehavioralProfile:
    """Comprehensive behavioral profile for a single customer."""
    account_number: str
    last_updated: str
    total_transactions: int
    
    # Amount patterns
    avg_amount: float
    median_amount: float
    std_amount: float
    min_amount: float
    max_amount: float
    amount_percentiles: Dict[str, float]  # 25th, 50th, 75th, 90th, 95th
    
    # Frequency patterns
    avg_daily_tx_count: float
    avg_weekly_tx_count: float
    avg_monthly_tx_count: float
    peak_hours: List[int]  # Hours when customer is most active
    peak_days: List[int]  # Days of week when customer is most active (0=Monday)
    
    # Channel preferences
    channel_distribution: Dict[str, float]  # Percentage per channel
    preferred_channels: List[str]
    
    # Transaction type preferences
    type_distribution: Dict[str, float]  # Percentage per type
    preferred_types: List[str]
    
    # Recipient patterns (for transfers)
    common_recipients: List[Tuple[str, float]]  # (account_number, frequency)
    recipient_diversity: float  # Number of unique recipients / total transfers
    
    # Geographic patterns
    common_countries: List[Tuple[str, float]]  # (country_code, frequency)
    international_ratio: float  # Percentage of international transfers
    
    # Temporal patterns
    time_between_tx_avg: float  # Average time between transactions (seconds)
    time_between_tx_std: float
    burst_detection: Dict[str, Any]  # Rapid transaction pattern data
    
    # Balance patterns
    avg_balance: float
    balance_volatility: float
    income_cycle_detected: bool
    income_cycle_period: Optional[int]  # Days in income cycle (e.g., 30 for monthly)
    
    # Seasonal patterns
    monthly_spending_pattern: List[float]  # 12 values, one per month
    seasonal_variance: float
    
    # Recent trends (last 30 days vs historical)
    recent_amount_trend: str  # "increasing", "decreasing", "stable"
    recent_frequency_trend: str
    recent_channel_shifts: List[str]
    
    # Risk indicators based on behavioral patterns
    behavioral_risk_score: float  # 0-100 based on pattern anomalies
    risk_factors: List[str]


@dataclass
class TransactionAnomaly:
    """Result of anomaly detection for a single transaction."""
    transaction_id: int
    account_number: str
    overall_anomaly_score: float  # 0-100
    risk_level: str  # normal, low, medium, high, critical
    
    # Specific anomaly dimensions
    amount_anomaly: float  # 0-100
    frequency_anomaly: float  # 0-100
    timing_anomaly: float  # 0-100
    channel_anomaly: float  # 0-100
    recipient_anomaly: float  # 0-100
    geographic_anomaly: float  # 0-100
    pattern_anomaly: float  # 0-100
    
    # Explanations
    anomaly_reasons: List[str]
    behavioral_context: str
    
    # Confidence
    confidence: float  # 0-1
    profile_confidence: float  # How much data the profile is based on


class BehavioralProfiler:
    """Main class for building and using customer behavioral profiles."""
    
    def __init__(self, min_transactions_for_profile: int = 10):
        self.min_transactions_for_profile = min_transactions_for_profile
        self.profiles: Dict[str, CustomerBehavioralProfile] = {}
    
    def extract_profile_from_history(
        self, 
        account_number: str, 
        transactions: List[Dict[str, Any]],
        balance_history: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[CustomerBehavioralProfile]:
        """
        Extract a comprehensive behavioral profile from transaction history.
        
        Args:
            account_number: Customer account number
            transactions: List of transaction dictionaries
            balance_history: Optional list of balance snapshots over time
            
        Returns:
            CustomerBehavioralProfile or None if insufficient data
        """
        if len(transactions) < self.min_transactions_for_profile:
            return None
        
        # Sort by timestamp
        sorted_tx = sorted(transactions, key=lambda x: x.get('timestamp', ''))
        
        # Extract amounts
        amounts = [float(tx.get('amount', 0)) for tx in sorted_tx]
        
        # Extract timestamps
        timestamps = []
        for tx in sorted_tx:
            try:
                timestamps.append(datetime.fromisoformat(tx.get('timestamp', '')))
            except (ValueError, TypeError):
                timestamps.append(datetime.now(timezone.utc))
        
        # Extract transaction types
        tx_types = [tx.get('transaction_type', 'unknown') for tx in sorted_tx]
        
        # Extract channels
        channels = [tx.get('channel', 'online') for tx in sorted_tx]
        
        # Extract recipients (for transfers)
        recipients = [tx.get('receiver_account', '') for tx in sorted_tx 
                     if tx.get('transaction_type') == 'transfer']
        
        # Extract countries
        countries = [tx.get('destination_country', 'ZW') for tx in sorted_tx]
        
        # Calculate amount statistics
        avg_amount = statistics.mean(amounts) if amounts else 0
        median_amount = statistics.median(amounts) if amounts else 0
        std_amount = statistics.stdev(amounts) if len(amounts) > 1 else 0
        min_amount = min(amounts) if amounts else 0
        max_amount = max(amounts) if amounts else 0
        
        # Calculate percentiles
        sorted_amounts = sorted(amounts)
        percentiles = {}
        for p in [25, 50, 75, 90, 95]:
            idx = int(len(sorted_amounts) * p / 100)
            percentiles[str(p)] = sorted_amounts[idx] if sorted_amounts else 0
        
        # Calculate frequency patterns
        now = datetime.now(timezone.utc)
        one_day_ago = now - timedelta(days=1)
        one_week_ago = now - timedelta(days=7)
        one_month_ago = now - timedelta(days=30)
        
        daily_count = sum(1 for ts in timestamps if ts >= one_day_ago)
        weekly_count = sum(1 for ts in timestamps if ts >= one_week_ago)
        monthly_count = sum(1 for ts in timestamps if ts >= one_month_ago)
        
        avg_daily_tx_count = daily_count if len(timestamps) >= 30 else len(timestamps) / 30
        avg_weekly_tx_count = weekly_count if len(timestamps) >= 90 else len(timestamps) / 90 * 7
        avg_monthly_tx_count = monthly_count if len(timestamps) >= 365 else len(timestamps) / 365 * 30
        
        # Peak activity hours and days
        hours = [ts.hour for ts in timestamps]
        hour_counter = Counter(hours)
        peak_hours = [h for h, _ in hour_counter.most_common(3)]
        
        days = [ts.weekday() for ts in timestamps]
        day_counter = Counter(days)
        peak_days = [d for d, _ in day_counter.most_common(3)]
        
        # Channel distribution
        channel_counter = Counter(channels)
        total_channels = len(channels)
        channel_distribution = {ch: count/total_channels for ch, count in channel_counter.items()}
        preferred_channels = [ch for ch, _ in channel_counter.most_common(3)]
        
        # Transaction type distribution
        type_counter = Counter(tx_types)
        total_types = len(tx_types)
        type_distribution = {t: count/total_types for t, count in type_counter.items()}
        preferred_types = [t for t, _ in type_counter.most_common(3)]
        
        # Recipient patterns
        recipient_counter = Counter(recipients)
        total_recipients = len(recipients) if recipients else 1
        common_recipients = [(rec, count/total_recipients) for rec, count in recipient_counter.most_common(10)]
        recipient_diversity = len(recipient_counter) / total_recipients if recipients else 0
        
        # Geographic patterns
        country_counter = Counter(countries)
        total_countries = len(countries)
        common_countries = [(c, count/total_countries) for c, count in country_counter.most_common(10)]
        international_count = sum(1 for c in countries if c not in ['ZW', 'US', 'GB', ''])
        international_ratio = international_count / total_countries if total_countries > 0 else 0
        
        # Temporal patterns
        time_diffs = []
        for i in range(1, len(timestamps)):
            diff = (timestamps[i] - timestamps[i-1]).total_seconds()
            time_diffs.append(diff)
        
        time_between_tx_avg = statistics.mean(time_diffs) if time_diffs else 0
        time_between_tx_std = statistics.stdev(time_diffs) if len(time_diffs) > 1 else 0
        
        # Burst detection (rapid transactions)
        bursts = self._detect_bursts(timestamps, amounts)
        
        # Balance patterns
        avg_balance = 0
        balance_volatility = 0
        income_cycle_detected = False
        income_cycle_period = None
        
        if balance_history:
            balances = [float(b.get('balance', 0)) for b in balance_history]
            avg_balance = statistics.mean(balances) if balances else 0
            balance_volatility = statistics.stdev(balances) if len(balances) > 1 else 0
            income_cycle_detected, income_cycle_period = self._detect_income_cycle(balances)
        
        # Seasonal patterns
        monthly_spending = [0.0] * 12
        for tx in sorted_tx:
            try:
                ts = datetime.fromisoformat(tx.get('timestamp', ''))
                month = ts.month - 1  # 0-indexed
                monthly_spending[month] += float(tx.get('amount', 0))
            except (ValueError, TypeError):
                continue
        
        monthly_spending_pattern = monthly_spending
        seasonal_variance = statistics.stdev(monthly_spending) if monthly_spending else 0
        
        # Recent trends
        recent_amount_trend = self._calculate_trend(amounts[-10:] if len(amounts) >= 10 else amounts)
        recent_frequency_trend = self._calculate_frequency_trend(timestamps)
        recent_channel_shifts = self._detect_channel_shifts(channels)
        
        # Build profile
        profile = CustomerBehavioralProfile(
            account_number=account_number,
            last_updated=datetime.now(timezone.utc).isoformat(),
            total_transactions=len(transactions),
            avg_amount=avg_amount,
            median_amount=median_amount,
            std_amount=std_amount,
            min_amount=min_amount,
            max_amount=max_amount,
            amount_percentiles=percentiles,
            avg_daily_tx_count=avg_daily_tx_count,
            avg_weekly_tx_count=avg_weekly_tx_count,
            avg_monthly_tx_count=avg_monthly_tx_count,
            peak_hours=peak_hours,
            peak_days=peak_days,
            channel_distribution=channel_distribution,
            preferred_channels=preferred_channels,
            type_distribution=type_distribution,
            preferred_types=preferred_types,
            common_recipients=common_recipients,
            recipient_diversity=recipient_diversity,
            common_countries=common_countries,
            international_ratio=international_ratio,
            time_between_tx_avg=time_between_tx_avg,
            time_between_tx_std=time_between_tx_std,
            burst_detection=bursts,
            avg_balance=avg_balance,
            balance_volatility=balance_volatility,
            income_cycle_detected=income_cycle_detected,
            income_cycle_period=income_cycle_period,
            monthly_spending_pattern=monthly_spending_pattern,
            seasonal_variance=seasonal_variance,
            recent_amount_trend=recent_amount_trend,
            recent_frequency_trend=recent_frequency_trend,
            recent_channel_shifts=recent_channel_shifts,
            behavioral_risk_score=0,
            risk_factors=[]
        )
        
        return profile
    
    def _detect_bursts(self, timestamps: List[datetime], amounts: List[float]) -> Dict[str, Any]:
        """Detect rapid transaction bursts (potential layering)."""
        if len(timestamps) < 3:
            return {"has_bursts": False, "burst_count": 0}
        
        bursts = []
        current_burst_start = 0
        
        for i in range(1, len(timestamps)):
            time_diff = (timestamps[i] - timestamps[i-1]).total_seconds()
            if time_diff <= 300:  # 5 minutes
                if i - current_burst_start >= 2:  # At least 3 transactions
                    burst_amounts = amounts[current_burst_start:i+1]
                    bursts.append({
                        "start_index": current_burst_start,
                        "end_index": i,
                        "count": i - current_burst_start + 1,
                        "total_amount": sum(burst_amounts),
                        "avg_amount": statistics.mean(burst_amounts)
                    })
            else:
                current_burst_start = i
        
        return {
            "has_bursts": len(bursts) > 0,
            "burst_count": len(bursts),
            "bursts": bursts[:5]  # Keep only top 5 bursts
        }
    
    def _detect_income_cycle(self, balances: List[float]) -> Tuple[bool, Optional[int]]:
        """Detect regular income cycles (e.g., monthly salary)."""
        if len(balances) < 6:
            return False, None
        
        # Look for regular increases in balance
        increases = []
        for i in range(1, len(balances)):
            if balances[i] > balances[i-1] * 1.1:  # 10% increase
                increases.append(i)
        
        if len(increases) < 2:
            return False, None
        
        # Calculate intervals between increases
        intervals = [increases[i] - increases[i-1] for i in range(1, len(increases))]
        
        if not intervals:
            return False, None
        
        avg_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        # If intervals are consistent (low std deviation), we have a cycle
        if std_interval < avg_interval * 0.3:  # Less than 30% variation
            return True, int(avg_interval)
        
        return False, None
    
    def _calculate_trend(self, recent_amounts: List[float]) -> str:
        """Calculate if recent amounts are trending up, down, or stable."""
        if len(recent_amounts) < 3:
            return "stable"
        
        first_half = recent_amounts[:len(recent_amounts)//2]
        second_half = recent_amounts[len(recent_amounts)//2:]
        
        avg_first = statistics.mean(first_half)
        avg_second = statistics.mean(second_half)
        
        if avg_second > avg_first * 1.2:
            return "increasing"
        elif avg_second < avg_first * 0.8:
            return "decreasing"
        return "stable"
    
    def _calculate_frequency_trend(self, timestamps: List[datetime]) -> str:
        """Calculate if transaction frequency is trending up, down, or stable."""
        if len(timestamps) < 10:
            return "stable"
        
        mid_point = len(timestamps) // 2
        first_half = timestamps[:mid_point]
        second_half = timestamps[mid_point:]
        
        # Calculate average time between transactions
        def avg_time_diff(ts_list):
            if len(ts_list) < 2:
                return 0
            diffs = [(ts_list[i] - ts_list[i-1]).total_seconds() for i in range(1, len(ts_list))]
            return statistics.mean(diffs)
        
        avg_first = avg_time_diff(first_half)
        avg_second = avg_time_diff(second_half)
        
        if avg_second < avg_first * 0.7:  # Faster transactions
            return "increasing"
        elif avg_second > avg_first * 1.3:  # Slower transactions
            return "decreasing"
        return "stable"
    
    def _detect_channel_shifts(self, channels: List[str]) -> List[str]:
        """Detect recent shifts in channel usage."""
        if len(channels) < 10:
            return []
        
        recent_channels = channels[-5:]
        historical_channels = channels[:-5]
        
        recent_counter = Counter(recent_channels)
        historical_counter = Counter(historical_channels)
        
        shifts = []
        for channel in set(channels):
            recent_freq = recent_counter.get(channel, 0) / len(recent_channels)
            historical_freq = historical_counter.get(channel, 0) / len(historical_channels)
            
            if recent_freq > historical_freq * 2 and recent_freq > 0.3:
                shifts.append(f"increased_{channel}")
            elif recent_freq < historical_freq * 0.5 and historical_freq > 0.3:
                shifts.append(f"decreased_{channel}")
        
        return shifts
    
    def detect_anomaly(
        self,
        profile: CustomerBehavioralProfile,
        transaction: Dict[str, Any]
    ) -> TransactionAnomaly:
        """
        Detect if a transaction is anomalous based on customer's behavioral profile.
        
        Args:
            profile: Customer's behavioral profile
            transaction: Transaction to analyze
            
        Returns:
            TransactionAnomaly with detailed anomaly information
        """
        amount = float(transaction.get('amount', 0))
        tx_type = transaction.get('transaction_type', 'unknown')
        channel = transaction.get('channel', 'online')
        recipient = transaction.get('receiver_account', '')
        country = transaction.get('destination_country', 'ZW')
        
        try:
            timestamp = datetime.fromisoformat(transaction.get('timestamp', ''))
        except (ValueError, TypeError):
            timestamp = datetime.now(timezone.utc)
        
        # Calculate anomaly scores for each dimension
        amount_anomaly = self._score_amount_anomaly(profile, amount)
        frequency_anomaly = self._score_frequency_anomaly(profile, timestamp)
        timing_anomaly = self._score_timing_anomaly(profile, timestamp)
        channel_anomaly = self._score_channel_anomaly(profile, channel)
        recipient_anomaly = self._score_recipient_anomaly(profile, recipient)
        geographic_anomaly = self._score_geographic_anomaly(profile, country)
        pattern_anomaly = self._score_pattern_anomaly(profile, transaction)
        
        # Calculate overall anomaly score
        weights = {
            'amount': 0.25,
            'frequency': 0.15,
            'timing': 0.10,
            'channel': 0.10,
            'recipient': 0.20,
            'geographic': 0.10,
            'pattern': 0.10
        }
        
        overall_score = (
            amount_anomaly * weights['amount'] +
            frequency_anomaly * weights['frequency'] +
            timing_anomaly * weights['timing'] +
            channel_anomaly * weights['channel'] +
            recipient_anomaly * weights['recipient'] +
            geographic_anomaly * weights['geographic'] +
            pattern_anomaly * weights['pattern']
        )
        
        # Determine risk level
        if overall_score >= 80:
            risk_level = "critical"
        elif overall_score >= 60:
            risk_level = "high"
        elif overall_score >= 40:
            risk_level = "medium"
        elif overall_score >= 25:
            risk_level = "low"
        else:
            risk_level = "normal"
        
        # Generate explanations
        anomaly_reasons = []
        if amount_anomaly > 50:
            anomaly_reasons.append(f"Amount ${amount:,.2f} significantly deviates from normal range (${profile.avg_amount:,.2f} ± ${profile.std_amount:,.2f})")
        if frequency_anomaly > 50:
            anomaly_reasons.append("Transaction frequency unusual for this customer")
        if timing_anomaly > 50:
            anomaly_reasons.append(f"Transaction at {timestamp.hour:02d}:00 outside normal activity hours")
        if channel_anomaly > 50:
            anomaly_reasons.append(f"Unusual channel '{channel}' for this customer")
        if recipient_anomaly > 50:
            anomaly_reasons.append("New or unusual recipient")
        if geographic_anomaly > 50:
            anomaly_reasons.append(f"Unusual destination country '{country}'")
        if pattern_anomaly > 50:
            anomaly_reasons.append("Transaction pattern suggests layering or structuring")
        
        # Behavioral context
        behavioral_context = (
            f"Customer typically transacts ${profile.avg_amount:,.2f} on average, "
            f"prefers {', '.join(profile.preferred_channels)} channels, "
            f"and has {profile.total_transactions} historical transactions."
        )
        
        # Profile confidence based on data volume
        profile_confidence = min(1.0, profile.total_transactions / 50)
        
        # Overall confidence
        confidence = profile_confidence * 0.7 + (overall_score / 100) * 0.3
        
        return TransactionAnomaly(
            transaction_id=transaction.get('id', 0),
            account_number=profile.account_number,
            overall_anomaly_score=overall_score,
            risk_level=risk_level,
            amount_anomaly=amount_anomaly,
            frequency_anomaly=frequency_anomaly,
            timing_anomaly=timing_anomaly,
            channel_anomaly=channel_anomaly,
            recipient_anomaly=recipient_anomaly,
            geographic_anomaly=geographic_anomaly,
            pattern_anomaly=pattern_anomaly,
            anomaly_reasons=anomaly_reasons,
            behavioral_context=behavioral_context,
            confidence=confidence,
            profile_confidence=profile_confidence
        )
    
    def _score_amount_anomaly(self, profile: CustomerBehavioralProfile, amount: float) -> float:
        """Score how anomalous the amount is (0-100)."""
        if profile.std_amount == 0:
            return 0
        
        # Z-score calculation
        z_score = abs(amount - profile.avg_amount) / profile.std_amount
        
        # Convert to 0-100 scale (3 standard deviations = 100)
        score = min(100, z_score * 33.33)
        
        # Additional check against percentiles
        if amount > profile.amount_percentiles.get('95', 0):
            score = max(score, 70)
        elif amount > profile.amount_percentiles.get('90', 0):
            score = max(score, 50)
        
        return score
    
    def _score_frequency_anomaly(self, profile: CustomerBehavioralProfile, timestamp: datetime) -> float:
        """Score how anomalous the transaction frequency is (0-100)."""
        # This would need recent transaction history to be accurate
        # For now, return a moderate score based on time of day
        return 0
    
    def _score_timing_anomaly(self, profile: CustomerBehavioralProfile, timestamp: datetime) -> float:
        """Score how anomalous the timing is (0-100)."""
        if not profile.peak_hours:
            return 0
        
        hour = timestamp.hour
        if hour in profile.peak_hours:
            return 0
        
        # Calculate distance from peak hours
        min_distance = min(abs(hour - h) for h in profile.peak_hours)
        
        # If more than 6 hours from peak, it's anomalous
        if min_distance > 6:
            return 60
        elif min_distance > 3:
            return 30
        return 0
    
    def _score_channel_anomaly(self, profile: CustomerBehavioralProfile, channel: str) -> float:
        """Score how anomalous the channel is (0-100)."""
        channel_freq = profile.channel_distribution.get(channel, 0)
        
        if channel_freq > 0.3:  # Common channel
            return 0
        elif channel_freq > 0.1:  # Occasionally used
            return 20
        elif channel_freq > 0:  # Rarely used
            return 50
        else:  # Never used
            return 70
    
    def _score_recipient_anomaly(self, profile: CustomerBehavioralProfile, recipient: str) -> float:
        """Score how anomalous the recipient is (0-100)."""
        if not recipient or not profile.common_recipients:
            return 0
        
        # Check if recipient is in common recipients
        for rec, freq in profile.common_recipients:
            if rec == recipient:
                if freq > 0.3:  # Frequent recipient
                    return 0
                elif freq > 0.1:  # Occasional recipient
                    return 20
                else:  # Rare recipient
                    return 40
        
        # New recipient
        if profile.recipient_diversity > 0.5:  # Customer uses many different recipients
            return 30
        else:  # Customer has few regular recipients
            return 60
    
    def _score_geographic_anomaly(self, profile: CustomerBehavioralProfile, country: str) -> float:
        """Score how anomalous the destination country is (0-100)."""
        if not profile.common_countries:
            return 0
        
        # Check if country is common
        for c, freq in profile.common_countries:
            if c == country:
                if freq > 0.5:  # Common country
                    return 0
                elif freq > 0.1:  # Occasional country
                    return 20
                else:  # Rare country
                    return 40
        
        # New country
        if profile.international_ratio > 0.3:  # Customer frequently does international transfers
            return 30
        else:  # Customer rarely does international transfers
            return 70
    
    def _score_pattern_anomaly(self, profile: CustomerBehavioralProfile, transaction: Dict[str, Any]) -> float:
        """Score how anomalous the transaction pattern is (0-100)."""
        amount = float(transaction.get('amount', 0))
        tx_type = transaction.get('transaction_type', 'unknown')
        
        score = 0
        
        # Check for structuring (amounts just below thresholds)
        if 8500 <= amount <= 9999:
            score += 40
        
        # Check for round amounts (suspicious for transfers)
        if tx_type == 'transfer' and amount >= 1000 and amount % 1000 == 0:
            score += 20
        
        # Check if transaction type is unusual
        type_freq = profile.type_distribution.get(tx_type, 0)
        if type_freq < 0.1:
            score += 30
        
        return min(100, score)
    
    def update_profile(
        self,
        profile: CustomerBehavioralProfile,
        new_transaction: Dict[str, Any],
        anomaly_score: float = 0
    ) -> CustomerBehavioralProfile:
        """
        Update behavioral profile with a new transaction using adaptive learning.
        
        The learning rate adapts based on:
        - Whether the transaction was anomalous (slower learning for anomalies)
        - Profile confidence (slower learning for well-established profiles)
        - Gradual vs sudden changes (detect legitimate behavior shifts)
        
        Args:
            profile: Existing profile to update
            new_transaction: New transaction to incorporate
            anomaly_score: How anomalous this transaction was (0-100)
            
        Returns:
            Updated profile
        """
        profile.last_updated = datetime.now(timezone.utc).isoformat()
        profile.total_transactions += 1
        
        # Adaptive learning rate based on anomaly and profile maturity
        # Lower learning rate for anomalous transactions to prevent contamination
        # Lower learning rate for mature profiles to maintain stability
        profile_maturity = min(1.0, profile.total_transactions / 100)
        anomaly_factor = 1.0 - (anomaly_score / 200)  # Reduce learning for anomalies
        base_alpha = 0.05  # Conservative base learning rate
        alpha = base_alpha * anomaly_factor * (1 - profile_maturity * 0.5)
        
        # Update amount statistics with adaptive learning
        new_amount = float(new_transaction.get('amount', 0))
        profile.avg_amount = profile.avg_amount * (1 - alpha) + new_amount * alpha
        
        # Update standard deviation (simplified)
        diff = abs(new_amount - profile.avg_amount)
        profile.std_amount = profile.std_amount * (1 - alpha) + diff * alpha
        
        # Update min/max
        profile.min_amount = min(profile.min_amount, new_amount)
        profile.max_amount = max(profile.max_amount, new_amount)
        
        # Update channel distribution
        new_channel = new_transaction.get('channel', 'online')
        profile.channel_distribution[new_channel] = (
            profile.channel_distribution.get(new_channel, 0) * (1 - alpha) + alpha
        )
        
        # Normalize channel distribution
        total = sum(profile.channel_distribution.values())
        if total > 0:
            profile.channel_distribution = {k: v/total for k, v in profile.channel_distribution.items()}
        
        # Update preferred channels
        sorted_channels = sorted(profile.channel_distribution.items(), key=lambda x: x[1], reverse=True)
        profile.preferred_channels = [ch for ch, _ in sorted_channels[:3]]
        
        # Update transaction type distribution
        new_type = new_transaction.get('transaction_type', 'unknown')
        profile.type_distribution[new_type] = (
            profile.type_distribution.get(new_type, 0) * (1 - alpha) + alpha
        )
        
        total_types = sum(profile.type_distribution.values())
        if total_types > 0:
            profile.type_distribution = {k: v/total_types for k, v in profile.type_distribution.items()}
        
        # Update preferred types
        sorted_types = sorted(profile.type_distribution.items(), key=lambda x: x[1], reverse=True)
        profile.preferred_types = [t for t, _ in sorted_types[:3]]
        
        # Update recipient patterns for transfers
        if new_transaction.get('transaction_type') == 'transfer':
            recipient = new_transaction.get('receiver_account', '')
            if recipient:
                # Add or update recipient in common recipients
                found = False
                updated_recipients = []
                for rec, freq in profile.common_recipients:
                    if rec == recipient:
                        updated_recipients.append((rec, freq * (1 - alpha) + alpha))
                        found = True
                    else:
                        updated_recipients.append((rec, freq * (1 - alpha * 0.5)))  # Decay others
                
                if not found:
                    updated_recipients.append((recipient, alpha))
                
                # Sort and keep top 10
                updated_recipients.sort(key=lambda x: x[1], reverse=True)
                profile.common_recipients = updated_recipients[:10]
                
                # Recalculate diversity
                total_recipient_freq = sum(f for _, f in profile.common_recipients)
                if total_recipient_freq > 0:
                    profile.recipient_diversity = len(profile.common_recipients) / total_recipient_freq
        
        # Update geographic patterns
        new_country = new_transaction.get('destination_country', 'ZW')
        profile.common_countries.append((new_country, alpha))
        
        # Decay old country entries and sort
        updated_countries = []
        for country, freq in profile.common_countries:
            if country == new_country:
                updated_countries.append((country, freq + alpha))
            else:
                updated_countries.append((country, freq * 0.99))  # Slow decay
        
        updated_countries.sort(key=lambda x: x[1], reverse=True)
        profile.common_countries = updated_countries[:10]
        
        # Recalculate international ratio
        international_count = sum(1 for c, _ in profile.common_countries if c not in ['ZW', 'US', 'GB', ''])
        profile.international_ratio = international_count / len(profile.common_countries) if profile.common_countries else 0
        
        # Detect gradual behavior shifts
        self._detect_behavioral_shift(profile, new_transaction)
        
        return profile
    
    def _detect_behavioral_shift(self, profile: CustomerBehavioralProfile, transaction: Dict[str, Any]):
        """Detect if customer is undergoing legitimate behavior change."""
        # This would track patterns over time to distinguish between
        # legitimate behavior changes and suspicious anomalies
        # For now, this is a placeholder for future enhancement
        
        # Example: If customer consistently uses a new channel over 10+ transactions,
        # it's likely a legitimate shift, not an anomaly
        new_channel = transaction.get('channel', 'online')
        if new_channel not in profile.preferred_channels:
            # Track this in a separate "emerging patterns" structure
            # After N consistent uses, promote to preferred
            pass
    
    def profile_to_dict(self, profile: CustomerBehavioralProfile) -> Dict[str, Any]:
        """Convert profile to dictionary for storage."""
        return asdict(profile)
    
    def dict_to_profile(self, data: Dict[str, Any]) -> CustomerBehavioralProfile:
        """Convert dictionary to profile object."""
        return CustomerBehavioralProfile(**data)
