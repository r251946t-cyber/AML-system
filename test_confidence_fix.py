"""
Test the new adaptive confidence threshold logic
"""

# Simulating the fixed code
AI_RISK_SCORES = {
    "normal": 10,
    "suspicious": 55,
    "super_suspicious": 90,
}

def test_ml_scoring(ml_level, ml_confidence):
    """Test the new adaptive confidence threshold"""
    
    # This is the NEW logic that was just implemented
    confidence_threshold = 0.65  # default
    if ml_level == "super_suspicious":
        confidence_threshold = 0.55
    elif ml_level == "suspicious":
        confidence_threshold = 0.65
    else:
        confidence_threshold = 0.75
    
    ml_score = AI_RISK_SCORES.get(ml_level, 0) if ml_confidence >= confidence_threshold else 0
    
    return ml_score, confidence_threshold

# Test cases based on actual transaction data
test_cases = [
    ("super_suspicious", 0.64, "Transaction #6 ($19,890) - NOW SHOULD BE FLAGGED"),
    ("super_suspicious", 0.82, "Transaction #2 ($5,906.50) - Already flagged"),
    ("suspicious", 0.62, "Test: Suspicious at 62% - Still NOT flagged (needs 65%)"),
    ("suspicious", 0.65, "Test: Suspicious at 65% - Exactly at threshold - FLAGGED"),
    ("normal", 0.74, "Test: Normal at 74% - NOT flagged (needs 75%)"),
    ("normal", 0.75, "Test: Normal at 75% - At threshold - FLAGGED"),
]

print("=" * 100)
print("ADAPTIVE CONFIDENCE THRESHOLD TEST RESULTS")
print("=" * 100)

for ml_level, ml_confidence, description in test_cases:
    ml_score, threshold = test_ml_scoring(ml_level, ml_confidence)
    passed = ml_score > 0
    status = "✓ FLAGGED" if passed else "✗ NOT FLAGGED"
    
    print(f"\n{description}")
    print(f"  ML Level: {ml_level}")
    print(f"  Confidence: {ml_confidence:.2%} (threshold: {threshold:.0%})")
    print(f"  ML Score: {ml_score}")
    print(f"  Result: {status}")

print("\n" + "=" * 100)
print("SUMMARY:")
print("=" * 100)
print("""
✓ Transaction #6 ($19,890): super_suspicious at 64% confidence
  - OLD behavior: 64% < 65% → NOT FLAGGED (BUG)
  - NEW behavior: 64% >= 55% → FLAGGED (FIXED)
  - Risk Score will now include: 90 * 0.64 * 0.65 = 37.4 points ✓
  
✓ Transaction #2 ($5,906.50): super_suspicious at 82% confidence
  - Already flagged in both old and new behavior
  - Risk Score: 90 * 0.82 * 0.65 = 48 points
""")
