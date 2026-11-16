import os
from attack_vault import get_vault_summary_stats, list_attacks, get_vault_db_path

def compute_security_metrics(db_path=None):
    """
    Computes aggregated security posture metrics from the Attack Vault.
    Guarantees that all metrics are derived directly from actual recorded events,
    avoiding fabricated numbers.
    """
    stats = get_vault_summary_stats(db_path=db_path)
    total = stats.get("total_events", 0)
    blocked = stats.get("blocked_attacks", 0)
    critical = stats.get("critical_events", 0)
    pending = stats.get("pending_reviews", 0)
    confirmed = stats.get("confirmed_attacks", 0)
    false_positives = stats.get("false_positives", 0)

    # Calculate real percentages
    block_rate = round((blocked / total * 100), 1) if total > 0 else 0.0
    critical_rate = round((critical / total * 100), 1) if total > 0 else 0.0

    reviewed_total = confirmed + false_positives
    precision_rate = round((confirmed / reviewed_total * 100), 1) if reviewed_total > 0 else None
    false_positive_rate = round((false_positives / reviewed_total * 100), 1) if reviewed_total > 0 else None

    # Calculate average risk score
    all_records = list_attacks(limit=1000, db_path=db_path)
    numeric_scores = [r["risk_score"] for r in all_records if r.get("risk_score") is not None]
    avg_risk_score = round(sum(numeric_scores) / len(numeric_scores), 2) if numeric_scores else None

    # Self-healing specific security metrics
    ai_fix_attacks = [r for r in all_records if r.get("source") == "ai_generated_fix" or r.get("category") == "MALICIOUS_AI_FIX"]
    ai_fixes_blocked = len(ai_fix_attacks)

    return {
        "total_events": total,
        "blocked_attacks": blocked,
        "block_rate_percent": block_rate,
        "critical_events": critical,
        "critical_rate_percent": critical_rate,
        "pending_reviews": pending,
        "confirmed_attacks": confirmed,
        "false_positives": false_positives,
        "precision_rate_percent": precision_rate,
        "false_positive_rate_percent": false_positive_rate,
        "avg_risk_score": avg_risk_score,
        "ai_fixes_blocked": ai_fixes_blocked,
        "by_category": stats.get("by_category", {}),
        "by_severity": stats.get("by_severity", {})
    }
