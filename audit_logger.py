import json
import os
from datetime import datetime
from agent_security import sanitize_text

INTERACTION_LOG_FILE = "system_interactions.json"
SECURITY_LOG_FILE = "security_audit_logs.json"

def log_interaction(user_prompt, llm_response, code_snippet="N/A", error_category="N/A", fixed_code="N/A"):
    """
    Appends a single interaction turn to system_interactions.json log file.
    """
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "error_category": error_category,
        "code_snippet": sanitize_text(code_snippet),
        "user_prompt": sanitize_text(user_prompt),
        "llm_response": sanitize_text(llm_response),
        "fixed_code": sanitize_text(fixed_code)  
    }

    data = []
    if os.path.exists(INTERACTION_LOG_FILE):
        with open(INTERACTION_LOG_FILE, "r", encoding="utf-8") as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                data = []

    data.append(log_entry)

    with open(INTERACTION_LOG_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

def log_security_event(
    event_type,
    risk_level,
    risk_score,
    action,
    detection_reason,
    input_snippet="N/A",
    correlation_id=None,
    source="submitted_code",
    repair_attempt_id=None
):
    """
    Appends a security audit event to security_audit_logs.json,
    and synchronizes threat/incident events into the persistent SQLite Attack Vault.
    """
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": str(event_type),
        "risk_level": str(risk_level),
        "risk_score": round(float(risk_score), 2) if isinstance(risk_score, (int, float)) else "N/A",
        "action": str(action),
        "detection_reason": sanitize_text(detection_reason),
        "input_snippet": sanitize_text(input_snippet)
    }

    logs = []
    if os.path.exists(SECURITY_LOG_FILE):
        with open(SECURITY_LOG_FILE, "r", encoding="utf-8") as file:
            try:
                logs = json.load(file)
            except json.JSONDecodeError:
                logs = []

    logs.append(log_entry)

    with open(SECURITY_LOG_FILE, "w", encoding="utf-8") as file:
        json.dump(logs, file, indent=4)

    # Persist security incidents to the SQLite Attack Vault
    if event_type != "BENIGN_CHECK" or action == "BLOCKED" or str(risk_level).upper() in ["CRITICAL", "HIGH", "MEDIUM"]:
        try:
            from attack_vault import record_attack
            record_attack(
                category=str(event_type),
                source=str(source),
                input_text=input_snippet,
                risk_level=str(risk_level),
                detection_reason=str(detection_reason),
                risk_score=risk_score,
                action_taken=str(action),
                correlation_id=correlation_id,
                repair_attempt_id=repair_attempt_id,
                validation_status="Failed" if action == "BLOCKED" else "Passed"
            )
        except Exception as e:
            print(f"Attack Vault Sync Notice: {e}")

    return log_entry

def get_security_logs():
    """
    Retrieves stored security audit logs from security_audit_logs.json.
    Returns list of dicts.
    """
    if os.path.exists(SECURITY_LOG_FILE):
        with open(SECURITY_LOG_FILE, "r", encoding="utf-8") as file:
            try:
                return json.load(file)
            except json.JSONDecodeError:
                return []
    return []

def clear_security_logs():
    """
    Clears stored security logs upon explicit user action.
    """
    with open(SECURITY_LOG_FILE, "w", encoding="utf-8") as file:
        json.dump([], file, indent=4)
