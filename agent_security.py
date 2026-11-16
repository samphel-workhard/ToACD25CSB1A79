import re
from datetime import datetime

def sanitize_text(text):
    """
    Scrubs sensitive patterns like API keys, secrets, or passwords before logging.
    """
    if not isinstance(text, str):
        return str(text)
    
    # Redact potential API keys, secret tokens, environment variable assignments
    scrubbed = re.sub(r'(?i)(api[_-]?key|secret|password|auth[_-]?token)\s*[:=]\s*[\'"]?[\w\-]+[\'"]?', r'\1=***REDACTED***', text)
    return scrubbed[:500] # Cap length to prevent log bloat

def analyze_security_threat(input_text, context_type="code"):
    """
    Analyzes input text or code for security threats:
    - PROMPT_INJECTION
    - POLICY_BYPASS
    - CODE_VULNERABILITY
    
    Returns a dict containing threat details:
    {
        "is_safe": bool,
        "event_type": str,
        "risk_level": str, # CRITICAL, HIGH, MEDIUM, LOW, NONE
        "risk_score": float, # 0.0 to 1.0
        "action": str, # BLOCKED or ALLOWED
        "detection_reason": str,
        "input_snippet": str
    }
    """
    input_str = str(input_text)
    lower_str = input_str.lower()
    
    # 1. Check for PROMPT INJECTION patterns
    prompt_injection_patterns = [
        (r"ignore\s+(all\s+)?(previous|prior)\s+instructions", "Attempted to override system instructions"),
        (r"disregard\s+(all\s+)?safety\s+rules", "Attempted to bypass safety directives"),
        (r"you\s+are\s+now\s+(a|an)?\s*(unrestricted|jailbroken|dan)", "Attempted persona modification / jailbreak"),
        (r"reveal\s+(the\s+)?(system\s+prompt|initial\s+instructions)", "Attempted system prompt extraction"),
        (r"override\s+(security|guardrails)", "Explicit security override prompt"),
    ]
    
    for pattern, reason in prompt_injection_patterns:
        if re.search(pattern, lower_str):
            return {
                "is_safe": False,
                "event_type": "PROMPT_INJECTION",
                "risk_level": "HIGH",
                "risk_score": 0.90,
                "action": "BLOCKED",
                "detection_reason": f"Prompt Injection Detected: {reason}",
                "input_snippet": sanitize_text(input_str)
            }
            
    # 2. Check for POLICY BYPASS patterns
    policy_bypass_patterns = [
        (r"system\s*\(\s*[\"'].*?rm\s+-rf", "Critical OS destruction command attempt"),
        (r"system\s*\(", "Attempted OS command execution via system()"),
        (r"popen\s*\(", "Attempted shell command pipe creation via popen()"),
        (r"exec(l|le|lp|v|vp|ve)\s*\(", "Attempted process execution via exec family"),
        (r"bypass\s+security", "Explicit policy bypass phrase detected"),
        (r"disable\s+guardrail", "Explicit request to disable security guardrails"),
        (r"cat\s+/etc/passwd", "Attempted sensitive system file access"),
    ]
    
    for pattern, reason in policy_bypass_patterns:
        if re.search(pattern, lower_str):
            risk_lvl = "CRITICAL" if "rm -rf" in lower_str else "HIGH"
            score = 0.98 if risk_lvl == "CRITICAL" else 0.85
            return {
                "is_safe": False,
                "event_type": "POLICY_BYPASS",
                "risk_level": risk_lvl,
                "risk_score": score,
                "action": "BLOCKED",
                "detection_reason": f"Policy Bypass Detected: {reason}",
                "input_snippet": sanitize_text(input_str)
            }

    # 3. Code level security checks (Banned C++ Functions)
    code_vulnerabilities = [
        (r"\bgets\b", "CRITICAL", 0.95, "Use of 'gets()' leads to unbounded buffer overflow"),
        (r"\bstrcpy\b", "HIGH", 0.80, "Use of 'strcpy()' lacks bounds checking"),
        (r"\bstrcat\b", "HIGH", 0.80, "Use of 'strcat()' lacks bounds checking"),
        (r"\bsprintf\b", "HIGH", 0.75, "Use of 'sprintf()' lacks buffer size enforcement"),
        (r"\bmktemp\b", "HIGH", 0.75, "Use of 'mktemp()' creates insecure temporary file race conditions"),
        (r"\bauto_ptr\b", "MEDIUM", 0.50, "Use of deprecated 'auto_ptr'"),
    ]
    
    for pattern, risk_lvl, score, reason in code_vulnerabilities:
        if re.search(pattern, input_str):
            is_blocked = (risk_lvl in ["CRITICAL", "HIGH"])
            return {
                "is_safe": not is_blocked,
                "event_type": "CODE_VULNERABILITY",
                "risk_level": risk_lvl,
                "risk_score": score,
                "action": "BLOCKED" if is_blocked else "ALLOWED",
                "detection_reason": f"Code Vulnerability Detected: {reason}",
                "input_snippet": sanitize_text(input_str)
            }

    # If all checks pass
    return {
        "is_safe": True,
        "event_type": "BENIGN_CHECK",
        "risk_level": "NONE",
        "risk_score": 0.00,
        "action": "ALLOWED",
        "detection_reason": "No security violations or threats detected.",
        "input_snippet": sanitize_text(input_str)
    }
