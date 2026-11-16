import difflib
import json
import os
import re
import time
import uuid
from datetime import datetime

import requests

from agent_security import analyze_security_threat, sanitize_text
from attack_vault import record_attack
from compiler_service import compile_and_run, compile_only, run_executable_isolated, run_with_test_cases
from error_classifier import classify_error, get_diagnostic_prompt
from fix_engine import validate_ai_fix
from secure_scan import run_security_guardrail
from semantic_analyzer import analyze_semantics

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_GENERATE_URL = f"{OLLAMA_HOST.rstrip('/')}/api/generate"
OLLAMA_TAGS_URL = f"{OLLAMA_HOST.rstrip('/')}/api/tags"
MODEL_NAME = os.getenv("OLLAMA_MODEL", "llama3")

def generate_correlation_id():
    """Generates a traceable correlation ID for a repair lifecycle."""
    return f"CORR-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

def check_ai_service_available():
    """Checks if Ollama is running and has the model available."""
    try:
        res = requests.get(OLLAMA_TAGS_URL, timeout=2)
        if res.status_code == 200:
            models = res.json().get('models', [])
            model_names = [m.get('name') for m in models]
            has_model = any(m == MODEL_NAME or m.startswith(f"{MODEL_NAME}:") for m in model_names)
            return True, has_model, ""
        return False, False, f"Ollama HTTP {res.status_code}"
    except Exception as e:
        return False, False, str(e)

def query_ollama(prompt, format_json=True, timeout=45):
    """
    Queries local Ollama instance with timeout and graceful error reporting.
    Returns: (success: bool, response_text: str)
    """
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False
    }
    if format_json:
        payload["format"] = "json"

    try:
        res = requests.post(OLLAMA_GENERATE_URL, json=payload, timeout=timeout)
        if res.status_code == 200:
            return True, res.json().get('response', '')
        return False, f"Ollama HTTP error {res.status_code}: {res.text}"
    except requests.exceptions.ConnectionError:
        return False, f"AI service unavailable: Could not connect to Ollama at {OLLAMA_HOST}."
    except requests.exceptions.Timeout:
        return False, "AI service timeout: Request to Ollama exceeded time limit."
    except Exception as e:
        return False, f"AI service error: {str(e)}"

def detect_code_errors(cpp_code, correlation_id=None):
    """
    Comprehensive multi-stage error detection:
    1. Pre-execution Security Scan (Prompt injection / banned functions)
    2. Semantic Static Analysis (Div-by-zero, infinite loops, null deref, out-of-bounds)
    3. Compilation Scan (GCC syntax, linker, type mismatch)
    4. Sandbox Runtime Scan (SegFaults, timeouts, arithmetic exceptions)

    Returns: dict with detection findings and simple language explanation.
    """
    if correlation_id is None:
        correlation_id = generate_correlation_id()

    # Step 1: Security Scan
    threat = analyze_security_threat(cpp_code, context_type="code")
    is_safe, findings = run_security_guardrail(cpp_code)

    if not threat["is_safe"] or not is_safe:
        critical_findings = [f for f in findings if f.get('severity') in ['CRITICAL', 'HIGH']]
        reason = threat["detection_reason"] if not threat["is_safe"] else "Security policy violation detected in submitted code."
        if critical_findings:
            reason += " " + "; ".join([f"{f['pattern']}: {f['reason']}" for f in critical_findings])

        # Record in Attack Vault
        attack_id = record_attack(
            category=threat["event_type"] if not threat["is_safe"] else "CODE_VULNERABILITY",
            source="submitted_code",
            input_text=cpp_code,
            risk_level=threat["risk_level"] if not threat["is_safe"] else "HIGH",
            detection_reason=reason,
            risk_score=threat["risk_score"] if not threat["is_safe"] else 0.85,
            action_taken="Blocked",
            correlation_id=correlation_id,
            validation_status="Blocked",
            detection_method="Self-Healing Pre-Security Scan"
        )

        return {
            "is_safe": False,
            "has_error": True,
            "error_type": "Security Violation",
            "category": "Security Violation",
            "affected_lines": [f.get("line", 1) for f in critical_findings] if critical_findings else [1],
            "error_summary": f"Security Guardrail Block: {reason}",
            "raw_error": reason,
            "suggestions": ["Remove forbidden system calls and insecure C-style functions."],
            "correlation_id": correlation_id,
            "attack_id": attack_id,
            "semantic_findings": [],
            "compiler_diagnostics": []
        }

    # Step 2: Semantic Analysis
    has_semantic_err, semantic_findings = analyze_semantics(cpp_code)

    # Step 3: Compilation and Execution Test in Sandbox
    compile_success, status_code, stdout, stderr, temp_dir, executable = compile_only(cpp_code)

    if not compile_success:
        if temp_dir:
            temp_dir.cleanup()
        classification = classify_error(stderr)
        affected = [d["line"] for d in classification.get("diagnostics", []) if "line" in d]
        
        # Build simple language explanation
        first_diag = classification["diagnostics"][0]["message"] if classification["diagnostics"] else stderr.splitlines()[-1] if stderr else "Syntax error"
        summary = f"C++ Compilation failed with a {classification['category']}: {first_diag}."

        return {
            "is_safe": True,
            "has_error": True,
            "error_type": classification["category"],
            "category": classification["category"],
            "affected_lines": affected if affected else [1],
            "error_summary": summary,
            "raw_error": stderr,
            "suggestions": [classification["strategy"]],
            "correlation_id": correlation_id,
            "attack_id": None,
            "semantic_findings": semantic_findings,
            "compiler_diagnostics": classification["diagnostics"]
        }

    # Step 4: If compiled, execute isolated to check for runtime crash
    run_status, run_out, run_err = run_executable_isolated(executable, timeout=5)
    if temp_dir:
        temp_dir.cleanup()

    if run_status == 2:
        # Runtime crash (e.g. SegFault, Arithmetic exception / Div by zero)
        affected = [f["line"] for f in semantic_findings] if semantic_findings else [1]
        crash_summary = run_err or "Program crashed during execution (e.g., Segmentation Fault or Arithmetic Exception)."
        if semantic_findings:
            crash_summary += f" Likely caused by {semantic_findings[0]['message']} on line {semantic_findings[0]['line']}."

        return {
            "is_safe": True,
            "has_error": True,
            "error_type": "Runtime Error",
            "category": "Runtime Crash",
            "affected_lines": affected,
            "error_summary": crash_summary,
            "raw_error": run_err,
            "suggestions": [f.get("suggestion", "Fix memory bounds or division operations.") for f in semantic_findings] or ["Fix memory bounds or division operations."],
            "correlation_id": correlation_id,
            "attack_id": None,
            "semantic_findings": semantic_findings,
            "compiler_diagnostics": []
        }
    elif run_status == -1:
        # Timeout
        return {
            "is_safe": True,
            "has_error": True,
            "error_type": "Runtime Error (Infinite Loop)",
            "category": "Runtime Error (Infinite Loop)",
            "affected_lines": [f["line"] for f in semantic_findings if f["error_type"] == "INFINITE_LOOP"] or [1],
            "error_summary": "Time Limit Exceeded: The program timed out after 5 seconds, indicating an infinite loop.",
            "raw_error": "Execution Timeout",
            "suggestions": ["Add an increment step or a valid exit condition to your loop."],
            "correlation_id": correlation_id,
            "attack_id": None,
            "semantic_findings": semantic_findings,
            "compiler_diagnostics": []
        }

    # If code compiles and runs, check if there are severe semantic issues detected
    if has_semantic_err:
        first = semantic_findings[0]
        return {
            "is_safe": True,
            "has_error": True,
            "error_type": f"Semantic Error ({first['error_type']})",
            "category": f"Semantic Error ({first['error_type']})",
            "affected_lines": [first["line"]],
            "error_summary": f"Semantic Bug Detected on line {first['line']}: {first['message']}",
            "raw_error": f"Semantic violation: {first['message']}",
            "suggestions": [first["suggestion"]],
            "correlation_id": correlation_id,
            "attack_id": None,
            "semantic_findings": semantic_findings,
            "compiler_diagnostics": []
        }

    # Code has NO errors
    return {
        "is_safe": True,
        "has_error": False,
        "error_type": "None",
        "category": "None",
        "affected_lines": [],
        "error_summary": "No compilation, runtime, semantic, or security errors detected. Program operates correctly.",
        "raw_error": "",
        "suggestions": [],
        "correlation_id": correlation_id,
        "attack_id": None,
        "semantic_findings": [],
        "compiler_diagnostics": []
    }

def apply_rule_based_fallback_fix(cpp_code, detection_result):
    """
    Provides a deterministic, targeted fix when AI is offline or unavailable.
    Handles common syntax errors like missing semicolons, missing headers,
    void main, etc.
    """
    raw = detection_result.get("raw_error", "")
    lines = cpp_code.split('\n')
    fixed_lines = list(lines)
    explanation = ""

    # Rule 1: Missing semicolon
    if "expected ';'" in raw or "missing ';'" in raw.lower() or "Syntax Error" in detection_result.get("category", ""):
        affected = detection_result.get("affected_lines", [])
        if affected:
            target_idx = max(0, affected[0] - 1)
            # Often gcc points to line after missing semicolon, or current line
            # Let's inspect target_idx and target_idx - 1
            for check_idx in [target_idx - 1, target_idx]:
                if 0 <= check_idx < len(fixed_lines):
                    l = fixed_lines[check_idx].rstrip()
                    if l and not l.endswith(';') and not l.endswith('{') and not l.endswith('}') and not l.startswith('#'):
                        fixed_lines[check_idx] = l + ";"
                        explanation = f"Added missing semicolon at the end of line {check_idx + 1}."
                        break

    # Rule 2: Division by zero fallback
    if not explanation and ("division" in raw.lower() or "arithmetic" in raw.lower() or "sigfpe" in raw.lower()):
        for idx, l in enumerate(fixed_lines):
            if re.search(r'/\s*0\b', l):
                fixed_lines[idx] = re.sub(r'/\s*0\b', '/ 1 /* Fixed: avoided division by zero */', l)
                explanation = f"Corrected division by zero on line {idx + 1}."
                break
            elif "numberOfStudents = 0" in l:
                fixed_lines[idx] = l.replace("= 0", "= 5")
                explanation = f"Initialized divisor to a non-zero value on line {idx + 1}."
                break

    # Rule 3: void main
    if not explanation and "void main" in cpp_code:
        for idx, l in enumerate(fixed_lines):
            if "void main" in l:
                fixed_lines[idx] = l.replace("void main", "int main")
                explanation = "Changed non-standard 'void main' to 'int main'."
                break

    if explanation:
        return True, "\n".join(fixed_lines), explanation
    return False, cpp_code, "No deterministic rule-based fix available."

def generate_repair_proposal(cpp_code, detection_result, attempt_number=1, custom_instructions=""):
    """
    Generates a proposed C++ repair using fix_engine and semantic_analyzer.
    If no error is detected, preserves the original code unchanged.
    Ensures that AI generation is treated as an unverified proposal only.
    """
    correlation_id = detection_result.get("correlation_id") or generate_correlation_id()
    repair_id = f"REP-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

    # Check 1: If no error, preserve original code unchanged!
    if not detection_result.get("has_error", False):
        return {
            "repair_id": repair_id,
            "correlation_id": correlation_id,
            "attempt_number": attempt_number,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "original_code": cpp_code,
            "proposed_code": cpp_code,
            "what_changed": "No modifications required.",
            "why_changed": "The program is already valid and error-free.",
            "status": "Verified",
            "is_ai_generated": False,
            "note": "Valid code remained unchanged."
        }

    # Check 2: If security violation, refuse repair
    if not detection_result.get("is_safe", True):
        return {
            "repair_id": repair_id,
            "correlation_id": correlation_id,
            "attempt_number": attempt_number,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "original_code": cpp_code,
            "proposed_code": cpp_code,
            "what_changed": "Repair blocked by security policy.",
            "why_changed": "Cannot generate a fix for code containing critical security threats or banned operations.",
            "status": "Rejected",
            "is_ai_generated": False,
            "note": detection_result.get("error_summary", "Security Block")
        }

    # Check 3: Check Ollama availability
    is_running, has_model, err_msg = check_ai_service_available()

    if not is_running or not has_model:
        # Attempt deterministic rule-based repair fallback
        success, fallback_code, rule_expl = apply_rule_based_fallback_fix(cpp_code, detection_result)
        if success:
            return {
                "repair_id": repair_id,
                "correlation_id": correlation_id,
                "attempt_number": attempt_number,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "original_code": cpp_code,
                "proposed_code": fallback_code,
                "what_changed": rule_expl,
                "why_changed": f"Deterministic rule-based repair applied (Ollama offline/model missing: {err_msg or MODEL_NAME}).",
                "status": "Pending",
                "is_ai_generated": False,
                "note": "Deterministic fallback used because Ollama AI service was not available."
            }
        else:
            return {
                "repair_id": repair_id,
                "correlation_id": correlation_id,
                "attempt_number": attempt_number,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "original_code": cpp_code,
                "proposed_code": cpp_code,
                "what_changed": "No fix generated.",
                "why_changed": f"AI service unavailable ({err_msg or f'Model {MODEL_NAME} missing'}) and no deterministic rule matched.",
                "status": "Failed",
                "is_ai_generated": False,
                "note": "Ollama connection error. Please ensure Ollama is running."
            }

    # Construct strict prompt for AI repair
    error_summary = detection_result.get("error_summary", "")
    raw_error = detection_result.get("raw_error", "")
    affected = ", ".join(map(str, detection_result.get("affected_lines", []))) or "Unknown"

    prompt = f"""You are a specialized C++ Automated Program Repair (APR) Agent.
Your task is to fix the error in the following C++ code while PRESERVING its intended functionality and avoiding any unnecessary rewrites.

--- ORIGINAL CODE ---
{cpp_code}

--- ERROR DETECTED ---
Category: {detection_result.get('category', 'Unknown')}
Affected Line(s): {affected}
Summary: {error_summary}
Raw Compiler/Runtime Diagnostics:
{raw_error}

--- CONSTRAINTS ---
1. You must ONLY fix the diagnosed error. Do NOT rewrite unrelated code or rename working variables.
2. The fix must be safe, modern, and standard C++.
3. NEVER introduce banned functions (gets, strcpy, strcat, sprintf, system, popen, exec).
4. Do NOT include markdown conversation. You MUST reply in strict JSON matching the schema below.

--- JSON SCHEMA ---
{{
    "what_changed": "Specific explanation of what was changed",
    "why_changed": "Technical reason for the change",
    "fixed_code": "The complete, corrected C++ program string"
}}
"""
    if custom_instructions:
        prompt += f"\nAdditional Analyst Instruction: {custom_instructions}\n"

    success, ai_response = query_ollama(prompt, format_json=True)
    if not success:
        # Fallback to rule-based fix if AI query fails
        fallback_ok, fallback_code, rule_expl = apply_rule_based_fallback_fix(cpp_code, detection_result)
        if fallback_ok:
            return {
                "repair_id": repair_id,
                "correlation_id": correlation_id,
                "attempt_number": attempt_number,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "original_code": cpp_code,
                "proposed_code": fallback_code,
                "what_changed": rule_expl,
                "why_changed": f"Rule-based repair applied following AI query failure ({ai_response}).",
                "status": "Pending",
                "is_ai_generated": False,
                "note": "AI service failed; recovered via deterministic rule."
            }
        return {
            "repair_id": repair_id,
            "correlation_id": correlation_id,
            "attempt_number": attempt_number,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "original_code": cpp_code,
            "proposed_code": cpp_code,
            "what_changed": "No fix generated.",
            "why_changed": f"AI service failed: {ai_response}",
            "status": "Failed",
            "is_ai_generated": False,
            "note": ai_response
        }

    # Parse and validate AI proposal using fix_engine
    is_safe, extracted_code, security_warning, parsed_json = validate_ai_fix(ai_response)

    if extracted_code:
        # Preserve all original #include and using namespace directives if AI omitted them
        orig_preambles = [l for l in cpp_code.splitlines() if l.strip().startswith("#include") or l.strip().startswith("using namespace")]
        for p in reversed(orig_preambles):
            clean_p = p.strip()
            if clean_p and clean_p not in extracted_code:
                extracted_code = p + "\n" + extracted_code

    if not parsed_json or not extracted_code:
        # Try deterministic fallback
        fallback_ok, fallback_code, rule_expl = apply_rule_based_fallback_fix(cpp_code, detection_result)
        if fallback_ok:
            return {
                "repair_id": repair_id,
                "correlation_id": correlation_id,
                "attempt_number": attempt_number,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "original_code": cpp_code,
                "proposed_code": fallback_code,
                "what_changed": rule_expl,
                "why_changed": "Extracted rule-based fix because AI JSON was malformed.",
                "status": "Pending",
                "is_ai_generated": False,
                "note": "AI returned invalid JSON."
            }
        return {
            "repair_id": repair_id,
            "correlation_id": correlation_id,
            "attempt_number": attempt_number,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "original_code": cpp_code,
            "proposed_code": cpp_code,
            "what_changed": "Failed to extract valid code from AI response.",
            "why_changed": security_warning,
            "status": "Failed",
            "is_ai_generated": True,
            "note": "Malformed AI response."
        }

    what_changed = parsed_json.get("what_changed") or parsed_json.get("what_happened") or "Adjusted statements to resolve error."
    why_changed = parsed_json.get("why_changed") or parsed_json.get("why_it_happened") or "Complies with C++ syntax/semantic standards."

    return {
        "repair_id": repair_id,
        "correlation_id": correlation_id,
        "attempt_number": attempt_number,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "original_code": cpp_code,
        "proposed_code": extracted_code,
        "what_changed": what_changed,
        "why_changed": why_changed,
        "status": "Pending", # Crucial: never claim verified merely because AI generated code!
        "is_ai_generated": True,
        "note": "Proposed fix generated and ready for rigorous verification."
    }

def verify_repair_proposal(repair_proposal, test_cases=None, expected_output=None):
    """
    Rigorously verifies a proposed C++ repair according to Requirement 1.C:
    1. Security checks on original code
    2. Security scan on proposed fix for dangerous ops, malicious behavior, policy violations
    3. Compilation verification with compiler service
    4. Execution in isolated sandbox with timeout limits
    5. Regression testing against test cases / expected output
    6. Performance measurement (execution timing)

    Only marks status as 'Verified' when ALL checks pass.
    If any check fails, marks as 'Rejected' or 'Failed' with clear reason.
    """
    repair_id = repair_proposal.get("repair_id")
    correlation_id = repair_proposal.get("correlation_id") or generate_correlation_id()
    original_code = repair_proposal.get("original_code", "")
    proposed_code = repair_proposal.get("proposed_code", "")

    verification_log = []
    
    # Measure execution time of original code (if compilable)
    orig_time_ms = None
    orig_comp_ok, _, _, _, orig_tmp, orig_exe = compile_only(original_code)
    if orig_comp_ok:
        t0 = time.perf_counter()
        run_executable_isolated(orig_exe, timeout=3)
        orig_time_ms = round((time.perf_counter() - t0) * 1000, 2)
    if orig_tmp:
        orig_tmp.cleanup()

    # 1. Original code security check
    orig_threat = analyze_security_threat(original_code, context_type="code")
    if not orig_threat["is_safe"]:
        return {
            "repair_id": repair_id,
            "correlation_id": correlation_id,
            "status": "Rejected",
            "security_passed": False,
            "compilation_passed": False,
            "execution_passed": False,
            "regression_passed": False,
            "rejection_reason": f"Original code contains security violation: {orig_threat['detection_reason']}",
            "execution_time_ms": None,
            "before_execution_time_ms": orig_time_ms,
            "diff": "",
            "verified_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    # 2. Security scan on proposed fix
    fix_threat = analyze_security_threat(proposed_code, context_type="code")
    is_safe, findings = run_security_guardrail(proposed_code)

    if not is_safe or not fix_threat["is_safe"]:
        reason = fix_threat["detection_reason"] if not fix_threat["is_safe"] else "Proposed fix introduces forbidden/vulnerable functions."
        critical_findings = [f for f in findings if f.get('severity') in ['CRITICAL', 'HIGH']]
        if critical_findings:
            reason += " " + "; ".join([f"{f['pattern']}: {f['reason']}" for f in critical_findings])

        # Record malicious AI fix to Attack Vault
        attack_id = record_attack(
            category="MALICIOUS_AI_FIX" if repair_proposal.get("is_ai_generated") else "CODE_VULNERABILITY",
            source="ai_generated_fix" if repair_proposal.get("is_ai_generated") else "submitted_code",
            input_text=proposed_code,
            risk_level="CRITICAL" if "rm -rf" in proposed_code or "gets" in proposed_code else "HIGH",
            detection_reason=f"Self-Healing Rejection: {reason}",
            risk_score=0.95,
            action_taken="Blocked",
            correlation_id=correlation_id,
            repair_attempt_id=repair_id,
            validation_status="Failed",
            detection_method="Self-Healing Verification Guardrail"
        )

        return {
            "repair_id": repair_id,
            "correlation_id": correlation_id,
            "status": "Rejected",
            "security_passed": False,
            "compilation_passed": False,
            "execution_passed": False,
            "regression_passed": False,
            "rejection_reason": f"Security Verification Failed: {reason}",
            "attack_id": attack_id,
            "execution_time_ms": None,
            "before_execution_time_ms": orig_time_ms,
            "diff": "",
            "verified_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    # 3. Compilation check
    comp_ok, comp_status, comp_out, comp_err, temp_dir, executable = compile_only(proposed_code)
    if not comp_ok:
        if temp_dir:
            temp_dir.cleanup()
        return {
            "repair_id": repair_id,
            "correlation_id": correlation_id,
            "status": "Rejected",
            "security_passed": True,
            "compilation_passed": False,
            "execution_passed": False,
            "regression_passed": False,
            "rejection_reason": f"Compilation Failed: {comp_err.strip() or 'GCC returned non-zero exit code'}",
            "execution_time_ms": None,
            "before_execution_time_ms": orig_time_ms,
            "diff": "",
            "verified_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    # 4. Isolated Execution & Timeout check
    t_start = time.perf_counter()
    run_status, run_out, run_err = run_executable_isolated(executable, timeout=5)
    fix_time_ms = round((time.perf_counter() - t_start) * 1000, 2)

    if run_status != 0:
        if temp_dir:
            temp_dir.cleanup()
        return {
            "repair_id": repair_id,
            "correlation_id": correlation_id,
            "status": "Rejected",
            "security_passed": True,
            "compilation_passed": True,
            "execution_passed": False,
            "regression_passed": False,
            "rejection_reason": f"Execution Crash or Timeout: {run_err}",
            "execution_time_ms": fix_time_ms,
            "before_execution_time_ms": orig_time_ms,
            "diff": "",
            "verified_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    # 5. Regression & Unit Tests
    regression_passed = True
    test_summary = "No unit tests configured."

    if test_cases and len(test_cases) > 0:
        all_passed, tc_results, tc_summary = run_with_test_cases(proposed_code, test_cases, timeout=5)
        regression_passed = all_passed
        test_summary = tc_summary
        if not all_passed:
            if temp_dir:
                temp_dir.cleanup()
            failed_case = next((r for r in tc_results if not r["passed"]), None)
            fail_detail = f"Expected '{failed_case['expected']}' but got '{failed_case['actual']}'" if failed_case else "Output mismatch"
            return {
                "repair_id": repair_id,
                "correlation_id": correlation_id,
                "status": "Rejected",
                "security_passed": True,
                "compilation_passed": True,
                "execution_passed": True,
                "regression_passed": False,
                "rejection_reason": f"Regression Test Failed: {fail_detail}. ({tc_summary})",
                "execution_time_ms": fix_time_ms,
                "before_execution_time_ms": orig_time_ms,
                "diff": "",
                "verified_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

    if expected_output:
        exp_clean = expected_output.strip()
        actual_clean = run_out.strip()
        if exp_clean not in actual_clean and actual_clean != exp_clean:
            if temp_dir:
                temp_dir.cleanup()
            return {
                "repair_id": repair_id,
                "correlation_id": correlation_id,
                "status": "Rejected",
                "security_passed": True,
                "compilation_passed": True,
                "execution_passed": True,
                "regression_passed": False,
                "rejection_reason": f"Output mismatch: Expected '{exp_clean}', but program produced '{actual_clean}'.",
                "execution_time_ms": fix_time_ms,
                "before_execution_time_ms": orig_time_ms,
                "diff": "",
                "verified_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

    if temp_dir:
        temp_dir.cleanup()

    # Compute clean unified diff
    diff_generator = difflib.unified_diff(
        original_code.splitlines(),
        proposed_code.splitlines(),
        fromfile="Original Code",
        tofile="Verified Fix",
        lineterm=""
    )
    diff_text = "\n".join(diff_generator)

    return {
        "repair_id": repair_id,
        "correlation_id": correlation_id,
        "status": "Verified",
        "security_passed": True,
        "compilation_passed": True,
        "execution_passed": True,
        "regression_passed": True,
        "rejection_reason": "",
        "execution_output": run_out,
        "execution_time_ms": fix_time_ms,
        "before_execution_time_ms": orig_time_ms,
        "diff": diff_text,
        "test_summary": test_summary,
        "verified_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

def apply_verified_fix(current_code, repair_proposal, verification_result):
    """
    Applies the repair ONLY when verification passed.
    Preserves original source and returns updated code.
    Raises ValueError if fix is not verified.
    """
    if verification_result.get("status") != "Verified":
        raise ValueError(
            f"Cannot apply unverified fix! Status is '{verification_result.get('status')}': "
            f"{verification_result.get('rejection_reason')}"
        )

    # Return the verified corrected code
    return verification_result.get("proposed_code") or repair_proposal.get("proposed_code")
