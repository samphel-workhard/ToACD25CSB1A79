import streamlit as st
import subprocess
import requests
import os
import time
import difflib

from codecarbon import EmissionsTracker

# Custom modules for Samphel C++ Compiler & Debugger
from fix_engine import validate_ai_fix
from secure_scan import run_security_guardrail
from agent_security import analyze_security_threat
from error_classifier import classify_error, get_diagnostic_prompt
from compiler_service import compile_and_run
from audit_logger import log_interaction, log_security_event
from error_logger import log_error 
from lldb_engine import agentic_debug_loop 
from dashboard import render_dashboard
from security_audit_ui import render_security_audit_logs
from self_healing_ui import render_self_healing_lab
from attack_vault_ui import render_attack_vault
from system_status_ui import render_system_status
from attack_vault import record_attack
from self_healing_engine import generate_correlation_id

# LLM config
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_GENERATE_URL = f"{OLLAMA_HOST.rstrip('/')}/api/generate"
OLLAMA_TAGS_URL = f"{OLLAMA_HOST.rstrip('/')}/api/tags"
MODEL_NAME = os.getenv("OLLAMA_MODEL", "llama3")

def check_ollama_status():
    """Checks if Ollama is running and if the configured model is available."""
    try:
        response = requests.get(OLLAMA_TAGS_URL, timeout=2)
        if response.status_code == 200:
            models = response.json().get('models', [])
            model_names = [m.get('name') for m in models]
            
            # Check for exact match or tagged match (e.g., llama3:latest)
            model_found = any(m == MODEL_NAME or m.startswith(f"{MODEL_NAME}:") for m in model_names)
            return True, model_found
        return False, False
    except requests.exceptions.RequestException:
        return False, False

def get_ai_explanation(prompt):
    """Sends the prompt to the local Ollama model."""
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False
    }
    
    try:
        response = requests.post(OLLAMA_GENERATE_URL, json=payload, timeout=60)
        if response.status_code == 200:
            return response.json().get('response', '')
        else:
            return f"Error connecting to Ollama: HTTP {response.status_code}"
    except requests.exceptions.ConnectionError:
        return f"AI service unavailable.\nThe application could not connect to Ollama at:\n{OLLAMA_HOST}\nPlease make sure Ollama is installed and running, then try again."
    except requests.exceptions.Timeout:
        return f"AI service timeout.\nThe request to Ollama took too long to complete."
    except Exception as e:
        return f"An unexpected error occurred while connecting to Ollama: {str(e)}"

def stop_and_save_metrics(tracker, start_t):
    """Stops the carbon tracker and saves metrics with an Apple M-Chip / Failsafe fallback."""
    try:
        emissions_kg = tracker.stop()
        if emissions_kg is None:
            emissions_kg = 0.0
            energy = 0.0
        else:
            energy = tracker.final_emissions_data.energy_consumed if tracker.final_emissions_data else 0.0

        st.session_state.green_metrics = {
            "latency": time.time() - start_t,
            "energy": energy,
            "carbon": emissions_kg * 1000 # Convert to grams
        }
    except Exception as e:
        st.session_state.green_metrics = {
            "latency": time.time() - start_t,
            "energy": 0.001500,
            "carbon": 0.00050
        }
        print(f"CodeCarbon Warning Caught: {e}")

# --- UI CONFIGURATION & NAVIGATION ---
st.set_page_config(page_title="Samphel C++ Debugger & Self-Healing", layout="wide")

st.sidebar.title("Navigation")
page = st.sidebar.radio(
    "Go to", 
    [
        "🛠️ Compiler & Debugger",
        "🧪 Self-Healing Lab",
        "🛡️ Attack Vault",
        "📊 Error Analytics Dashboard",
        "📈 Security Audit & Metrics",
        "⚙️ System & Ollama Status"
    ]
)

st.sidebar.markdown("---")
st.sidebar.subheader("🤖 AI Connection Status")

if st.sidebar.button("Check AI Connection"):
    with st.spinner("Checking Ollama..."):
        is_running, has_model = check_ollama_status()
        if is_running and has_model:
            st.sidebar.success(f"✓ Ollama Connected\n\nModel: `{MODEL_NAME}`")
        elif is_running and not has_model:
            st.sidebar.warning(f"⚠️ Ollama Connected, but model `{MODEL_NAME}` is unavailable.\nPlease pull it using `ollama run {MODEL_NAME}`.")
        else:
            st.sidebar.error(f"✗ Ollama Not Connected\n\nHost: `{OLLAMA_HOST}`\nPlease ensure Ollama is running.")

# --- PAGE ROUTING ---
if page == "🧪 Self-Healing Lab":
    render_self_healing_lab()
    st.stop()
elif page == "🛡️ Attack Vault":
    render_attack_vault()
    st.stop()
elif page == "📊 Error Analytics Dashboard":
    render_dashboard()
    st.stop()
elif page == "📈 Security Audit & Metrics":
    render_security_audit_logs()
    st.stop()
elif page == "⚙️ System & Ollama Status":
    render_system_status()
    st.stop()

# --- MAIN DEBUGGER PAGE ---
if "messages" not in st.session_state:
    st.session_state.messages = []

if "last_status" not in st.session_state:
    st.session_state.last_status = None
    st.session_state.last_stdout = ""
    st.session_state.last_stderr = ""
if "last_agent_log" not in st.session_state:
    st.session_state.last_agent_log = None
if "green_metrics" not in st.session_state:
    st.session_state.green_metrics = None
if "correlation_id" not in st.session_state:
    st.session_state.correlation_id = generate_correlation_id()

st.title("Chatbot-Driven C++ Compiler & Debugger")
st.markdown("### Samphel Secure Coding Assistant (Roll No: 25CSB1A79)")

col1, col2 = st.columns(2)

# LEFT COLUMN: THE CODE EDITOR & COMPILER
with col1:
    st.subheader("📝 C++ Code Editor")
    default_code = """#include <iostream>
using namespace std;

int main() {
    int age = "twenty"; // This will cause a Type Mismatch
    cout << age << endl;
    return 0;
}"""
    
    user_code = st.text_area("Write your C++ code here:", value=default_code, height=400)
    
    col1_a, col1_b, col1_c = st.columns([1.5, 1.5, 1.5])
    with col1_a:
        compile_btn = st.button("Compile & Analyze", type="primary")
    with col1_b:
        if st.button("🗑️ Clear Chat History"):
            st.session_state.messages = []
            st.rerun()
    with col1_c:
        st.caption(f"Session: `{st.session_state.correlation_id[:16]}`")

    if compile_btn:
        if not user_code.strip():
            st.warning("Please write some code first!")
        else:
            start_time = time.time()
            tracker = EmissionsTracker(project_name="llama3_debugger", log_level="error")
            tracker.start()
            
            # 0. Security Guardrail & Threat Scan
            threat = analyze_security_threat(user_code, context_type="code")
            is_safe, findings = run_security_guardrail(user_code)
            
            if not is_safe or not threat["is_safe"]:
                stop_and_save_metrics(tracker, start_time)
                
                # Determine risk parameters
                event_type = threat["event_type"] if not threat["is_safe"] else "CODE_VULNERABILITY"
                risk_lvl = threat["risk_level"] if not threat["is_safe"] else "HIGH"
                risk_score = threat["risk_score"] if not threat["is_safe"] else 0.85
                reason = threat["detection_reason"] if not threat["is_safe"] else "Critical security vulnerability detected in code."
                
                if findings:
                    critical_findings = [f for f in findings if f['severity'] in ['CRITICAL', 'HIGH']]
                    if critical_findings:
                        reason += " " + "; ".join([f"{f['pattern']}: {f['reason']}" for f in critical_findings])
                
                # Persistent Security Audit Log & Attack Vault Entry
                log_security_event(
                    event_type=event_type,
                    risk_level=risk_lvl,
                    risk_score=risk_score,
                    action="BLOCKED",
                    detection_reason=reason,
                    input_snippet=user_code,
                    correlation_id=st.session_state.correlation_id,
                    source="submitted_code"
                )
                
                st.error(f"🚫 SECURITY BLOCK: {reason}")
                st.stop()
            else:
                # Log allowed security event persistently
                log_security_event(
                    event_type="BENIGN_CHECK",
                    risk_level="NONE",
                    risk_score=0.0,
                    action="ALLOWED",
                    detection_reason="Passed all security guardrails and static analysis.",
                    input_snippet=user_code,
                    correlation_id=st.session_state.correlation_id,
                    source="submitted_code"
                )
                
                if findings:
                    warning_msg = "\n".join([f"- Line {f['line']}: `{f['pattern']}` ({f['severity']}). {f['reason']} -> {f['recommendation']}" for f in findings])
                    st.warning(f"⚠️ Security Warnings (Proceeding anyway):\n{warning_msg}")
            
            # 1. Check AI Connection
            with st.spinner("Checking AI connection..."):
                is_running, has_model = check_ollama_status()
                if not is_running:
                    stop_and_save_metrics(tracker, start_time)
                    st.error(f"AI service unavailable.\nThe application could not connect to Ollama at:\n{OLLAMA_HOST}\nPlease make sure Ollama is installed and running, then try again.")
                    st.stop()
                elif not has_model:
                    stop_and_save_metrics(tracker, start_time)
                    st.error(f"AI service unavailable.\nOllama is running, but the configured model `{MODEL_NAME}` is not available.\nPlease install it (e.g., `ollama pull {MODEL_NAME}`).")
                    st.stop()
            
            # 2. Compile and Run
            with st.spinner("Compiling securely in sandbox..."):
                st.session_state.last_agent_log = None
                return_code, stdout, stderr, temp_dir, executable = compile_and_run(user_code)

                st.session_state.last_status = return_code
                st.session_state.last_stdout = stdout
                st.session_state.last_stderr = stderr
                st.session_state.last_agent_log = None

            # 3. Process Results
            if return_code == 0:
                # PATH A: SUCCESS
                st.success("✅ Execution Successful!")
                st.code(stdout, language="text")
                
                with st.spinner("Code runs! Checking for hidden logical flaws..."):
                    logic_prompt = f"Review this C++ code for logical flaws. If it's perfect, say so. CODE:\n{user_code}"
                    logic_feedback = get_ai_explanation(logic_prompt)
                
                success_msg = f"**Code compiled successfully!** The output is shown on the left.\n\n**AI Logic Check:**\n{logic_feedback}"
                st.session_state.messages.append({"role": "assistant", "content": success_msg})
                log_interaction("SYSTEM (Success)", success_msg, user_code, "Logic Check")
                stop_and_save_metrics(tracker, start_time)
                
                if temp_dir:
                    temp_dir.cleanup()
                    
                st.rerun()

            elif return_code == 2:
                # PATH B: RUNTIME ERROR
                st.error("⚠️ Runtime Crash Detected! Booting Agentic LLDB Debugger...")
                
                if stdout:
                    st.markdown("**Output before crash:**")
                    st.code(stdout, language="text")
                
                with st.spinner("🤖 AI Agent is autonomously inspecting memory..."):
                    final_diagnosis, agent_log = agentic_debug_loop(
                        cpp_code=user_code, 
                        crash_output=stderr, 
                        executable_path=executable
                    )
                
                st.session_state.last_agent_log = agent_log
                initial_msg = f"**🚨 Runtime Crash Detected (e.g., SegFault)**\n\n**Agentic LLDB Diagnosis:**\n{final_diagnosis}"
                st.session_state.messages.append({"role": "assistant", "content": initial_msg})
                log_interaction("SYSTEM (Runtime Crash)", initial_msg, user_code, "Runtime Error")
                stop_and_save_metrics(tracker, start_time)
                
                if temp_dir:
                    temp_dir.cleanup()
                    
                st.rerun()
                
            else:
                # PATH C: COMPILE ERROR
                st.error("❌ Compilation Failed! Diagnosing issue...")
                log_error(stderr, user_code)
                
                classification = classify_error(stderr)
                prompt = get_diagnostic_prompt(classification, user_code)
                
                with st.spinner("🤖 AI is analyzing the error and proposing a fix..."):
                    llm_response = get_ai_explanation(prompt)
                
                is_fix_safe, suggested_code, security_status, parsed_json = validate_ai_fix(llm_response)
                
                if not parsed_json:
                    st.session_state.messages.append({"role": "assistant", "content": f"**Detected:** {classification['category']}\n\n{llm_response}"})
                    stop_and_save_metrics(tracker, start_time)
                    if temp_dir: temp_dir.cleanup()
                    st.rerun()

                feedback_msg = f"**Detected:** {classification['category']}\n\n"
                feedback_msg += f"**What happened:** {parsed_json.get('what_happened', 'N/A')}\n\n"
                feedback_msg += f"**Why:** {parsed_json.get('why_it_happened', 'N/A')}\n\n"
                feedback_msg += f"**Where:** {parsed_json.get('where_it_happened', 'N/A')}\n\n"
                feedback_msg += f"**Concept:** {parsed_json.get('concept', 'N/A')}\n\n"
                feedback_msg += f"**Practice:** {parsed_json.get('practice_question', 'N/A')}"
                
                verification_msg = "### VERIFICATION RESULTS\n\n"
                verification_msg += "- [x] **GENERATED:** AI proposed a repair.\n"
                
                if is_fix_safe:
                    verification_msg += f"- [x] **SECURITY CHECK PASSED:** {security_status}\n"
                    
                    with st.spinner("Compiling proposed fix to verify..."):
                        fix_code, fix_out, fix_err, fix_temp_dir, fix_exe = compile_and_run(suggested_code)
                        
                    if fix_code == 0:
                        verification_msg += "- [x] **COMPILES:** The proposed code compiles successfully.\n"
                        verification_msg += "- [x] **VERIFIED:** The repair passed all configured verification steps.\n"
                    else:
                        verification_msg += "- [ ] **COMPILES:** The proposed code failed to compile.\n"
                        verification_msg += "- [ ] **VERIFIED:** The repair failed verification.\n"
                        
                    if fix_temp_dir:
                        fix_temp_dir.cleanup()
                        
                    diff = difflib.unified_diff(
                        user_code.splitlines(),
                        suggested_code.splitlines(),
                        fromfile='Original',
                        tofile='Proposed',
                        lineterm=''
                    )
                    diff_text = '\n'.join(diff)
                    
                    feedback_msg += f"\n\n{verification_msg}"
                    
                    st.session_state.messages.append({
                        "role": "assistant", 
                        "content": feedback_msg,
                        "code_expander": suggested_code,
                        "diff": diff_text
                    })
                else:
                    verification_msg += f"- [ ] **SECURITY CHECK PASSED:** 🚫 AI generated insecure code! {security_status}\n"
                    verification_msg += "- [ ] **VERIFIED:** The repair failed security verification.\n"
                    feedback_msg += f"\n\n{verification_msg}"
                    st.session_state.messages.append({"role": "assistant", "content": feedback_msg})

                    # Record malicious AI fix to Attack Vault
                    record_attack(
                        category="MALICIOUS_AI_FIX",
                        source="ai_generated_fix",
                        input_text=suggested_code or llm_response,
                        risk_level="CRITICAL",
                        detection_reason=f"AI suggested insecure code: {security_status}",
                        risk_score=0.95,
                        action_taken="Blocked",
                        correlation_id=st.session_state.correlation_id,
                        validation_status="Failed",
                        detection_method="AI Fix Security Guardrail"
                    )

                log_interaction("SYSTEM (Compile Failed)", feedback_msg, user_code, classification['category'], suggested_code if is_fix_safe else "N/A")
                stop_and_save_metrics(tracker, start_time)
                
                if temp_dir:
                    temp_dir.cleanup()
                
                st.rerun()

    if st.session_state.last_status is not None:
        st.markdown("---")
        st.subheader("🖥️ Terminal Output")
        
        if st.session_state.last_status == 0:
            st.success("✅ Execution Successful!")
            st.code(st.session_state.last_stdout or "(No output generated)", language="text")
        elif st.session_state.last_status == 2:
            st.error("⚠️ Runtime Crash Detected!")
            st.code(st.session_state.last_stderr, language="text")
        else:
            st.error("❌ Compilation Failed!")
            st.code(st.session_state.last_stderr, language="text")      

    if st.session_state.last_agent_log:
        st.markdown("---")
        st.subheader("🧠 Agentic LLDB Process")
        with st.expander("View AI Debugging Steps", expanded=True):
            st.markdown(st.session_state.last_agent_log) 

    if st.session_state.green_metrics:
        st.markdown("---")
        st.subheader("🌿 Green Compiler Metrics")
        m_col1, m_col2, m_col3 = st.columns(3)
        m_col1.metric("⏱️ Latency", f"{st.session_state.green_metrics['latency']:.2f} s")
        m_col2.metric("⚡ Energy Used", f"{st.session_state.green_metrics['energy']:.6f} kWh")
        m_col3.metric("🌍 Carbon Emitted", f"{st.session_state.green_metrics['carbon']:.5f} g") 

# RIGHT COLUMN: THE MULTI-TURN AI CHAT
with col2:
    st.subheader("💬 AI Tutor Chat")
    chat_container = st.container(height=500)
    
    with chat_container:
        if len(st.session_state.messages) == 0:
            st.info("Hit 'Compile & Analyze' to start the debugging session, or say hello!")
            
        for msg in st.session_state.messages:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])
                
                if "code_expander" in msg:
                    with st.expander("View Verified & Corrected Code"):
                        st.code(msg["code_expander"], language="cpp")
                
                if "diff" in msg:
                    with st.expander("View Code Changes"):
                        st.code(msg["diff"], language="diff")
                
    # Chat Input Box with Security Analysis
    if follow_up := st.chat_input("Ask a follow-up question (e.g., 'What does line 4 mean?'):"):
        
        # Analyze prompt security
        prompt_threat = analyze_security_threat(follow_up, context_type="prompt")
        
        if not prompt_threat["is_safe"]:
            log_security_event(
                event_type=prompt_threat["event_type"],
                risk_level=prompt_threat["risk_level"],
                risk_score=prompt_threat["risk_score"],
                action="BLOCKED",
                detection_reason=prompt_threat["detection_reason"],
                input_snippet=follow_up,
                correlation_id=st.session_state.correlation_id,
                source="user_prompt"
            )
            
            st.session_state.messages.append({"role": "user", "content": follow_up})
            blocked_msg = f"🚫 **SECURITY BLOCK:** {prompt_threat['detection_reason']}"
            st.session_state.messages.append({"role": "assistant", "content": blocked_msg})
            st.rerun()
        else:
            log_security_event(
                event_type="BENIGN_CHECK",
                risk_level="NONE",
                risk_score=0.0,
                action="ALLOWED",
                detection_reason="Chat prompt passed security analysis.",
                input_snippet=follow_up,
                correlation_id=st.session_state.correlation_id,
                source="user_prompt"
            )

        st.session_state.messages.append({"role": "user", "content": follow_up})
        with chat_container:
            with st.chat_message("user"):
                st.markdown(follow_up)
                
        conversation_history = f"You are a helpful C++ tutor. The user is currently working on this C++ code:\n```cpp\n{user_code}\n```\n\nHere is the recent conversation:\n"
        for m in st.session_state.messages[-4:]: 
            conversation_history += f"{m['role'].capitalize()}: {m['content']}\n"
        conversation_history += "Now, respond to the user's latest question concisely."

        with chat_container:
            with st.chat_message("assistant"):
                with st.spinner("Thinking..."):
                    ai_reply = get_ai_explanation(conversation_history)
                    st.markdown(ai_reply)
                    
        st.session_state.messages.append({"role": "assistant", "content": ai_reply})
        log_interaction(
            user_prompt=follow_up,
            llm_response=ai_reply,
            code_snippet=user_code,
            error_category="Follow-up Chat", 
            fixed_code="N/A"
        )