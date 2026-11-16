import streamlit as st
import time
from self_healing_engine import (
    detect_code_errors,
    generate_repair_proposal,
    verify_repair_proposal,
    apply_verified_fix,
    generate_correlation_id,
    check_ai_service_available
)

SAMPLE_SNIPPETS = {
    "1. Missing Semicolon (Syntax Error)": """#include <iostream>
using namespace std;

int main() {
    int total_marks = 95
    cout << "Score: " << total_marks << endl;
    return 0;
}""",

    "2. Division by Zero (Arithmetic Exception)": """#include <iostream>
using namespace std;

int main() {
    int totalScore = 500;
    int numberOfStudents = 0;
    
    // Compiles, but triggers SIGFPE runtime crash
    int average = totalScore / numberOfStudents;
    cout << "Average: " << average << endl;
    return 0;
}""",

    "3. Malicious OS Command (Security Guardrail Block)": """#include <iostream>
#include <cstdlib>
using namespace std;

int main() {
    cout << "Running privileged task..." << endl;
    system("rm -rf /");
    return 0;
}""",

    "4. Banned C Buffer Overflow (Security Guardrail Block)": """#include <iostream>
using namespace std;

int main() {
    char buf[16];
    cout << "Enter your secret:" << endl;
    gets(buf); // Unbounded buffer overflow
    return 0;
}""",

    "5. Infinite Loop Timeout (Runtime Error)": """#include <iostream>
using namespace std;

int main() {
    cout << "Looping indefinitely..." << endl;
    int counter = 0;
    while(true) {
        counter++;
        // Missing break condition
    }
    return 0;
}""",

    "6. Clean & Valid C++ Code (No Repair Needed)": """#include <iostream>
using namespace std;

int main() {
    cout << "Hello from verified Samphel C++ Assistant!" << endl;
    return 0;
}"""
}

def render_self_healing_lab():
    st.title("🧪 Self-Healing Code Engine")
    st.markdown("### Autonomous C++ Error Detection, AI Repair & Multi-Stage Verification")
    st.caption("Detects syntax, runtime, semantic, and security bugs. AI proposes fixes which are strictly verified in a sandbox before acceptance.")

    # Initialize session state variables for Self-Healing Lab
    if "sh_code" not in st.session_state:
        st.session_state.sh_code = SAMPLE_SNIPPETS["1. Missing Semicolon (Syntax Error)"]
    if "sh_orig_backup" not in st.session_state:
        st.session_state.sh_orig_backup = st.session_state.sh_code
    if "sh_correlation_id" not in st.session_state:
        st.session_state.sh_correlation_id = generate_correlation_id()
    if "sh_detection" not in st.session_state:
        st.session_state.sh_detection = None
    if "sh_proposal" not in st.session_state:
        st.session_state.sh_proposal = None
    if "sh_verification" not in st.session_state:
        st.session_state.sh_verification = None
    if "sh_attempt" not in st.session_state:
        st.session_state.sh_attempt = 1
    if "sh_history" not in st.session_state:
        st.session_state.sh_history = []
    if "sh_test_input" not in st.session_state:
        st.session_state.sh_test_input = ""
    if "sh_test_expected" not in st.session_state:
        st.session_state.sh_test_expected = ""

    # Correlation ID banner
    col_corr1, col_corr2 = st.columns([3, 1])
    with col_corr1:
        st.markdown(f"🔗 **Session Correlation ID:** `{st.session_state.sh_correlation_id}`")
    with col_corr2:
        if st.button("🔄 Reset Session"):
            st.session_state.sh_correlation_id = generate_correlation_id()
            st.session_state.sh_detection = None
            st.session_state.sh_proposal = None
            st.session_state.sh_verification = None
            st.session_state.sh_attempt = 1
            st.rerun()

    st.markdown("---")

    # Sample snippet loader
    sel_sample = st.selectbox("📂 Load Sample Test Case", ["-- Select a preset snippet --"] + list(SAMPLE_SNIPPETS.keys()))
    if sel_sample != "-- Select a preset snippet --":
        if st.button(f"Load '{sel_sample}' into Editor"):
            st.session_state.sh_code = SAMPLE_SNIPPETS[sel_sample]
            st.session_state.sh_orig_backup = SAMPLE_SNIPPETS[sel_sample]
            st.session_state.sh_detection = None
            st.session_state.sh_proposal = None
            st.session_state.sh_verification = None
            st.rerun()

    # Workspace Layout: Left Column = Code Editor & Test Inputs, Right Column = Repair & Verification Status
    col_editor, col_results = st.columns([1, 1])

    with col_editor:
        st.subheader("📝 C++ Working Code")
        code_input = st.text_area(
            "C++ Source Code:",
            value=st.session_state.sh_code,
            height=320,
            key="sh_code_area"
        )
        st.session_state.sh_code = code_input

        # Optional Regression Testing Config
        with st.expander("🧪 Regression Test Suite (Optional Expected Output)", expanded=False):
            st.caption("Verify that the fixed code produces the expected output or handles specific input.")
            st.session_state.sh_test_input = st.text_input("Standard Input (stdin):", value=st.session_state.sh_test_input)
            st.session_state.sh_test_expected = st.text_input("Expected Substring in Output:", value=st.session_state.sh_test_expected)

        # Primary Action Buttons
        b_col1, b_col2, b_col3 = st.columns(3)
        with b_col1:
            detect_btn = st.button("🔍 Detect Errors", use_container_width=True, type="primary")
        with b_col2:
            fix_btn = st.button("✨ Generate Fix", use_container_width=True)
        with b_col3:
            verify_btn = st.button("🛡️ Verify Fix", use_container_width=True)

        b2_col1, b2_col2 = st.columns(2)
        with b2_col1:
            apply_btn = st.button("✅ Apply Verified Fix", use_container_width=True)
        with b2_col2:
            download_code = st.session_state.sh_proposal.get("proposed_code", "") if st.session_state.sh_proposal else st.session_state.sh_code
            st.download_button(
                "💾 Download Code",
                data=download_code,
                file_name="repaired_code.cpp",
                mime="text/x-c++src",
                use_container_width=True
            )

    # Handle Detect Action
    if detect_btn:
        with st.spinner("Analyzing code for syntax, runtime, semantic, and security errors..."):
            st.session_state.sh_detection = detect_code_errors(
                st.session_state.sh_code,
                correlation_id=st.session_state.sh_correlation_id
            )
            st.session_state.sh_proposal = None
            st.session_state.sh_verification = None

    # Handle Fix Action
    if fix_btn:
        if not st.session_state.sh_detection:
            with st.spinner("Running initial error detection first..."):
                st.session_state.sh_detection = detect_code_errors(
                    st.session_state.sh_code,
                    correlation_id=st.session_state.sh_correlation_id
                )

        with st.spinner("Generating targeted C++ repair proposal..."):
            st.session_state.sh_proposal = generate_repair_proposal(
                cpp_code=st.session_state.sh_code,
                detection_result=st.session_state.sh_detection,
                attempt_number=st.session_state.sh_attempt
            )
            st.session_state.sh_verification = None

    # Handle Verify Action
    if verify_btn:
        if not st.session_state.sh_proposal:
            st.warning("Please generate a repair proposal first before verifying.")
        else:
            with st.spinner("Executing multi-stage sandbox verification..."):
                test_cases = []
                if st.session_state.sh_test_input or st.session_state.sh_test_expected:
                    test_cases.append({
                        "input": st.session_state.sh_test_input,
                        "expected_output": st.session_state.sh_test_expected
                    })

                st.session_state.sh_verification = verify_repair_proposal(
                    repair_proposal=st.session_state.sh_proposal,
                    test_cases=test_cases if test_cases else None,
                    expected_output=st.session_state.sh_test_expected if st.session_state.sh_test_expected else None
                )

                # Add to history
                st.session_state.sh_history.append({
                    "attempt": st.session_state.sh_attempt,
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "status": st.session_state.sh_verification["status"],
                    "reason": st.session_state.sh_verification.get("rejection_reason") or "All checks passed"
                })
                st.session_state.sh_attempt += 1

    # Handle Apply Verified Fix Action
    if apply_btn:
        if not st.session_state.sh_verification:
            st.error("Cannot apply fix: Fix has not been verified yet!")
        elif st.session_state.sh_verification.get("status") != "Verified":
            st.error(f"🚫 Cannot apply unverified fix! Status is '{st.session_state.sh_verification.get('status')}'.")
        else:
            st.session_state.sh_orig_backup = st.session_state.sh_code
            updated_code = apply_verified_fix(
                st.session_state.sh_code,
                st.session_state.sh_proposal,
                st.session_state.sh_verification
            )
            st.session_state.sh_code = updated_code
            st.success("✅ Verified fix applied successfully to working code! (Original source backed up)")
            time.sleep(0.5)
            st.rerun()

    # RIGHT COLUMN: Error Diagnosis, Repair Proposal & Verification Results
    with col_results:
        st.subheader("🔍 Diagnosis & Self-Healing Pipeline")

        # 1. Detection View
        if st.session_state.sh_detection:
            det = st.session_state.sh_detection
            if not det["has_error"]:
                st.success("✅ **Clean Code:** No compilation, runtime, or security errors detected!")
            elif not det["is_safe"]:
                st.error(f"🚫 **Security Block:** {det['error_summary']}")
                st.info("The security guardrail blocked this code and logged the incident to the Attack Vault.")
            else:
                st.warning(f"⚠️ **{det['category']} Detected:** {det['error_summary']}")
                if det.get("affected_lines"):
                    st.markdown(f"**Affected Line(s):** `{det['affected_lines']}`")
                if det.get("suggestions"):
                    st.markdown(f"**Suggestion:** {det['suggestions'][0]}")

            with st.expander("View Raw Compiler / Diagnostic Output", expanded=False):
                st.code(det.get("raw_error") or "No raw error output.", language="text")
        else:
            st.info("Click **🔍 Detect Errors** to scan your code.")

        # 2. Repair Proposal View
        if st.session_state.sh_proposal:
            prop = st.session_state.sh_proposal
            st.markdown("---")
            st.subheader("💡 Proposed AI Repair")

            # Status Badge
            status = prop.get("status", "Pending")
            badge_color = "orange" if status == "Pending" else ("green" if status == "Verified" else "red")
            st.markdown(f"**Repair Status:** :{badge_color}[**{status.upper()}**] | **Attempt:** #{prop.get('attempt_number', 1)}")

            st.markdown(f"**What changed:** {prop.get('what_changed')}")
            st.markdown(f"**Why changed:** {prop.get('why_changed')}")

            # 3. Verification Checklist & Execution Results
            if st.session_state.sh_verification:
                ver = st.session_state.sh_verification
                st.markdown("---")
                st.subheader("🛡️ Multi-Stage Verification Results")

                v_status = ver["status"]
                if v_status == "Verified":
                    st.success("🎉 **VERIFIED: All security, compilation, execution, and regression tests passed!**")
                else:
                    st.error(f"❌ **REJECTED: {ver.get('rejection_reason')}**")

                # Verification Gates Checklist
                sec_icon = "✅" if ver.get("security_passed") else "❌"
                comp_icon = "✅" if ver.get("compilation_passed") else "❌"
                exe_icon = "✅" if ver.get("execution_passed") else "❌"
                reg_icon = "✅" if ver.get("regression_passed") else "❌"

                st.markdown(f"- {sec_icon} **Security Guardrail:** Safe from banned calls and policy violations")
                st.markdown(f"- {comp_icon} **Compilation Gate:** Successfully built by GCC with -g")
                st.markdown(f"- {exe_icon} **Sandbox Execution:** Executed within 5s without crashes or SegFaults")
                st.markdown(f"- {reg_icon} **Regression Tests:** Output matches expected behavior ({ver.get('test_summary', 'N/A')})")

                # Performance Timing Metrics (Before vs After)
                st.markdown("---")
                st.markdown("#### ⏱️ Performance & Timing")
                t1, t2 = st.columns(2)
                before_t = ver.get("before_execution_time_ms")
                after_t = ver.get("execution_time_ms")

                with t1:
                    st.metric("Original Runtime", f"{before_t} ms" if before_t is not None else "N/A (Failed)")
                with t2:
                    st.metric("Repaired Runtime", f"{after_t} ms" if after_t is not None else "N/A")

        # 4. Attempt History & Audit Log
        if st.session_state.sh_history:
            st.markdown("---")
            with st.expander("📋 Repair Attempt Log", expanded=False):
                for h in reversed(st.session_state.sh_history):
                    h_icon = "✅" if h["status"] == "Verified" else "❌"
                    st.markdown(f"{h_icon} **Attempt #{h['attempt']} [{h['timestamp']}]** — Status: `{h['status']}` ({h['reason']})")

    # Side-by-Side Code Comparison & Diff View (Below Workspace)
    if st.session_state.sh_proposal:
        st.markdown("---")
        st.subheader("⚖️ Side-by-Side Code Review")
        s1, s2 = st.columns(2)
        with s1:
            st.markdown("##### 📄 Original Code")
            st.code(st.session_state.sh_proposal.get("original_code", ""), language="cpp")
        with s2:
            st.markdown("##### ✨ Proposed Repair")
            st.code(st.session_state.sh_proposal.get("proposed_code", ""), language="cpp")

        with st.expander("📊 Unified Diff Inspector", expanded=True):
            if st.session_state.sh_verification and st.session_state.sh_verification.get("diff"):
                st.code(st.session_state.sh_verification["diff"], language="diff")
            else:
                import difflib
                diff = difflib.unified_diff(
                    st.session_state.sh_proposal.get("original_code", "").splitlines(),
                    st.session_state.sh_proposal.get("proposed_code", "").splitlines(),
                    fromfile="Original",
                    tofile="Proposed",
                    lineterm=""
                )
                st.code("\n".join(diff) or "No textual changes.", language="diff")
