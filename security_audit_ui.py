import streamlit as st
import pandas as pd
from audit_logger import get_security_logs, clear_security_logs
from security_metrics import compute_security_metrics

def render_security_audit_logs():
    st.title("🛡️ Security Audit & Metrics")
    st.markdown("### Real-Time Security Incident & Guardrail Monitoring")
    st.caption("Tracks all prompt injections, policy bypasses, and security guardrail decisions persistently.")

    tab_logs, tab_metrics = st.tabs(["📋 Security Audit Logs", "📈 Security Posture Metrics"])

    with tab_metrics:
        st.subheader("📊 High-Level Threat Posture Analysis")
        metrics = compute_security_metrics()

        sm1, sm2, sm3, sm4 = st.columns(4)
        sm1.metric("Total Events Logged", metrics["total_events"])
        sm2.metric("Threat Block Rate", f"{metrics['block_rate_percent']}%")
        sm3.metric("Critical Threat Rate", f"{metrics['critical_rate_percent']}%")
        sm4.metric("Avg Risk Score", f"{metrics['avg_risk_score']}" if metrics["avg_risk_score"] is not None else "N/A")

        st.markdown("---")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("##### Threat Events by Category")
            if metrics["by_category"]:
                cat_df = pd.DataFrame(list(metrics["by_category"].items()), columns=["Category", "Count"]).set_index("Category")
                st.bar_chart(cat_df)
            else:
                st.info("No categorical threat data recorded yet.")

        with c2:
            st.markdown("##### Threat Events by Severity")
            if metrics["by_severity"]:
                sev_df = pd.DataFrame(list(metrics["by_severity"].items()), columns=["Severity", "Count"]).set_index("Severity")
                st.bar_chart(sev_df)
            else:
                st.info("No severity distribution recorded yet.")

        st.markdown("---")
        st.markdown("##### 🔬 Triage & Self-Healing Defense Performance")
        k1, k2, k3 = st.columns(3)
        k1.metric("Confirmed Malicious Attacks", metrics["confirmed_attacks"])
        k2.metric("Confirmed False Positives", metrics["false_positives"])
        k3.metric("Malicious AI Fixes Blocked", metrics["ai_fixes_blocked"])

    with tab_logs:
        # 1. Fetch persistent logs
        raw_logs = get_security_logs()

        # 2. Control Row (Refresh & Clear Logs)
        c1, c2, c3 = st.columns([2, 2, 4])
        with c1:
            if st.button("🔄 Refresh Logs", type="secondary"):
                st.rerun()
        with c2:
            if "confirm_clear" not in st.session_state:
                st.session_state.confirm_clear = False

            if not st.session_state.confirm_clear:
                if st.button("🗑️ Clear Logs", type="secondary"):
                    st.session_state.confirm_clear = True
                    st.rerun()
            else:
                if st.button("⚠️ Confirm Clear All", type="primary"):
                    clear_security_logs()
                    st.session_state.confirm_clear = False
                    st.success("Security audit logs cleared successfully.")
                    st.rerun()

        # Check if empty
        if not raw_logs:
            st.markdown("---")
            st.info("ℹ️ No security audit records found. All security events will be logged automatically here.")
            return

        df = pd.DataFrame(raw_logs)

        # Ensure required columns exist
        expected_cols = ["timestamp", "event_type", "risk_level", "risk_score", "action", "detection_reason", "input_snippet"]
        for col in expected_cols:
            if col not in df.columns:
                df[col] = "N/A"

        # Fill NaN values with N/A
        df = df.fillna("N/A")

        # 3. Overview Metrics
        st.markdown("---")
        m1, m2, m3, m4 = st.columns(4)
        total_events = len(df)
        blocked_count = len(df[df["action"] == "BLOCKED"])
        allowed_count = len(df[df["action"] == "ALLOWED"])
        high_critical_count = len(df[df["risk_level"].isin(["HIGH", "CRITICAL"])])

        m1.metric("📊 Total Security Events", total_events)
        m2.metric("🚫 Blocked Threats", blocked_count)
        m3.metric("✅ Allowed Checks", allowed_count)
        m4.metric("⚠️ High/Critical Risk", high_critical_count)

        # 4. Filters Section
        st.markdown("---")
        st.subheader("🔍 Filter Audit Logs")
        f1, f2, f3 = st.columns(3)

        event_types = ["All"] + sorted(list(df["event_type"].unique()))
        risk_levels = ["All"] + sorted(list(df["risk_level"].unique()))
        actions = ["All"] + sorted(list(df["action"].unique()))

        with f1:
            sel_event_type = st.selectbox("Event Type", event_types)
        with f2:
            sel_risk_level = st.selectbox("Risk Level", risk_levels)
        with f3:
            sel_action = st.selectbox("Action Taken", actions)

        # Filter dataframe
        filtered_df = df.copy()
        if sel_event_type != "All":
            filtered_df = filtered_df[filtered_df["event_type"] == sel_event_type]
        if sel_risk_level != "All":
            filtered_df = filtered_df[filtered_df["risk_level"] == sel_risk_level]
        if sel_action != "All":
            filtered_df = filtered_df[filtered_df["action"] == sel_action]

        st.markdown("---")
        st.subheader(f"📋 Recorded Security Audit Events ({len(filtered_df)} items)")

        if filtered_df.empty:
            st.info("No security audit records match the selected filter criteria.")
            return

        # Sort reverse chronological (newest first)
        display_df = filtered_df.iloc[::-1]

        # Format and display in structured table view
        st.dataframe(
            display_df,
            column_config={
                "timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                "event_type": st.column_config.TextColumn("Event Type", width="medium"),
                "risk_level": st.column_config.TextColumn("Risk Level", width="small"),
                "risk_score": st.column_config.TextColumn("Risk Score", width="small"),
                "action": st.column_config.TextColumn("Action", width="small"),
                "detection_reason": st.column_config.TextColumn("Detection Reason", width="large"),
                "input_snippet": st.column_config.TextColumn("Snippet", width="medium"),
            },
            use_container_width=True,
            hide_index=True
        )

        # Expander detailed view for each record
        with st.expander("🔍 Detailed Log Event Inspector", expanded=False):
            for idx, row in display_df.head(15).iterrows():
                action_icon = "🚫" if row["action"] == "BLOCKED" else "✅"
                st.markdown(f"#### {action_icon} [{row['timestamp']}] {row['event_type']} - Action: `{row['action']}`")
                st.markdown(f"- **Risk Level:** `{row['risk_level']}` | **Risk Score:** `{row['risk_score']}`")
                st.markdown(f"- **Reason:** {row['detection_reason']}")
                st.code(row['input_snippet'], language="text")
                st.markdown("---")
