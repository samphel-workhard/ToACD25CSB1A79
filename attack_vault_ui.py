import streamlit as st
import pandas as pd
import json
import os
from datetime import datetime
from attack_vault import (
    list_attacks,
    count_attacks,
    get_vault_summary_stats,
    update_review_status,
    export_attacks_to_json,
    export_attacks_to_csv,
    import_attack_dataset,
    get_timeline,
    get_vault_db_path
)
from security_metrics import compute_security_metrics

def render_attack_vault():
    st.title("🛡️ Attack Vault")
    st.markdown("### Dedicated Security Incident Storage, Threat Triage & Labelled Datasets")
    st.caption("Structured, persistent SQLite storage for detected prompt injections, policy bypasses, vulnerable C++ calls, and poisoned AI fixes.")

    # 1. Summary Statistics & KPI Cards
    metrics = compute_security_metrics()

    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("📊 Total Incidents", metrics["total_events"])
    m2.metric("🚫 Blocked Threats", metrics["blocked_attacks"])
    m3.metric("⚠️ Critical Events", metrics["critical_events"])
    m4.metric("⏳ Pending Reviews", metrics["pending_reviews"])
    m5.metric("🎯 Confirmed Attacks", metrics["confirmed_attacks"])
    m6.metric("🛡️ False Positives", metrics["false_positives"])

    st.markdown("---")

    # 2. Controls & Actions: Import Baseline Dataset, Export CSV / JSON
    act_col1, act_col2, act_col3, act_col4 = st.columns([2, 1.5, 1.5, 1.5])

    with act_col1:
        if st.button("📥 Import attack_dataset.json (Deduplicated)", use_container_width=True):
            dataset_file = "attack_dataset.json"
            if os.path.exists(dataset_file):
                res = import_attack_dataset(dataset_file)
                st.success(f"Dataset Imported: {res['imported']} new records added, {res['skipped_duplicates']} duplicates skipped.")
                time_sleep = True
                st.rerun()
            else:
                st.error("attack_dataset.json not found in project directory.")

    with act_col2:
        csv_data = export_attacks_to_csv()
        st.download_button(
            "📤 Export CSV",
            data=csv_data,
            file_name=f"attack_vault_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
            use_container_width=True
        )

    with act_col3:
        json_data = export_attacks_to_json()
        st.download_button(
            "📤 Export JSON",
            data=json_data,
            file_name=f"attack_vault_{datetime.now().strftime('%Y%m%d')}.json",
            mime="application/json",
            use_container_width=True
        )

    with act_col4:
        # Export only confirmed attacks as labelled evaluation dataset
        confirmed_json = export_attacks_to_json(filter_status="Confirmed attack")
        st.download_button(
            "🏷️ Export Confirmed Dataset",
            data=confirmed_json,
            file_name=f"labelled_attack_dataset_{datetime.now().strftime('%Y%m%d')}.json",
            mime="application/json",
            use_container_width=True,
            help="Exports confirmed sanitized attacks for offline model evaluation."
        )

    st.markdown("---")

    # 3. Filters & Search Section
    st.subheader("🔍 Search & Filter Security Records")
    f_col1, f_col2, f_col3, f_col4, f_col5 = st.columns(5)

    with f_col1:
        search_query = st.text_input("Search text / ID:", placeholder="e.g. system, gets, prompt...")

    with f_col2:
        category_options = ["All", "PROMPT_INJECTION", "POLICY_BYPASS", "CODE_VULNERABILITY", "MALICIOUS_AI_FIX", "SECURITY_BYPASS_ATTEMPT"]
        sel_cat = st.selectbox("Category", category_options)

    with f_col3:
        severity_options = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
        sel_sev = st.selectbox("Severity", severity_options)

    with f_col4:
        action_options = ["All", "Blocked", "Flagged", "Quarantined", "Allowed"]
        sel_act = st.selectbox("Action Taken", action_options)

    with f_col5:
        review_options = ["All", "Needs review", "Confirmed attack", "False positive"]
        sel_rev = st.selectbox("Review Status", review_options)

    # Pagination setup
    PAGE_SIZE = 15
    if "vault_page" not in st.session_state:
        st.session_state.vault_page = 0

    total_matched = count_attacks(
        category=sel_cat if sel_cat != "All" else None,
        risk_level=sel_sev if sel_sev != "All" else None,
        action_taken=sel_act if sel_act != "All" else None,
        review_status=sel_rev if sel_rev != "All" else None,
        search_query=search_query if search_query.strip() else None
    )

    records = list_attacks(
        category=sel_cat if sel_cat != "All" else None,
        risk_level=sel_sev if sel_sev != "All" else None,
        action_taken=sel_act if sel_act != "All" else None,
        review_status=sel_rev if sel_rev != "All" else None,
        search_query=search_query if search_query.strip() else None,
        limit=PAGE_SIZE,
        offset=st.session_state.vault_page * PAGE_SIZE
    )

    # 4. Display Table
    st.markdown(f"#### 📋 Vault Records ({total_matched} total matching)")

    if not records:
        st.info("No attack records found matching the current filter criteria.")
    else:
        # Build pandas DataFrame for presentation
        df = pd.DataFrame(records)
        display_cols = ["attack_id", "timestamp", "category", "risk_level", "risk_score", "action_taken", "review_status", "detection_reason"]
        
        # Color badge formatting
        st.dataframe(
            df[display_cols],
            column_config={
                "attack_id": st.column_config.TextColumn("Attack ID", width="medium"),
                "timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                "category": st.column_config.TextColumn("Category", width="medium"),
                "risk_level": st.column_config.TextColumn("Severity", width="small"),
                "risk_score": st.column_config.NumberColumn("Risk Score", format="%.2f", width="small"),
                "action_taken": st.column_config.TextColumn("Action", width="small"),
                "review_status": st.column_config.TextColumn("Disposition", width="medium"),
                "detection_reason": st.column_config.TextColumn("Reason", width="large"),
            },
            use_container_width=True,
            hide_index=True
        )

        # Pagination controls
        p_col1, p_col2, p_col3 = st.columns([1, 2, 1])
        with p_col1:
            if st.session_state.vault_page > 0:
                if st.button("⬅️ Previous Page"):
                    st.session_state.vault_page -= 1
                    st.rerun()
        with p_col2:
            max_pages = max(1, (total_matched + PAGE_SIZE - 1) // PAGE_SIZE)
            st.markdown(f"<center>Page {st.session_state.vault_page + 1} of {max_pages}</center>", unsafe_allow_html=True)
        with p_col3:
            if (st.session_state.vault_page + 1) * PAGE_SIZE < total_matched:
                if st.button("Next Page ➡️"):
                    st.session_state.vault_page += 1
                    st.rerun()

    # 5. Record Inspector & Review Workflow
    st.markdown("---")
    st.subheader("🔬 Record Inspector & Analyst Review")

    if records:
        attack_options = [f"{r['attack_id']} | [{r['risk_level']}] {r['category']} - {r['detection_reason'][:40]}..." for r in records]
        sel_record_str = st.selectbox("Select Record to Inspect & Review:", attack_options)
        sel_attack_id = sel_record_str.split(" | ")[0]
        selected_record = next((r for r in records if r["attack_id"] == sel_attack_id), None)

        if selected_record:
            r1, r2 = st.columns([1, 1])

            with r1:
                st.markdown("#### 📄 Incident Details")
                st.markdown(f"- **Attack ID:** `{selected_record['attack_id']}`")
                st.markdown(f"- **Timestamp:** `{selected_record['timestamp']}`")
                st.markdown(f"- **Category:** `{selected_record['category']}`")
                st.markdown(f"- **Source:** `{selected_record['source']}`")
                st.markdown(f"- **Severity:** `{selected_record['risk_level']}` | **Risk Score:** `{selected_record['risk_score'] if selected_record['risk_score'] is not None else 'N/A'}`")
                st.markdown(f"- **Action Taken:** `{selected_record['action_taken']}`")
                st.markdown(f"- **Detection Method:** `{selected_record['detection_method']}`")
                st.markdown(f"- **Correlation ID:** `{selected_record['correlation_id'] or 'None'}`")
                st.markdown(f"- **Related Repair ID:** `{selected_record['repair_attempt_id'] or 'None'}`")
                st.markdown(f"- **Reason:** {selected_record['detection_reason']}")

                st.markdown("##### 🛡️ Sanitized Input Excerpt (Safe View)")
                st.code(selected_record["sanitized_input"], language="text")

            with r2:
                st.markdown("#### ✍️ Analyst Review & Triage")
                current_status = selected_record["review_status"]
                st.markdown(f"**Current Disposition:** `{current_status}`")

                new_status = st.radio(
                    "Set Review Disposition:",
                    ["Needs review", "Confirmed attack", "False positive"],
                    index=["Needs review", "Confirmed attack", "False positive"].index(current_status) if current_status in ["Needs review", "Confirmed attack", "False positive"] else 0
                )

                analyst_notes = st.text_area(
                    "Analyst Notes & Assessment:",
                    value=selected_record.get("analyst_notes") or "",
                    height=120
                )

                if st.button("💾 Save Review Decision", type="primary"):
                    updated = update_review_status(
                        attack_id=selected_record["attack_id"],
                        review_status=new_status,
                        analyst_notes=analyst_notes
                    )
                    if updated:
                        st.success(f"Review saved: Record marked as '{new_status}'.")
                        st.rerun()
                    else:
                        st.error("Failed to save review status.")

            # Timeline of Related Events
            st.markdown("---")
            st.markdown("#### ⏳ Timeline of Correlated Events")
            corr_id = selected_record.get("correlation_id")
            timeline = get_timeline(correlation_id=corr_id if corr_id else None, limit=10)
            if timeline:
                for t in timeline:
                    t_icon = "🚫" if t["action_taken"] == "Blocked" else "✅"
                    st.markdown(f"{t_icon} `[{t['timestamp']}]` **{t['category']}** ({t['risk_level']}) — Action: `{t['action_taken']}` | *{t['detection_reason']}*")
            else:
                st.caption("No additional correlated security events recorded for this session.")
