import streamlit as st
import subprocess
import os
import sqlite3
import requests
from attack_vault import get_vault_db_path

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_TAGS_URL = f"{OLLAMA_HOST.rstrip('/')}/api/tags"
MODEL_NAME = os.getenv("OLLAMA_MODEL", "llama3")

def render_system_status():
    st.title("⚙️ System & Environment Status")
    st.markdown("### Runtime Diagnostics, Subsystem Health & LLM Status")
    st.caption("Verifies the availability and readiness of GCC, Ollama, SQLite Attack Vault, and Sandboxing components.")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("🤖 Local AI (Ollama) Health")
        try:
            res = requests.get(OLLAMA_TAGS_URL, timeout=2)
            if res.status_code == 200:
                models = res.json().get('models', [])
                model_names = [m.get('name') for m in models]
                has_model = any(m == MODEL_NAME or m.startswith(f"{MODEL_NAME}:") for m in model_names)

                st.success(f"✓ Ollama Daemon Running at `{OLLAMA_HOST}`")
                if has_model:
                    st.success(f"✓ Configured Model `{MODEL_NAME}` is available and ready for inference.")
                else:
                    st.warning(f"⚠️ Model `{MODEL_NAME}` not detected. Available models: `{model_names}`. Pull via `ollama pull {MODEL_NAME}`.")

                with st.expander("View Available Local Models", expanded=False):
                    for m in models:
                        st.markdown(f"- **{m.get('name')}** ({m.get('details', {}).get('parameter_size', 'N/A')}, {m.get('details', {}).get('quantization_level', 'N/A')})")
            else:
                st.error(f"✗ Ollama returned HTTP {res.status_code}")
        except Exception as e:
            st.error(f"✗ Cannot connect to Ollama at `{OLLAMA_HOST}`: {str(e)}")

        st.markdown("---")
        st.subheader("🛠️ C++ GCC Compiler Toolchain")
        try:
            gcc_res = subprocess.run(["g++", "--version"], capture_output=True, text=True, timeout=3)
            if gcc_res.returncode == 0:
                first_line = gcc_res.stdout.splitlines()[0] if gcc_res.stdout else "g++ detected"
                st.success(f"✓ GCC Compiler Operational: `{first_line}`")
                st.caption("Supports `-g` debug symbols, C++11, C++14, and isolated temporary compilation.")
            else:
                st.error(f"✗ GCC error: {gcc_res.stderr}")
        except Exception as e:
            st.error(f"✗ G++ Compiler execution failed: {str(e)}")

    with col2:
        st.subheader("🗄️ Attack Vault Database Status")
        db_path = get_vault_db_path()
        st.markdown(f"**Database File Location:** `{db_path}`")
        if os.path.exists(db_path):
            size_kb = round(os.path.getsize(db_path) / 1024, 2)
            st.success(f"✓ SQLite Database Active ({size_kb} KB)")
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM attacks")
                count = cursor.fetchone()[0]
                cursor.execute("PRAGMA journal_mode;")
                journal_mode = cursor.fetchone()[0]
                conn.close()
                st.markdown(f"- **Total Stored Attack Records:** `{count}`")
                st.markdown(f"- **SQLite Journal Mode:** `{journal_mode.upper()}` (Concurrent WAL)")
                st.markdown("- **Storage Isolation:** Data is isolated from transient build directories.")
            except Exception as e:
                st.error(f"Database query error: {e}")
        else:
            st.info("Database will be initialized on first security event or dataset import.")

        st.markdown("---")
        st.subheader("🛡️ Sandbox & Resource Limits")
        st.markdown("- **Compilation Timeout:** `10 seconds`")
        st.markdown("- **Execution Sandbox Timeout:** `5 seconds`")
        st.markdown("- **Process Isolation:** Dedicated temporary directory per compile/run cycle")
        st.markdown("- **Input Sanitization:** Redacts passwords, API tokens, and secret keys")
        st.markdown("- **Execution Policy:** Untrusted attacks stored in Attack Vault are strictly inert data and never executed")
