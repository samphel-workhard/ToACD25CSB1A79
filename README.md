# Samphel — Agentic AI Security and Self-Healing C++ Compiler Debugger

An Agentic Automated Program Repair (APR) and Security Engineering platform designed for safe C++ code diagnosis, self-healing code repair, real-time threat detection, and persistent security incident analytics.

---

## 🌟 Overview & New Features

### 1. 🧪 Self-Healing Code Engine (`Self-Healing Lab`)
The Self-Healing Code Engine autonomously identifies, repairs, verifies, and applies targeted corrections for C++ programs without unrestricted execution access:
* **Automatic Error Detection:** Integrates GCC compiler diagnostics, isolated sandbox execution, and the `semantic_analyzer.py` engine to detect syntax errors, linker failures, type mismatches, runtime crashes (SegFaults, arithmetic exceptions), and logic/semantic bugs (division by zero, infinite loops, null pointer dereferences, array out-of-bounds).
* **AI-Assisted Program Repair:** Leverages local LLMs (via Ollama Llama 3) along with deterministic rule fallbacks to produce minimal, intent-preserving corrections.
* **Multi-Stage Verification Pipeline:**
  1. **Pre-Scan:** Validates the original code for banned functions and prompt injections.
  2. **Security Gate:** Scans proposed fixes for banned calls (`gets`, `strcpy`, `system`, `popen`, `exec`) or jailbreak constructs.
  3. **Compilation Gate:** Compiles the proposed fix in an isolated temporary sandbox with GCC `-g`.
  4. **Sandbox Execution Gate:** Executes the compiled binary under strict resource limits and a 5-second timeout.
  5. **Regression & Test Gate:** Evaluates output against user-specified test cases or expected substrings.
  6. **Timing Benchmark:** Reliably records before-and-after execution latency.
* **Safe Application:** The "Apply Verified Fix" button only accepts repairs that have passed all verification gates, backing up the original source and providing an interactive side-by-side unified diff view.

### 2. 🛡️ Attack Vault (`Attack Vault`)
A dedicated, persistent SQLite database system for recording, categorizing, and triaging security incidents and malicious inputs:
* **Persistent Structured Storage:** SQLite database (`attack_vault.db`) stored in an isolated data directory (`data/`), decoupled from transient compilation folders.
* **Captured Threat Vectors:**
  - Prompt injections and system prompt extraction attempts
  - Policy bypass attempts (e.g. `system("rm -rf /")`, `popen`, `exec`)
  - Banned C++ memory and buffer overflow vulnerabilities (`gets`, `strcpy`, `strcat`, `sprintf`, `auto_ptr`, `mktemp`)
  - Poisoned or malicious AI-generated fixes (`MALICIOUS_AI_FIX`)
  - Failed security verifications and guardrail overrides
* **Session Correlation:** Every compilation and repair session is tracked with a unique `correlation_id` to link submissions, repair proposals, validation checks, and security incidents.
* **Analyst Review Workflow:** Security reviewers can classify incidents as `Confirmed attack`, `False positive`, or `Needs review`, appending audit notes and review timestamps.
* **Deduplicating Dataset Management:** Import baseline datasets (`attack_dataset.json`) with SHA-256 hash deduplication, and export confirmed attacks as labeled evaluation datasets (CSV or JSON).

---

## 🏛️ Architecture & Component Layout

```
├── app.py                      # Main Streamlit application and navigation router
├── self_healing_ui.py          # Streamlit UI for the Self-Healing Lab
├── self_healing_engine.py      # Core orchestration for APR detection, repair & verification
├── attack_vault.py             # SQLite database manager for Attack Vault (CRUD, indexing, import/export)
├── attack_vault_ui.py          # Streamlit UI for Attack Vault triage & inspection
├── attack_dataset.json         # Standardized baseline dataset of attack signatures
├── security_metrics.py         # Real-time metrics and threat posture calculation
├── semantic_analyzer.py        # Static semantic analyzer (div-by-zero, infinite loops, null pointers)
├── compiler_service.py         # Subprocess compiler wrapper with timeout & test case execution
├── agent_security.py           # Regex-based threat detection (prompt injection & policy bypass)
├── secure_scan.py              # C++ security guardrail for banned APIs
├── fix_engine.py               # AI repair JSON parser and safety validation
├── error_classifier.py         # GCC error parser and pedagogical prompt constructor
├── audit_logger.py             # Dual logger (mirrors threats to Attack Vault and JSON audit logs)
├── dashboard.py                # Error analytics dashboard
├── security_audit_ui.py        # Security audit log view & threat metrics
├── system_status_ui.py         # Environment diagnostic panel (Ollama, GCC, SQLite, Sandboxing)
├── test_system.py              # Master test suite (runs 25 automated unit tests)
├── test_self_healing.py        # Dedicated Self-Healing automated unit tests
└── test_attack_vault.py        # Dedicated Attack Vault automated unit tests
```

---

## 🚀 Getting Started

### Prerequisites
1. **Python 3.10+**
2. **GCC / G++ Compiler:** Available in system PATH (e.g., MinGW on Windows or GCC on Linux/macOS).
3. **Ollama (Optional but Recommended):** Running locally with model `llama3` (`ollama run llama3`). If Ollama is unavailable, the application gracefully provides deterministic fallbacks and status warnings without crashing.

### Installation
Install python dependencies:
```bash
pip install streamlit pandas codecarbon requests
```

### Initializing the Database
The Attack Vault database initializes automatically on first run in `data/attack_vault.db`. You can also initialize or populate it manually via Python:
```python
from attack_vault import init_vault, import_attack_dataset
init_vault()
import_attack_dataset("attack_dataset.json")
```

### Starting the Application
Launch the Streamlit web application:
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## 🧪 Running the Tests

To run the complete automated test suite (25 tests covering existing functionality, Attack Vault, Self-Healing, and Semantic Analysis):

```bash
python test_system.py
```

To run individual test suites:
```bash
# Run Attack Vault tests (9 tests)
python -m unittest test_attack_vault.py

# Run Self-Healing Engine tests (8 tests)
python -m unittest test_self_healing.py
```

### Automated Test Coverage
* **Self-Healing Tests:**
  1. `test_valid_cpp_code_remains_unchanged`: Valid C++ code remains untouched when no repair is needed.
  2. `test_missing_semicolon_identified_and_repaired`: Semicolon syntax errors are repaired and verified.
  3. `test_proposed_repair_must_compile_before_verified`: Fixes must compile before verification is granted.
  4. `test_repair_that_fails_compilation_is_rejected`: Non-compiling repairs are rejected.
  5. `test_repair_introducing_suspicious_code_rejected`: Repairs introducing dangerous system calls or banned APIs are rejected.
  6. `test_repair_breaking_regression_tests_rejected`: Code breaking regression test outputs is rejected.
  7. `test_original_code_preserved_after_failed_repair`: Original source is untouched when a repair fails.
  8. `test_ollama_unavailable_produces_useful_error`: Connection errors to Ollama produce clear diagnostics without crashing.
* **Attack Vault Tests:**
  1. `test_attack_event_stored_correctly`: Verifies field storage and schema constraints.
  2. `test_records_persist_after_reopening_database`: Tests SQLite persistence across connections.
  3. `test_filtering_by_severity_and_category`: Tests multi-column query filtering.
  4. `test_sql_injection_stored_safely`: Verifies parameterized query safety against SQL injection attacks.
  5. `test_stored_attack_inputs_never_executed`: Confirms payloads remain inert text data.
  6. `test_duplicate_dataset_imports_handled_safely`: Verifies SHA-256 deduplication during imports.
  7. `test_review_decisions_and_notes_persist`: Tests analyst triage updates and notes.
  8. `test_csv_and_json_exports_contain_expected_fields`: Validates export schema.
  9. `test_database_errors_handled_gracefully`: Confirms error resilience on invalid database operations.

---

## ⚠️ Known Limitations & Security Assumptions

1. **Compilation Sandboxing:** C++ compilation relies on the host GCC binary with strict subprocess timeouts (10 seconds for compilation, 5 seconds for execution). In an untrusted multi-tenant production environment, this should be complemented with OS-level isolation (such as Docker, Linux cgroups/seccomp, or WebAssembly/WASI).
2. **Pre-Execution Guardrails:** Security guardrails enforce a strict "Never-List" of dangerous C-style functions (`gets`, `strcpy`, `sprintf`, `system`, `popen`, `exec*`). Complex obfuscations (e.g. dynamic runtime function loading via `dlopen`/`LoadLibrary` or XOR-encoded shellcode) should be paired with dynamic sandboxing.
3. **Local AI Model:** Local Ollama models (such as Llama 3) generate fixes based on compiler diagnostic prompts. Fix generation speed and quality depend on host hardware. If Ollama is offline, the system safely uses rule-based repairs and disables AI inference gracefully.
