import sqlite3
import os
import json
import csv
import hashlib
import uuid
import io
from datetime import datetime
from agent_security import sanitize_text

# Configurable database path: environment variable takes precedence
DEFAULT_VAULT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DEFAULT_DB_PATH = os.path.join(DEFAULT_VAULT_DIR, "attack_vault.db")

def get_vault_db_path():
    """Returns the configured Attack Vault SQLite database path."""
    return os.getenv("ATTACK_VAULT_DB_PATH", DEFAULT_DB_PATH)

def init_vault(db_path=None):
    """
    Initializes the SQLite Attack Vault database, tables, and indexes.
    Safe to call multiple times (idempotent).
    """
    if db_path is None:
        db_path = get_vault_db_path()

    # Ensure parent directory exists
    vault_dir = os.path.dirname(db_path)
    if vault_dir and not os.path.exists(vault_dir):
        os.makedirs(vault_dir, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")

    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                attack_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                category TEXT NOT NULL,
                source TEXT NOT NULL,
                sanitized_input TEXT NOT NULL,
                risk_score REAL,
                risk_level TEXT NOT NULL,
                detection_reason TEXT NOT NULL,
                detection_method TEXT NOT NULL,
                action_taken TEXT NOT NULL,
                correlation_id TEXT,
                repair_attempt_id TEXT,
                validation_status TEXT,
                review_status TEXT NOT NULL DEFAULT 'Needs review',
                analyst_notes TEXT DEFAULT '',
                reviewed_at TEXT,
                input_hash TEXT
            )
        """)

        # Indexes for fast querying and filtering
        conn.execute("CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_attacks_category ON attacks(category);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_attacks_risk_level ON attacks(risk_level);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_attacks_action ON attacks(action_taken);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_attacks_review_status ON attacks(review_status);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_attacks_correlation_id ON attacks(correlation_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_attacks_input_hash ON attacks(input_hash);")

    conn.close()
    return db_path

def compute_input_hash(text):
    """Computes a SHA-256 hash of the input string for deduplication."""
    if text is None:
        text = ""
    return hashlib.sha256(str(text).strip().encode("utf-8")).hexdigest()

def record_attack(
    category,
    source,
    input_text,
    risk_level,
    detection_reason,
    risk_score=None,
    detection_method="Rule-Based Security Guardrail",
    action_taken="Blocked",
    correlation_id=None,
    repair_attempt_id=None,
    validation_status="Failed",
    review_status="Needs review",
    analyst_notes="",
    attack_id=None,
    timestamp=None,
    db_path=None
):
    """
    Records an attack or security incident into the persistent Attack Vault.
    Uses parameterized SQL to guarantee protection against SQL injection.
    Stores untrusted inputs as data only.
    """
    if db_path is None:
        db_path = get_vault_db_path()
    init_vault(db_path)

    if attack_id is None:
        attack_id = f"ATK-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Sanitize input for safe persistent storage (strip secrets/tokens)
    sanitized = sanitize_text(input_text)
    input_hash = compute_input_hash(input_text)

    # Normalize numeric risk_score if valid float
    numeric_risk_score = None
    if risk_score is not None and risk_score != "N/A":
        try:
            numeric_risk_score = round(float(risk_score), 2)
        except (ValueError, TypeError):
            numeric_risk_score = None

    try:
        conn = sqlite3.connect(db_path)
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO attacks (
                    attack_id, timestamp, category, source, sanitized_input,
                    risk_score, risk_level, detection_reason, detection_method,
                    action_taken, correlation_id, repair_attempt_id,
                    validation_status, review_status, analyst_notes,
                    reviewed_at, input_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(attack_id),
                str(timestamp),
                str(category),
                str(source),
                str(sanitized),
                numeric_risk_score,
                str(risk_level),
                str(detection_reason),
                str(detection_method),
                str(action_taken),
                str(correlation_id) if correlation_id else None,
                str(repair_attempt_id) if repair_attempt_id else None,
                str(validation_status),
                str(review_status),
                str(analyst_notes),
                None,
                input_hash
            ))
        conn.close()
        return attack_id
    except sqlite3.Error as e:
        print(f"Attack Vault Database Error in record_attack: {e}")
        return None

def get_attack(attack_id, db_path=None):
    """Retrieves a single attack record by its unique attack ID."""
    if db_path is None:
        db_path = get_vault_db_path()
    init_vault(db_path)

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM attacks WHERE attack_id = ?", (str(attack_id),))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    except sqlite3.Error as e:
        print(f"Attack Vault Database Error in get_attack: {e}")
        return None

def list_attacks(
    category=None,
    risk_level=None,
    action_taken=None,
    review_status=None,
    search_query=None,
    correlation_id=None,
    start_date=None,
    end_date=None,
    limit=50,
    offset=0,
    db_path=None
):
    """
    Queries attacks with multiple filters, parameterized search, and pagination.
    Returns: list of dicts.
    """
    if db_path is None:
        db_path = get_vault_db_path()
    init_vault(db_path)

    query = "SELECT * FROM attacks WHERE 1=1"
    params = []

    if category and category != "All":
        query += " AND category = ?"
        params.append(category)

    if risk_level and risk_level != "All":
        query += " AND risk_level = ?"
        params.append(risk_level)

    if action_taken and action_taken != "All":
        query += " AND action_taken = ?"
        params.append(action_taken)

    if review_status and review_status != "All":
        query += " AND review_status = ?"
        params.append(review_status)

    if correlation_id:
        query += " AND correlation_id = ?"
        params.append(correlation_id)

    if start_date:
        query += " AND timestamp >= ?"
        params.append(str(start_date))

    if end_date:
        query += " AND timestamp <= ?"
        params.append(str(end_date) + " 23:59:59")

    if search_query:
        # Search safely across category, reason, and sanitized input snippet
        query += " AND (category LIKE ? OR detection_reason LIKE ? OR sanitized_input LIKE ? OR attack_id LIKE ?)"
        wildcard = f"%{search_query}%"
        params.extend([wildcard, wildcard, wildcard, wildcard])

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([int(limit), int(offset)])

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows
    except sqlite3.Error as e:
        print(f"Attack Vault Database Error in list_attacks: {e}")
        return []

def count_attacks(
    category=None,
    risk_level=None,
    action_taken=None,
    review_status=None,
    search_query=None,
    correlation_id=None,
    db_path=None
):
    """Returns total count of records matching the filter criteria."""
    if db_path is None:
        db_path = get_vault_db_path()
    init_vault(db_path)

    query = "SELECT COUNT(*) FROM attacks WHERE 1=1"
    params = []

    if category and category != "All":
        query += " AND category = ?"
        params.append(category)

    if risk_level and risk_level != "All":
        query += " AND risk_level = ?"
        params.append(risk_level)

    if action_taken and action_taken != "All":
        query += " AND action_taken = ?"
        params.append(action_taken)

    if review_status and review_status != "All":
        query += " AND review_status = ?"
        params.append(review_status)

    if correlation_id:
        query += " AND correlation_id = ?"
        params.append(correlation_id)

    if search_query:
        query += " AND (category LIKE ? OR detection_reason LIKE ? OR sanitized_input LIKE ? OR attack_id LIKE ?)"
        wildcard = f"%{search_query}%"
        params.extend([wildcard, wildcard, wildcard, wildcard])

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(query, params)
        count = cursor.fetchone()[0]
        conn.close()
        return count
    except sqlite3.Error as e:
        print(f"Attack Vault Database Error in count_attacks: {e}")
        return 0

def update_review_status(attack_id, review_status, analyst_notes="", db_path=None):
    """
    Updates the review status ('Confirmed attack', 'False positive', 'Needs review'),
    along with reviewer notes and a review timestamp.
    """
    if db_path is None:
        db_path = get_vault_db_path()
    init_vault(db_path)

    valid_statuses = ["Confirmed attack", "False positive", "Needs review"]
    if review_status not in valid_statuses:
        raise ValueError(f"Invalid review status: '{review_status}'. Must be one of {valid_statuses}")

    reviewed_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = sqlite3.connect(db_path)
        with conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE attacks
                SET review_status = ?,
                    analyst_notes = ?,
                    reviewed_at = ?
                WHERE attack_id = ?
            """, (review_status, str(analyst_notes), reviewed_at, str(attack_id)))
            updated = cursor.rowcount > 0
        conn.close()
        return updated
    except sqlite3.Error as e:
        print(f"Attack Vault Database Error in update_review_status: {e}")
        return False

def get_vault_summary_stats(db_path=None):
    """
    Returns summary statistics for the Attack Vault dashboard:
    Total events, blocked attacks, critical events, pending reviews,
    confirmed attacks, and false positives.
    """
    if db_path is None:
        db_path = get_vault_db_path()
    init_vault(db_path)

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM attacks")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM attacks WHERE action_taken = 'Blocked'")
        blocked = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM attacks WHERE risk_level = 'CRITICAL'")
        critical = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM attacks WHERE review_status = 'Needs review'")
        pending_review = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM attacks WHERE review_status = 'Confirmed attack'")
        confirmed = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM attacks WHERE review_status = 'False positive'")
        false_positive = cursor.fetchone()[0]

        # Category breakdown
        cursor.execute("SELECT category, COUNT(*) FROM attacks GROUP BY category ORDER BY COUNT(*) DESC")
        category_counts = dict(cursor.fetchall())

        # Severity breakdown
        cursor.execute("SELECT risk_level, COUNT(*) FROM attacks GROUP BY risk_level")
        severity_counts = dict(cursor.fetchall())

        conn.close()

        return {
            "total_events": total,
            "blocked_attacks": blocked,
            "critical_events": critical,
            "pending_reviews": pending_review,
            "confirmed_attacks": confirmed,
            "false_positives": false_positive,
            "by_category": category_counts,
            "by_severity": severity_counts
        }
    except sqlite3.Error as e:
        print(f"Attack Vault Database Error in get_vault_summary_stats: {e}")
        return {
            "total_events": 0,
            "blocked_attacks": 0,
            "critical_events": 0,
            "pending_reviews": 0,
            "confirmed_attacks": 0,
            "false_positives": 0,
            "by_category": {},
            "by_severity": {}
        }

def get_timeline(correlation_id=None, limit=20, db_path=None):
    """Retrieves chronological security events, optionally filtered by correlation_id."""
    if db_path is None:
        db_path = get_vault_db_path()
    init_vault(db_path)

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if correlation_id:
            cursor.execute("""
                SELECT attack_id, timestamp, category, risk_level, action_taken, detection_reason, source, correlation_id
                FROM attacks
                WHERE correlation_id = ?
                ORDER BY timestamp ASC
                LIMIT ?
            """, (str(correlation_id), int(limit)))
        else:
            cursor.execute("""
                SELECT attack_id, timestamp, category, risk_level, action_taken, detection_reason, source, correlation_id
                FROM attacks
                ORDER BY timestamp DESC
                LIMIT ?
            """, (int(limit),))

        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows
    except sqlite3.Error as e:
        print(f"Attack Vault Database Error in get_timeline: {e}")
        return []

def export_attacks_to_json(filter_status=None, db_path=None):
    """
    Exports attacks matching filter_status (e.g., 'Confirmed attack' for labelled dataset,
    or None for all) to a clean, formatted JSON string.
    """
    records = list_attacks(review_status=filter_status, limit=10000, db_path=db_path)
    return json.dumps(records, indent=2)

def export_attacks_to_csv(filter_status=None, db_path=None):
    """
    Exports attacks matching filter_status to a CSV string.
    """
    records = list_attacks(review_status=filter_status, limit=10000, db_path=db_path)
    if not records:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "attack_id", "timestamp", "category", "source", "sanitized_input",
            "risk_score", "risk_level", "detection_reason", "detection_method",
            "action_taken", "correlation_id", "repair_attempt_id",
            "validation_status", "review_status", "analyst_notes", "reviewed_at"
        ])
        return output.getvalue()

    output = io.StringIO()
    fieldnames = list(records[0].keys())
    # Omit internal input_hash if desired, or keep it
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in records:
        writer.writerow(row)
    return output.getvalue()

def import_attack_dataset(dataset_path_or_data, db_path=None):
    """
    Safely imports attack records into the Attack Vault with duplicate detection.
    Records with identical attack_id OR matching input_hash will be detected
    and avoided (or safely skipped) so repeated imports do not create duplicates.
    
    Returns: dict with {"imported": int, "skipped_duplicates": int, "errors": int}
    """
    if db_path is None:
        db_path = get_vault_db_path()
    init_vault(db_path)

    # Determine input type
    if isinstance(dataset_path_or_data, str):
        if os.path.exists(dataset_path_or_data):
            try:
                with open(dataset_path_or_data, "r", encoding="utf-8") as f:
                    entries = json.load(f)
            except Exception as e:
                print(f"Failed to read dataset file {dataset_path_or_data}: {e}")
                return {"imported": 0, "skipped_duplicates": 0, "errors": 1}
        else:
            try:
                entries = json.loads(dataset_path_or_data)
            except Exception as e:
                print(f"Failed to parse dataset string: {e}")
                return {"imported": 0, "skipped_duplicates": 0, "errors": 1}
    elif isinstance(dataset_path_or_data, list):
        entries = dataset_path_or_data
    else:
        return {"imported": 0, "skipped_duplicates": 0, "errors": 1}

    imported_count = 0
    skipped_count = 0
    error_count = 0

    try:
        conn = sqlite3.connect(db_path)
        with conn:
            cursor = conn.cursor()
            for entry in entries:
                if not isinstance(entry, dict):
                    error_count += 1
                    continue

                raw_input = entry.get("sanitized_input") or entry.get("input_text") or entry.get("input_snippet") or ""
                input_hash = entry.get("input_hash") or compute_input_hash(raw_input)
                attack_id = entry.get("attack_id")

                # Check duplicate by attack_id or input_hash
                cursor.execute(
                    "SELECT attack_id FROM attacks WHERE attack_id = ? OR (input_hash = ? AND input_hash != '')",
                    (attack_id, input_hash)
                )
                existing = cursor.fetchone()
                if existing:
                    skipped_count += 1
                    continue

                # Generate ID if missing
                if not attack_id:
                    attack_id = f"ATK-IMP-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

                timestamp = entry.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                category = entry.get("category") or entry.get("event_type") or "CODE_VULNERABILITY"
                source = entry.get("source") or "imported_dataset"
                sanitized_input = sanitize_text(raw_input)
                risk_score = entry.get("risk_score")
                risk_level = entry.get("risk_level") or "HIGH"
                detection_reason = entry.get("detection_reason") or "Imported attack dataset signature"
                detection_method = entry.get("detection_method") or "Dataset Baseline"
                action_taken = entry.get("action_taken") or entry.get("action") or "Blocked"
                correlation_id = entry.get("correlation_id")
                repair_attempt_id = entry.get("repair_attempt_id")
                validation_status = entry.get("validation_status") or "Blocked"
                review_status = entry.get("review_status") or "Needs review"
                analyst_notes = entry.get("analyst_notes") or "Imported from attack dataset"

                numeric_risk_score = None
                if risk_score is not None and risk_score != "N/A":
                    try:
                        numeric_risk_score = round(float(risk_score), 2)
                    except (ValueError, TypeError):
                        numeric_risk_score = None

                cursor.execute("""
                    INSERT INTO attacks (
                        attack_id, timestamp, category, source, sanitized_input,
                        risk_score, risk_level, detection_reason, detection_method,
                        action_taken, correlation_id, repair_attempt_id,
                        validation_status, review_status, analyst_notes,
                        reviewed_at, input_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(attack_id),
                    str(timestamp),
                    str(category),
                    str(source),
                    str(sanitized_input),
                    numeric_risk_score,
                    str(risk_level),
                    str(detection_reason),
                    str(detection_method),
                    str(action_taken),
                    str(correlation_id) if correlation_id else None,
                    str(repair_attempt_id) if repair_attempt_id else None,
                    str(validation_status),
                    str(review_status),
                    str(analyst_notes),
                    None,
                    input_hash
                ))
                imported_count += 1
        conn.close()
    except sqlite3.Error as e:
        print(f"Attack Vault Database Error during dataset import: {e}")
        error_count += 1

    return {
        "imported": imported_count,
        "skipped_duplicates": skipped_count,
        "errors": error_count
    }
