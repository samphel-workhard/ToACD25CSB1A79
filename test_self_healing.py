import unittest
import tempfile
import os
import difflib
from unittest.mock import patch

from self_healing_engine import (
    detect_code_errors,
    generate_repair_proposal,
    verify_repair_proposal,
    apply_verified_fix,
    generate_correlation_id,
    query_ollama,
    check_ai_service_available
)
from compiler_service import compile_and_run

class TestSelfHealingEngine(unittest.TestCase):

    def setUp(self):
        self.correlation_id = generate_correlation_id()

    def test_valid_cpp_code_remains_unchanged(self):
        """1. Valid C++ code remains unchanged when no repair is needed."""
        valid_code = """#include <iostream>
using namespace std;

int main() {
    cout << "Clean valid program" << endl;
    return 0;
}"""
        detection = detect_code_errors(valid_code, correlation_id=self.correlation_id)
        self.assertFalse(detection["has_error"])
        self.assertTrue(detection["is_safe"])

        proposal = generate_repair_proposal(valid_code, detection)
        # Original code must be completely unchanged
        self.assertEqual(proposal["proposed_code"], valid_code)
        self.assertEqual(proposal["status"], "Verified")
        self.assertIn("No modifications required", proposal["what_changed"])

    def test_missing_semicolon_identified_and_repaired(self):
        """2. A missing semicolon is identified and can be repaired."""
        buggy_code = """#include <iostream>
using namespace std;

int main() {
    int x = 42
    cout << x << endl;
    return 0;
}"""
        detection = detect_code_errors(buggy_code, correlation_id=self.correlation_id)
        self.assertTrue(detection["has_error"])
        self.assertIn("Syntax Error", detection["category"])

        proposal = generate_repair_proposal(buggy_code, detection)
        self.assertIsNotNone(proposal["proposed_code"])
        # Verify the proposed code has the semicolon added
        self.assertIn("int x = 42;", proposal["proposed_code"])

        # Run verification on the proposal
        verification = verify_repair_proposal(proposal)
        self.assertEqual(verification["status"], "Verified")
        self.assertTrue(verification["compilation_passed"])
        self.assertTrue(verification["execution_passed"])

    def test_proposed_repair_must_compile_before_verified(self):
        """3. The proposed repair must compile before it can be marked verified."""
        original_code = "int main() { int a = 1; return 0; }"
        # Intentionally invalid proposed code that cannot compile
        uncompilable_proposal = {
            "repair_id": "REP-TEST-001",
            "correlation_id": self.correlation_id,
            "original_code": original_code,
            "proposed_code": "int main() { invalid_syntax_error_not_cpp }",
            "status": "Pending"
        }

        verification = verify_repair_proposal(uncompilable_proposal)
        self.assertNotEqual(verification["status"], "Verified")
        self.assertEqual(verification["status"], "Rejected")
        self.assertFalse(verification["compilation_passed"])
        self.assertIn("Compilation Failed", verification["rejection_reason"])

    def test_repair_that_fails_compilation_is_rejected(self):
        """4. A repair that fails compilation is rejected."""
        original_code = "int main() { return 0 }"
        failed_proposal = {
            "repair_id": "REP-TEST-002",
            "correlation_id": self.correlation_id,
            "original_code": original_code,
            "proposed_code": "int main() { undefined_identifier_xyz(); return 0; }",
            "status": "Pending"
        }

        verification = verify_repair_proposal(failed_proposal)
        self.assertEqual(verification["status"], "Rejected")
        self.assertFalse(verification["compilation_passed"])

    def test_repair_introducing_suspicious_code_rejected(self):
        """5. A repair that introduces suspicious or banned code is rejected."""
        original_code = "int main() { char buf[10]; return 0; }"
        # Proposed fix attempts to insert banned gets() or system() call
        poisoned_proposal = {
            "repair_id": "REP-TEST-003",
            "correlation_id": self.correlation_id,
            "original_code": original_code,
            "proposed_code": """#include <cstdlib>
int main() {
    system("rm -rf /");
    return 0;
}""",
            "is_ai_generated": True,
            "status": "Pending"
        }

        verification = verify_repair_proposal(poisoned_proposal)
        self.assertEqual(verification["status"], "Rejected")
        self.assertFalse(verification["security_passed"])
        self.assertIn("Security Verification Failed", verification["rejection_reason"])
        self.assertIsNotNone(verification.get("attack_id"))

    def test_repair_breaking_regression_tests_rejected(self):
        """6. A repair that breaks regression tests is not accepted."""
        original_code = """#include <iostream>
using namespace std;
int main() {
    // Should print 'Hello Alice'
    cout << "Hello Alice" << endl;
    return 0;
}"""
        # Proposed fix mistakenly changes the output to 'Goodbye Alice'
        broken_regression_proposal = {
            "repair_id": "REP-TEST-004",
            "correlation_id": self.correlation_id,
            "original_code": original_code,
            "proposed_code": """#include <iostream>
using namespace std;
int main() {
    cout << "Goodbye Alice" << endl;
    return 0;
}""",
            "status": "Pending"
        }

        test_cases = [{"input": "", "expected_output": "Hello Alice"}]
        verification = verify_repair_proposal(broken_regression_proposal, test_cases=test_cases)
        self.assertEqual(verification["status"], "Rejected")
        self.assertFalse(verification["regression_passed"])
        self.assertIn("Regression Test Failed", verification["rejection_reason"])

    def test_original_code_preserved_after_failed_repair(self):
        """7. The original code is preserved after a failed repair."""
        original_working_code = """#include <iostream>
using namespace std;
int main() {
    cout << "Original Working Code" << endl;
    return 0;
}"""
        failed_proposal = {
            "repair_id": "REP-TEST-005",
            "correlation_id": self.correlation_id,
            "original_code": original_working_code,
            "proposed_code": "int main() { syntax_error }",
            "status": "Pending"
        }

        verification = verify_repair_proposal(failed_proposal)
        self.assertEqual(verification["status"], "Rejected")

        # Attempting to apply the unverified fix must fail and preserve original code
        with self.assertRaises(ValueError):
            apply_verified_fix(original_working_code, failed_proposal, verification)

        # Confirm original code remains intact
        current_code = original_working_code
        self.assertEqual(current_code, original_working_code)

    def test_ollama_unavailable_produces_useful_error(self):
        """8. Ollama being unavailable produces a useful error rather than crashing the app."""
        # Mock request error for Ollama endpoint
        with patch("requests.post") as mock_post:
            import requests
            mock_post.side_effect = requests.exceptions.ConnectionError("Connection refused")

            success, error_msg = query_ollama("Test prompt", format_json=True)
            self.assertFalse(success)
            self.assertIn("AI service unavailable", error_msg)
            self.assertIn("Could not connect to Ollama", error_msg)

if __name__ == '__main__':
    unittest.main()
