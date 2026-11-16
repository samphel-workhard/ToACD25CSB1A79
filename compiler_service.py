import tempfile
import subprocess
import os

def compile_and_run(cpp_code):
    """
    Compiles with '-g' for LLDB support and runs the code in an isolated temporary directory.
    Returns: (status_code, stdout, stderr, temp_dir, executable)
      0 = Success
      1 = Compile Error
      2 = Runtime Error (Segfault/Crash)
     -1 = Timeout/System Error
    """
    temp_dir = tempfile.TemporaryDirectory()
    try:
        source_file = os.path.join(temp_dir.name, "temp_source.cpp")
        executable = os.path.join(temp_dir.name, "temp_program")
        if os.name == 'nt': # Windows compatibility
            executable += ".exe"

        with open(source_file, "w", encoding="utf-8") as f:
            f.write(cpp_code)

        # 1. COMPILE (with -g for debug symbols)
        compile_process = subprocess.run(
            ["g++", "-g", source_file, "-o", executable], 
            capture_output=True, 
            text=True, 
            timeout=10
        )

        if compile_process.returncode != 0:
            return 1, "", compile_process.stderr, temp_dir, executable

        # 2. RUN BINARY
        run_process = subprocess.run(
            [executable], 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        
        # 3. CATCH RUNTIME CRASHES (e.g. SegFaults, DivByZero on POSIX or Windows)
        if run_process.returncode != 0:
            crash_reason = run_process.stderr if run_process.stderr else f"Process crashed with exit code {run_process.returncode} (Likely Segmentation Fault or Arithmetic Exception)"
            return 2, run_process.stdout, crash_reason, temp_dir, executable
            
        full_output = run_process.stdout
        if run_process.stderr:
            full_output += "\n" + run_process.stderr
            
        return 0, full_output.strip(), "", temp_dir, executable
    except subprocess.TimeoutExpired:
        return -1, "", "❌ Time Limit Exceeded! Possible infinite loop.", temp_dir, ""
    except Exception as e:
        return -1, "", f"❌ System Error: {str(e)}", temp_dir, ""

def compile_only(cpp_code):
    """
    Compiles C++ code in an isolated directory without executing it.
    Returns: (success: bool, status_code, stdout, stderr, temp_dir, executable)
    """
    temp_dir = tempfile.TemporaryDirectory()
    try:
        source_file = os.path.join(temp_dir.name, "temp_source.cpp")
        executable = os.path.join(temp_dir.name, "temp_program")
        if os.name == 'nt':
            executable += ".exe"

        with open(source_file, "w", encoding="utf-8") as f:
            f.write(cpp_code)

        compile_process = subprocess.run(
            ["g++", "-g", source_file, "-o", executable], 
            capture_output=True, 
            text=True, 
            timeout=10
        )

        if compile_process.returncode != 0:
            return False, 1, "", compile_process.stderr, temp_dir, executable

        return True, 0, compile_process.stdout, "", temp_dir, executable
    except subprocess.TimeoutExpired:
        return False, -1, "", "❌ Compilation Timeout! G++ compiler took too long.", temp_dir, ""
    except Exception as e:
        return False, -1, "", f"❌ Compilation Error: {str(e)}", temp_dir, ""

def run_executable_isolated(executable, stdin_input="", timeout=5):
    """
    Executes a pre-compiled binary in an isolated subprocess with timeout and input piping.
    Returns: (status_code, stdout, stderr)
    """
    try:
        run_process = subprocess.run(
            [executable],
            input=stdin_input,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if run_process.returncode != 0:
            err = run_process.stderr or f"Crashed with exit code {run_process.returncode}"
            return 2, run_process.stdout, err
        return 0, run_process.stdout.strip(), run_process.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "❌ Execution Timeout (Time Limit Exceeded)"
    except Exception as e:
        return -1, "", f"❌ Execution Failed: {str(e)}"

def run_with_test_cases(cpp_code, test_cases, timeout=5):
    """
    Compiles and executes C++ code against a suite of test cases.
    Each test_case should be: {"input": str, "expected_output": str} or similar.
    Returns: (all_passed: bool, test_results: list[dict], summary_msg: str)
    """
    success, status, stdout, stderr, temp_dir, executable = compile_only(cpp_code)
    if not success:
        if temp_dir:
            temp_dir.cleanup()
        return False, [], f"Compilation failed: {stderr}"

    test_results = []
    all_passed = True

    try:
        for idx, tc in enumerate(test_cases):
            tc_input = str(tc.get("input", ""))
            expected = str(tc.get("expected_output", "")).strip()

            code, out, err = run_executable_isolated(executable, stdin_input=tc_input, timeout=timeout)
            actual = out.strip()

            passed = (code == 0) and (expected in actual or actual == expected)
            if not passed:
                all_passed = False

            test_results.append({
                "test_index": idx + 1,
                "input": tc_input,
                "expected": expected,
                "actual": actual,
                "passed": passed,
                "error": err if code != 0 else ""
            })
    finally:
        if temp_dir:
            temp_dir.cleanup()

    summary_msg = f"{sum(1 for r in test_results if r['passed'])}/{len(test_results)} test cases passed."
    return all_passed, test_results, summary_msg
