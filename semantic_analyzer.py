import re

def extract_block_content(lines, start_line_idx):
    """
    Extracts the code content inside the braces {...} corresponding to
    a control statement starting at start_line_idx.
    """
    brace_depth = 0
    found_first_brace = False
    block_lines = []

    for idx in range(start_line_idx, len(lines)):
        line = lines[idx]
        for char in line:
            if char == '{':
                brace_depth += 1
                found_first_brace = True
            elif char == '}':
                brace_depth -= 1
                if found_first_brace and brace_depth == 0:
                    block_lines.append(line)
                    return "\n".join(block_lines)
        if found_first_brace:
            block_lines.append(line)

    return "\n".join(block_lines)

def analyze_semantics(cpp_code):
    """
    Performs static semantic analysis on C++ code to detect logic bugs,
    semantic flaws, and runtime risks prior to or during compilation/debugging.
    
    Returns:
        (has_semantic_error: bool, findings: list[dict])
        Each finding contains:
        {
            "error_type": str,
            "line": int,
            "severity": str,
            "message": str,
            "snippet": str,
            "suggestion": str
        }
    """
    findings = []
    lines = cpp_code.split('\n')
    
    # Track variable declarations with zero values or null pointers
    zero_variables = set()
    null_pointers = set()
    array_sizes = {} # {array_name: int size}

    # Pass 1: Gather variable context
    for i, line in enumerate(lines):
        line_num = i + 1
        clean = line.strip()
        
        # Check variable initialized to 0: e.g., int numberOfStudents = 0;
        zero_match = re.search(r'\b(?:int|long|short|float|double|size_t)\s+([a-zA-Z_]\w*)\s*=\s*0(?:\.0*)?\s*;', clean)
        if zero_match:
            zero_variables.add(zero_match.group(1))

        # Check pointer initialized to nullptr/NULL/0
        null_match = re.search(r'\b[a-zA-Z_]\w*\s*\*\s*([a-zA-Z_]\w*)\s*=\s*(?:nullptr|NULL|0)\s*;', clean)
        if null_match:
            null_pointers.add(null_match.group(1))

        # Check array declaration with fixed size: int arr[5];
        arr_decl = re.search(r'\b[a-zA-Z_]\w*\s+([a-zA-Z_]\w*)\s*\[\s*(\d+)\s*\]', clean)
        if arr_decl:
            arr_name = arr_decl.group(1)
            arr_size = int(arr_decl.group(2))
            array_sizes[arr_name] = arr_size

    # Pass 2: Detect semantic issues
    for i, line in enumerate(lines):
        line_num = i + 1
        clean = line.strip()
        
        # Skip comments
        if clean.startswith("//") or clean.startswith("/*") or clean.startswith("*"):
            continue

        # 1. Direct or Variable Division by Zero
        # Direct literal: / 0 or % 0
        literal_div_zero = re.search(r'/\s*0(?:\.0*)?(?![0-9])', clean) or re.search(r'%\s*0(?![0-9])', clean)
        if literal_div_zero:
            findings.append({
                "error_type": "DIVISION_BY_ZERO",
                "line": line_num,
                "severity": "CRITICAL",
                "message": "Division by literal zero detected. This will trigger a CPU arithmetic exception (SIGFPE) at runtime.",
                "snippet": clean,
                "suggestion": "Ensure the denominator expression is non-zero before dividing."
            })
        else:
            # Division by known zero variable
            for var in zero_variables:
                pattern = rf'/\s*{re.escape(var)}\b|%\s*{re.escape(var)}\b'
                if re.search(pattern, clean):
                    # Check if reassigned on this line or checked
                    if f"{var} =" not in clean:
                        findings.append({
                            "error_type": "DIVISION_BY_ZERO",
                            "line": line_num,
                            "severity": "CRITICAL",
                            "message": f"Potential division by zero: variable '{var}' was initialized to 0 and is used as a divisor.",
                            "snippet": clean,
                            "suggestion": f"Check if '{var} != 0' before performing division, or initialize with a valid non-zero count."
                        })

        # 2. Potential Infinite Loop
        # while(true) or while(1) or for(;;)
        if re.search(r'\bwhile\s*\(\s*(?:true|1)\s*\)', clean) or re.search(r'\bfor\s*\(\s*;\s*;\s*\)', clean):
            loop_body = extract_block_content(lines, i)
            # Only check for break or return strictly INSIDE the loop body
            if loop_body:
                has_exit = re.search(r'\bbreak\b|\breturn\b', loop_body)
                if not has_exit:
                    findings.append({
                        "error_type": "INFINITE_LOOP",
                        "line": line_num,
                        "severity": "HIGH",
                        "message": "Infinite loop detected: loop condition is constantly true with no break or return condition inside the loop body.",
                        "snippet": clean,
                        "suggestion": "Add a proper loop termination condition or a break statement."
                    })
            else:
                # Loop on single line or without braces
                findings.append({
                    "error_type": "INFINITE_LOOP",
                    "line": line_num,
                    "severity": "HIGH",
                    "message": "Infinite loop detected: loop condition is constantly true.",
                    "snippet": clean,
                    "suggestion": "Add a proper loop termination condition or a break statement."
                })

        # 3. Null Pointer Dereference
        for ptr in null_pointers:
            # Pattern: *ptr = ... or ptr->
            deref_pattern = rf'\*\s*{re.escape(ptr)}\b|{re.escape(ptr)}\s*->'
            if re.search(deref_pattern, clean):
                findings.append({
                    "error_type": "NULL_POINTER_DEREFERENCE",
                    "line": line_num,
                    "severity": "CRITICAL",
                    "message": f"Dereference of null pointer '{ptr}'. Accessing address 0 causes an immediate segmentation fault.",
                    "snippet": clean,
                    "suggestion": f"Allocate memory or assign '{ptr}' to a valid object before dereferencing."
                })

        # 4. Array Out of Bounds Indexing
        for arr, size in array_sizes.items():
            access_match = re.search(rf'\b{re.escape(arr)}\s*\[\s*(\d+)\s*\]', clean)
            if access_match:
                index = int(access_match.group(1))
                if index >= size:
                    findings.append({
                        "error_type": "ARRAY_OUT_OF_BOUNDS",
                        "line": line_num,
                        "severity": "HIGH",
                        "message": f"Array '{arr}' has size {size}, but is accessed at index {index} (valid indices are 0 to {size - 1}).",
                        "snippet": clean,
                        "suggestion": f"Ensure index is within [0, {size - 1}]."
                    })

        # 5. Off-by-one Loop Boundary (e.g. for (int i = 0; i <= size; i++) indexing an array of size)
        for arr, size in array_sizes.items():
            loop_pattern = rf'for\s*\(\s*int\s+([a-zA-Z_]\w*)\s*=\s*0\s*;\s*\1\s*<=\s*{size}\s*;'
            if re.search(loop_pattern, clean):
                findings.append({
                    "error_type": "OFF_BY_ONE",
                    "line": line_num,
                    "severity": "MEDIUM",
                    "message": f"Potential off-by-one loop boundary: loop iterates up to '{size}', which exceeds array '{arr}' bounds (indices 0 to {size - 1}).",
                    "snippet": clean,
                    "suggestion": f"Change '<= {size}' to '< {size}'."
                })

    has_error = any(f["severity"] in ["CRITICAL", "HIGH"] for f in findings)
    return has_error, findings
