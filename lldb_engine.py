import subprocess
import requests
import json
import os

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_GENERATE_URL = f"{OLLAMA_HOST.rstrip('/')}/api/generate"
MODEL_NAME = os.getenv("OLLAMA_MODEL", "llama3")

def execute_lldb_command(executable_path, command):
    """
    Runs a specific LLDB command on the compiled binary in batch mode.
    """
    try:
        result = subprocess.run(
            ["lldb", "-b", "-o", "run", "-o", command, executable_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "LLDB Timeout: The command took too long to execute."
    except Exception as e:
        return f"LLDB System Error: {str(e)}"

def agentic_debug_loop(cpp_code, crash_output, executable_path="./temp_program"):
    """
    The ReAct Loop for LLDB debugging.
    """
    agent_prompt = f"""You are an Autonomous C++ Debugger.
A C++ program just crashed with a Runtime Error.

--- BUGGY CODE ---
{cpp_code}

--- CRASH OUTPUT ---
{crash_output}

You have access to the LLDB Debugger. 
You must choose ONE of the following actions:
ACTION 1: Run an LLDB command to inspect memory (e.g., 'bt' for backtrace).
ACTION 2: Explain the error and provide the fix.

You MUST respond in strict JSON format:
{{
    "thought": "Your reasoning about what to do next",
    "action": "lldb_command" OR "final_fix",
    "command": "the exact lldb command to run (leave empty if final_fix)",
    "explanation": "Your final explanation to the user. You MUST include the fully corrected C++ code inside a markdown block. (leave empty if lldb_command)"
}}"""

    max_turns = 2
    current_context = agent_prompt
    ui_debug_log = "" 

    for turn in range(max_turns):
        payload = {"model": MODEL_NAME, "prompt": current_context, "stream": False, "format": "json"}
        try:
            response = requests.post(OLLAMA_GENERATE_URL, json=payload, timeout=60).json()['response']
        except requests.exceptions.RequestException as e:
            return f"❌ Agent aborted due to connection error: {str(e)}", ui_debug_log
        
        try:
            ai_decision = json.loads(response)
            thought = ai_decision.get('thought')
            action = ai_decision.get('action')
            
            ui_debug_log += f"**Turn {turn + 1} - 🧠 Thought:** {thought}\n\n"
            
            if action == "lldb_command":
                cmd = ai_decision.get("command")
                ui_debug_log += f"**🛠️ Action:** Ran LLDB command `{cmd}`\n\n"
                
                lldb_result = execute_lldb_command(executable_path, cmd)
                ui_debug_log += f"**💻 LLDB Response:**\n```text\n{lldb_result}\n```\n\n---\n\n"
                
                current_context += f"\n\n--- LLDB RESULT FOR '{cmd}' ---\n{lldb_result}\n\nNow, provide the 'final_fix' JSON based on this new memory data."
            
            elif action == "final_fix":
                ui_debug_log += "**✅ Action:** Diagnosis Complete. Delivering final fix."
                return ai_decision.get("explanation"), ui_debug_log 
                
        except json.JSONDecodeError:
            return "Critical Error: The AI failed to output valid JSON routing.", ui_debug_log

    return "Agentic Loop Halted: AI exceeded maximum allowed debugging turns.", ui_debug_log
