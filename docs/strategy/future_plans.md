# Future Implementation Specs

## 1. Laptop 1: The Graphical Simulator Dashboard
As discussed, the 3-Laptop architecture will have a dedicated UI for the log source simulator.
- **Location:** Laptop 1 will run the `/dev` dashboard.
- **Functionality:** Instead of using the command line (`ulpf replay`), the dashboard will feature a visual control panel listing all datasets (e.g., Cisco ASA, FortiGate, Windows, Apache, etc.).
- **Controls:** Users will be able to click graphical switches to turn specific log streams ON or OFF, simulating a live network environment for the judges.

## 2. NTRO Parsing Choice: AI vs. Deterministic
NTRO must have the explicit choice of how to generate parsers (Source Packs) for unknown logs.
- **The Options:** The UI must provide two distinct options for handling Unparsed Clusters:
  1. **"Draft Pack (AI Copilot)"**: Uses the local LLM (Ollama) to deeply analyze the log and write a complex pack.
  2. **"Draft Pack (Deterministic Heuristic)"**: Bypasses the AI entirely and uses the strict, rules-based `heuristic.rs` generator (guaranteed to work air-gapped without a GPU).
- **Why:** This proves to NTRO that the system is fully capable of operating in highly restricted environments without sacrificing the cutting-edge AI features when hardware permits.
