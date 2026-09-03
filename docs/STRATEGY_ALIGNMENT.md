# ULPF Strategy Alignment

**To:** Devansh & AI Teammates
**From:** The Architecture Team
**Date:** September 3, 2026

Please read this document carefully before making further commits. We recently took a step back to evaluate the codebase against the actual requirements of the NTRO Problem Statement (26156). 

We realized that while the Rust backend is incredibly strong, we were drifting towards building a "flashy prototype" rather than an actual deployable product that NTRO SOC analysts can use in a highly restricted environment.

## 1. What We Discussed & Decided

Our core realization was that **NTRO deployments are air-gapped and often lack GPUs.** Therefore, a log pre-processor that *requires* an internet connection, a Google Fonts CDN, or a local 7-billion-parameter LLM to function is a prototype, not a product.

We decided to pivot the architecture to guarantee a fallback to deterministic, heuristic rules. The AI is a powerful *assistant*, but it cannot be a hard dependency for parsing unknown logs.

## 2. What We Built in Phase 2 & 3

To achieve this product-grade state, we just pushed the following major updates to `main`:

1.  **Air-Gapped UI:** Removed all external CDNs. Fonts and assets are now bundled. The dashboard loads instantly with the internet cord pulled.
2.  **Syslog UDP Listener (`0.0.0.0:5514`):** The `ulpf serve` command no longer just serves HTTP. It spins up a dedicated `tokio` thread to receive raw syslog, just like a real SIEM.
3.  **Real Dataset Library (`testdata/real/`):** We stopped using fake simulators and seeded real logs from FortiGate, Cisco ASA, PAN-OS, Snort, Suricata, and custom apps.
4.  **Replay Engine (`ulpf replay`):** A new CLI subcommand to blast the real datasets over UDP to the listener.
5.  **SIEM Sinks Built-In:** The `serve` command now natively forwards the normalized OCSF data to OpenSearch/Wazuh via bulk HTTP POST.
6.  **Deterministic Heuristic Generator:** We wrote a `heuristic.rs` pack drafter. If the LLM is offline or no GPU is present, the `/api/generate` endpoint silently falls back to this heuristic engine, ensuring the "Unparsed Clusters" workflow never breaks.

## 3. How the AI Copilot Fits In

Devansh's recent commit (`5378a21`) adding a conversational chat thread to the AI Copilot was merged successfully! 

However, please note our new design philosophy: **The AI is an optional assistant, not the core pipeline.**
The "Unparsed Clusters" tab (which uses the Drain algorithm to group unknown logs) is the primary deterministic workflow for SOC analysts. The Copilot Chat is a secondary tab. Devansh added an excellent safeguard where the chat intercepts raw log lines and offers to run them through the strict Pack Drafting workflow. This is exactly the kind of hybrid approach we want.

## 4. Required Reading for AI Agents

To fully understand our deep-dive analysis, I have committed the exact markdown files we used to plan this pivot into the `docs/strategy/` folder:

*   `docs/strategy/codebase_analysis.md` - Our brutally honest audit of what was real vs. fake in the codebase.
*   `docs/strategy/implementation_plan.md` - The exact blueprint we used to execute Phase 2 & 3.
*   `docs/strategy/task.md` - The checklist of what is done and what is pending.

**Please do not remove the Unparsed Clusters workflow, and do not add any internet-dependent libraries to this repository.** Let's build a bleeding-edge system that actually works when deployed!
