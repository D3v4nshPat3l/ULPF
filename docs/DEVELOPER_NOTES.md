# ULPF Developer & AI Agent Guide

This document is for human developers (like Devansh) and AI agents contributing to the ULPF codebase. Please read this before making architectural changes.

## 1. Core Architecture
ULPF is designed as an **air-gapped, high-throughput, deterministic log pipeline**.
The pipeline is strictly:
`Raw syslog (UDP/TCP)` -> `VaultWriter (Disk)` -> `PackLibrary (Identify & Decode)` -> `OCSF Mapping` -> `Integrity Checkpoint` -> `Sinks (SIEM/Parquet)`

**Rules for AI Agents:**
- Do not introduce dependencies that require an internet connection (e.g., CDNs, external APIs, cloud LLMs).
- Do not compromise the integrity vault. The `RawRef` must always point to the original, cryptographically signed byte array.

## 2. The AI Copilot & Unparsed Clusters
We have two UI paradigms in `index.html`:
1.  **Unparsed Clusters (Strict Workflow):** Group unknown logs and use deterministic heuristics (Drain algorithm) to draft Source Packs. This is the primary workflow for NTRO analysts in production.
2.  **AI Copilot (Conversational Workflow):** A chat interface powered by local LLMs (Ollama). It can answer questions and assist with pack drafting.

**Important Note for Devansh's AI:**
The conversational UI was merged successfully with the strict Unparsed Clusters workflow. If you modify `llm.rs` or `ui/index.html`, **do not remove the Unparsed Clusters workflow**. The AI should assist the analyst, not replace the deterministic pipeline.

## 3. Deployment Constraints
NTRO SOC deployments have specific constraints:
- **No GPUs:** Assume the target hardware is CPU-only. Any AI features must fall back to deterministic Rust logic if Ollama is not present or too slow.
- **Air-Gapped:** No outbound internet access.
- **Syslog-First:** The primary ingestion method is Syslog UDP/TCP on port 5514, not HTTP APIs.

## 4. Current Phase Tasks
We are currently executing **Phase 2 (Production Hardening)**. The current focus is:
- A deterministic (heuristic) pack generator that does not rely on LLMs.
- A `replay` engine for generating synthetic traffic.
- TOML configuration and graceful shutdown.
