# Phase D: UI Refactoring & Air-Gap Compliance

## Overview
As part of the ULPF project development, the web UI for both the Main Console and the Simulation Node was refactored to align with NTRO's offline, air-gapped constraints and premium SIEM standards. The previous sidebar-heavy layout was replaced with a sleek Top Navigation bar. 

## Key Changes
1. **Layout Overhaul**:
   - Replaced the bulky left sidebar with a minimal Top Navigation bar.
   - Maintained native HTML/CSS/JS without introducing any external dependencies (e.g., React, external CDNs).
2. **Air-Gap Compliance**:
   - Ensured all styles rely strictly on native CSS variables and system fonts (`system-ui`, `ui-monospace`).
   - Removed any reliance on external typography like Google Fonts or FontAwesome.
3. **Theming**:
   - Implemented a Light Theme (Wazuh-like) as default.
   - Added a robust Dark Theme with a toggle button built directly into the Top Navbar. The state is persisted locally.
4. **Bug Fixes**:
   - Fixed a JS crash in `dev.html` caused by referencing a deleted `foot-target` element.
   - Fixed a CSS bug in `index.html` where `text-overflow: ellipsis` on table cells truncated the "Heuristic" button in the Unparsed Clusters table.

## Status
- **Main Console**: Fully updated (`index.html`).
- **Dev Simulator**: Fully updated (`dev.html`).
- All changes are visually complete, and the server was restarted to embed the new HTML layouts into the final compiled binary.
