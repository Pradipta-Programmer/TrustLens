# TRUSTLENS — Priority 6: UI/UX Audit Report (READ-ONLY)

**Date:** 2026-11-09
**Audit Scope:** Full UI/UX Inspection of `frontend/index.html` across 11 evaluation dimensions
**Baseline Test Status:** 165 / 165 automated tests passing (100%)
**Baseline Git Commit:** `47f6337` (`fix(frontend): allow keyboard typing and paste by returning undefined from onkeydown`)
**Audit Type:** Strictly READ-ONLY. No source files, APIs, database documents, or schemas were altered.

---

## 1. Current UI Condition

The TRUSTLENS frontend is delivered as a lightweight, framework-free single-page application (`frontend/index.html`, 792 lines). The application interacts with the Express REST API running on port 4000 and MongoDB Atlas.

### What is Working Well:
- **Core Functionality:** Scanner URL input now accepts typed keystrokes, Backspace, and `Ctrl+V` pasting without synthetic suppression.
- **Data Rendering:** Live analysis returns risk scores (0–100), classification badges, confidence ratings, and coverage percentages from the multi-factor scoring engine.
- **Modular Views:** All primary views (`Scan`, `Dashboard`, `Threat Explorer`, `Report a site`, `Certificates`, and `Admin`) navigate smoothly via hash routing (`#scan`, `#dash`, `#exp`, `#rep`, `#cert`, `#admin`).
- **Security & Integrity:** All input is sanitized via `esc()`, avoiding XSS vulnerabilities. SSRF protection on backend scan endpoints remains intact.
- **Visual Foundation:** Clean color scheme with clear risk-level indicators (`--ok: #15803d`, `--warn: #b45309`, `--bad: #c62828`).

### Core Areas Requiring Polish:
- **Mobile Touch Usability:** Navigation links and input controls have touch targets below the WCAG 44×44px standard on small screens.
- **Theme Flexibility:** While dark mode CSS variables exist, there is no manual switch for users to toggle dark/light mode on demand.
- **Feedback & In-Flight State:** Interactive actions (such as initiating a scan, running debounced search, or moderating reports in Admin) lack disabled button states or distinct loading feedback.
- **Layout Robustness:** Multi-column grids and large score badges overflow or wrap awkwardly on screens narrower than 400px.

---

## 2. Issues Identified Across Audit Dimensions

### Severity Definitions
- **Critical:** Prevents essential user actions, breaks page layout completely, or violates core security principles.
- **High:** Substantially degrades usability, violates standard accessibility criteria (WCAG AA), or risks duplicate submission requests.
- **Medium:** Inconvenient workflow, sub-optimal responsive layout, missing feedback cues, or cognitive friction for users.
- **Low:** Minor aesthetic inconsistency, subtle contrast variance, or cosmetic polish opportunity.

---

### Area 1: Overall Visual Design & Consistency

| ID | Location | Severity | Description | Recommended Improvement |
|---|---|:---:|---|---|
| **VIS-01** | `frontend/index.html` L6–10, L36 | **Medium** | **No Manual Theme Switcher:** Dark mode CSS exists (`:root[data-theme=dark]` and `@media (prefers-color-scheme: dark)`), but there is no toggle button in the header or footer to manually switch themes. | Add a compact theme toggle button in `<header>` (`🌙 Dark` / `☀️ Light`) storing choice in `localStorage`. |
| **VIS-02** | `frontend/index.html` L24 | **Low** | **Subtle Card Border Contrast in Dark Mode:** `.card` uses `border: 1px solid var(--line);` where `--line` is `#243459` against background `#122042`. Under some display angles, cards blend into background. | Increase contrast slightly to `#2c3e6b` for dark mode borders. |
| **VIS-03** | `frontend/index.html` L27 | **Low** | **Pill Font Size Inconsistency:** Status pills use `12px` font size in results but `11px` in some tables and admin badges. | Standardize pill typography and padding across all modules. |

---

### Area 2: Navigation & Page Layouts

| ID | Location | Severity | Description | Recommended Improvement |
|---|---|:---:|---|---|
| **NAV-01** | `frontend/index.html` L12–15, L36, L91 | **High** | **Mobile Touch Targets Below WCAG 44×44px Standard:** Header nav links use `padding: 4px 2px;`, yielding physical tap height of ~22px. On mobile, adjacent tabs are easily mis-tapped. | Increase touch padding on mobile viewports (`min-height: 44px; padding: 8px 12px; display: inline-flex; align-items: center;`). |
| **NAV-02** | `frontend/index.html` L12, L36 | **Medium** | **Navigation Wrap on Narrow Viewports (<400px):** Six navigation links wrap into 3 uneven vertical rows, pushing header content down. | Add horizontal scrolling container (`overflow-x: auto; white-space: nowrap; scrollbar-width: none;`) for navigation on viewports narrower than 600px. |
| **NAV-03** | `frontend/index.html` L14–15 | **Medium** | **Low Contrast Active Navigation Indicator:** Active tab relies on a thin 2px underline (`border-color: #6ea0ff;`), which lacks sufficient distinctiveness for users with vision impairments. | Enhance active link indicator with bold weight, `#fff` text, and a distinct indicator pill or 3px border. |

---

### Area 3: Dashboard Presentation

| ID | Location | Severity | Description | Recommended Improvement |
|---|---|:---:|---|---|
| **DSH-01** | `frontend/index.html` L25, L168–174 | **Medium** | **Metric Cards Grid Balance:** Dashboard has 5 metric cards inside `minmax(210px, 1fr)`. On 3-column screens, the 5th card spans wide across the second row alone. | Use balanced 5-column layout on wide desktop screens (`@media (min-width: 960px) { grid-template-columns: repeat(5, 1fr); }`) or 2/3 structured layout. |
| **DSH-02** | `frontend/index.html` L196–200, L205–209 | **Low** | **Recent Scans and Reports Not Clickable:** Lists display recent domain activity with risk pills, but rows cannot be clicked to view detailed scans. | Make rows clickable links navigating directly to the scan report or Threat Explorer filtered by domain. |
| **DSH-03** | `frontend/index.html` L195, L204 | **Low** | **Plain Text Empty States:** When no scans exist, cards display bare text `"No recent scans on record."`. | Provide structured empty state with brief explanation and a "Run your first scan" action button. |

---

### Area 4: Scanner Input, Results & Risk Visualization

| ID | Location | Severity | Description | Recommended Improvement |
|---|---|:---:|---|---|
| **SCN-01** | `frontend/index.html` L101–105 | **High** | **Scan Button & Input Not Disabled During In-Flight Scan:** When user clicks "Scan website", `#prog` renders the progress list, but `#go` remains active. Accidental double-clicks trigger duplicate API scans. | Disable `#go` and `#u` during analysis: `$("#go").disabled = true; $("#u").disabled = true;` inside a `try/finally` block. |
| **SCN-02** | `frontend/index.html` L29, L127 | **Medium** | **Result Header Wraps Unevenly on Mobile:** On screens < 450px wide, the 64px score circle wraps above domain and details, misaligning with the card body. | Add responsive layout query to center score circle and classification title on mobile viewports. |
| **SCN-03** | `frontend/index.html` L126, L135 | **Medium** | **SVG Trust Timeline Lacks Point Tooltips:** Historical scan trend renders `<polyline points="${pts}"/>`, but points lack hover tooltips showing date and exact risk score. | Add SVG `<circle>` nodes with `<title>` tooltips for each scan coordinate on the curve. |
| **SCN-04** | `frontend/index.html` L136 | **Low** | **"Copy Report Summary" Feedback Does Not Auto-Dismiss:** Clicking `#cp` renders `Copied.` permanently until user navigates away. | Add `setTimeout(() => { $("#cpm").textContent = ""; }, 2500);` to dismiss confirmation. |

---

### Area 5: Threat Explorer

| ID | Location | Severity | Description | Recommended Improvement |
|---|---|:---:|---|---|
| **EXP-01** | `frontend/index.html` L224–228, L280–310 | **Medium** | **Debounced Search Lacks Loading Indicator:** As user types in `#q`, a 300ms debounce fires, but table remains static with old data until API returns. | Display subtle loading indicator or reduced opacity (`style="opacity: 0.5;"`) on `#tb` while search is fetching. |
| **EXP-02** | `frontend/index.html` L230 | **Low** | **Missing Horizontal Scroll Indicator:** On mobile screens, table scrolls horizontally via `.scroll`, but there is no visual indicator that off-screen columns exist. | Add subtle gradient scroll cue or shadow on right edge of table wrapper. |

---

### Area 6: Certificate Intelligence & CT Timeline

| ID | Location | Severity | Description | Recommended Improvement |
|---|---|:---:|---|---|
| **CRT-01** | `frontend/index.html` L380–455 | **Medium** | **CT Discovered SANs Truncated Without Full View:** When CT discovers > 10 SANs, it outputs `slice(0, 10).join(', ') + ' …'`, concealing remaining discovered domains. | Display first 10 SANs with an expandable `<details><summary>View all (X) SANs</summary>...</details>` container. |
| **CRT-02** | `frontend/index.html` L458–464 | **Low** | **Missing Example Shortcut Pills:** Main scanner provides demo shortcut buttons, but certificate lookup requires manual typing. | Add 2 quick demo shortcut buttons (`example.com`, `google.com`) beneath the certificate lookup input. |

---

### Area 7: Community Reporting Interface

| ID | Location | Severity | Description | Recommended Improvement |
|---|---|:---:|---|---|
| **REP-01** | `frontend/index.html` L320–350 | **Medium** | **Anonymous Token Generation Failure Feedback:** If guest token initialization fails on report submit, the UI shows a generic error message. | Provide clear error copy: `"Unable to establish secure anonymous session. Check your network and retry."` with a retry button. |
| **REP-02** | `frontend/index.html` L322 | **Low** | **Leading/Trailing Whitespace in URL Input:** Pasting a URL with accidental leading/trailing spaces relies on backend validation error. | Auto-trim `#ru.value` on paste and blur events. |

---

### Area 8: Admin Panel

| ID | Location | Severity | Description | Recommended Improvement |
|---|---|:---:|---|---|
| **ADM-01** | `frontend/index.html` L615–639 | **High** | **Moderation Action Buttons Lack Visual Processing Feedback:** Clicking `Verify`, `Investigate`, or `Reject` disables the button, but text remains static during the ~300ms PATCH roundtrip. | Change button text to `"Updating..."` or display inline spinner while request is in flight. |
| **ADM-02** | `frontend/index.html` L673 | **Medium** | **Audit Trail Detail Column Renders Raw JSON:** Renders `JSON.stringify(l.detail)`. Security reviewers must read raw strings like `{"previousStatus":"pending_review","newStatus":"verified"}`. | Format known audit details into readable badges (e.g. `pending_review → verified`). |

---

### Area 9: Responsive Behavior Across Devices

| ID | Location | Severity | Description | Recommended Improvement |
|---|---|:---:|---|---|
| **RSP-01** | `frontend/index.html` L16, L25 | **High** | **Grid Overflow on Small Screens (<360px):** `.grid` uses `minmax(210px, 1fr)`. Combined with container padding (16px * 2), devices under 360px experience horizontal page overflow. | Change to `grid-template-columns: repeat(auto-fit, minmax(min(100%, 210px), 1fr));`. |
| **RSP-02** | `frontend/index.html` L19–20 | **Medium** | **Form Input Stacking on Mobile:** Inputs with `min-width: 220px` inside `.row` wrap abruptly on small viewports. | Set `min-width: 0; width: 100%;` inside media query for viewports under 480px. |

---

### Area 10: Accessibility & Usability (WCAG 2.1 AA)

| ID | Location | Severity | Description | Recommended Improvement |
|---|---|:---:|---|---|
| **ACC-01** | `frontend/index.html` L30, L89 | **Medium** | **Progress Bar Uses Generic `role="img"`:** Progress bars use `role="img" aria-label="${v} of 100"`. Screen readers do not announce it as a range or value gauge. | Use `role="progressbar" aria-valuenow="${v}" aria-valuemin="0" aria-valuemax="100" aria-label="Risk score bar"`. |
| **ACC-02** | `frontend/index.html` L23 | **Low** | **Focus Outline Color Consistency:** `:focus-visible` outline uses `#f59e0b`. Ensure 3:1 contrast against both light (`#f3f5f9`) and dark (`#0a1428`) backgrounds. | Verified compliant, but adding `outline-offset: 3px` enhances visibility on buttons. |

---

### Area 11: Loading, Empty, Error & Success States

| ID | Location | Severity | Description | Recommended Improvement |
|---|---|:---:|---|---|
| **STA-01** | `frontend/index.html` L101, L143, L577 | **Medium** | **Fragmented Loading Patterns Across Modules:** Scanner uses simulated step text; Dashboard uses static text; Admin uses plain paragraph. | Introduce a lightweight `.spinner` CSS keyframe animation for unified visual feedback. |
| **STA-02** | `frontend/index.html` L340–345 | **Low** | **Report Success Message Placement:** Submitting a report leaves the form in place with a green success message below, without resetting input fields. | Clear form fields on successful submission and offer "Submit another report" button. |

---

## 3. Summary of Issues by Severity

```
┌───────────────────────────────────────────────┐
│              SEVERITY BREAKDOWN               │
├────────────────────┬───────────┬──────────────┤
│ Critical           │     0     │   (0.0%)     │
│ High               │     4     │  (14.8%)     │
│ Medium             │    13     │  (48.1%)     │
│ Low                │    10     │  (37.0%)     │
├────────────────────┼───────────┼──────────────┤
│ TOTAL ISSUES       │    27     │ (100.0%)     │
└────────────────────┴───────────┴──────────────┘
```

---

## 4. Potential Regression Risks & Safeguards

| Potential Risk | Affected Feature | Safeguard / Prevention Strategy |
|---|---|---|
| **Form Event Handling Breakage** | Scanner URL input & shortcuts | Keep `(e) => { if (e.key === 'Enter') run(e.target.value); }` pattern returning `undefined` (do not return boolean or call `preventDefault()` on non-Enter keys). |
| **Theme Toggle CSS Interference** | Dark/light color variables | Ensure CSS `:root[data-theme=dark]` and `:root[data-theme=light]` variables match existing values without altering specificity. |
| **Async State Locking** | In-flight scan button disabling | Always re-enable button and input inside a `finally` block so failures or timeouts never permanently lock inputs. |
| **HTML Syntax Corruptions** | SPA string interpolation | Keep all multi-line template literals intact; test JavaScript compilation using `node -e` after any edit. |
| **API Contract Mismatch** | REST endpoints | UI polish is strictly frontend; no backend endpoints, request payloads, or response schemas will be modified. |

---

## 5. Prioritized Implementation Plan

The improvements are organized into **4 sequential, focused phases** to prevent bulk rewrites and ensure verification at each stage:

```
┌────────────────────────────────────────────────────────────────────────┐
│  Phase 6.1: Core Design System, Theme Toggle & Navigation Accessibility│
│  - Add manual dark/light theme switch in header with localStorage.      │
│  - Enforce WCAG 2.1 touch target sizing (>= 44px) on header navigation.│
│  - Fix responsive grid overflow for narrow viewports (<360px).         │
│  - Update progress bars to role="progressbar" with ARIA attributes.    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│  Phase 6.2: Scanner UX & Results Polish                                │
│  - Disable input and scan button during in-flight analysis.            │
│  - Center score and title on mobile viewports (<480px).                │
│  - Add interactive tooltips/points to SVG trust timeline.              │
│  - Auto-dismiss "Copied." confirmation message after 2.5s.             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│  Phase 6.3: Dashboard & Threat Explorer Polish                         │
│  - Balance dashboard metric card grid (5 columns on desktop).          │
│  - Make recent scans and reports clickable to open details.            │
│  - Add search loading indicator on Threat Explorer debounced input.    │
│  - Enhance empty states with styled action callouts.                   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│  Phase 6.4: Certificate Intelligence & Admin Console Experience        │
│  - Add expandable <details> viewer for full CT SAN lists (> 10).       │
│  - Add one-click demo pills to certificate lookup view.                │
│  - Add "Updating..." button state on admin moderation actions.         │
│  - Format AuditLog JSON details into readable change badges.           │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Exact First Implementation Task

Upon receiving approval, the first task to execute will be:

> **Execute Phase 6.1 (Core Design System, Theme Toggle & Navigation Accessibility):**
> 1. In `frontend/index.html`, add CSS rules and a toggle button to `<header>` to allow users to switch between Light and Dark themes, saving the choice in `localStorage`.
> 2. Increase header navigation touch target padding and height to satisfy WCAG AA recommendations (`min-height: 44px`, `padding: 8px 12px; display: inline-flex; align-items: center;`).
> 3. Update `.grid` CSS to prevent horizontal overflow on viewports under 360px: `grid-template-columns: repeat(auto-fit, minmax(min(100%, 210px), 1fr));`.
> 4. Update the active navigation indicator to provide stronger visual contrast and update progress bars to use `role="progressbar" aria-valuenow="..." aria-valuemin="0" aria-valuemax="100"`.
> 5. Compile the extracted inline JavaScript via `node -e` to guarantee zero syntax errors, verify the UI at `http://localhost:4000`, and confirm all 165 backend automated tests pass.

---
*Report prepared in compliance with the TRUSTLENS Priority 6 READ-ONLY Audit specification.*
