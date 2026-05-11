# CyberNews Week 3 Progress

## Current Step

Pre-AI Integration Bundle

Status: DONE

## Progress Log

### Data Source Research

Status: DONE

Commit: document data source plan

Tested:

- Checked public source URLs where possible.
- Confirmed the project already has NewsAPI and BSI WID RSS integrated.

Notes:

- CISA KEV is the best next source because it is official, public, free, and focused on known exploited CVEs.
- FIRST EPSS is the best follow-up source because it adds exploit probability scoring to CVEs.
- The Hacker News, SecurityWeek, and BleepingComputer are useful later for additional news RSS feeds.
- URLhaus, MalwareBazaar, and OpenPhish are possible IOC sources, but should wait until CVE and news data are stable.

### Step 1: CISA KEV API

Status: DONE

Commit: add CISA KEV API

Tested:

- Checked `/api/kev-vulnerabilities` returns `200`.
- Checked the response includes normalized vulnerability objects.
- Checked `/health` still returns the health message.

Notes:

- Added the official CISA KEV JSON source.
- Normalized the latest 10 vulnerabilities into beginner-readable fields.
- Kept this step API-only; dashboard UI comes next.

### Step 2: Vulnerability Dashboard Panel

Status: DONE

Commit: show KEV vulnerabilities

Tested:

- Checked `/` returns `200`.
- Checked the dashboard includes the Known Exploited Vulnerabilities panel.
- Checked `/api/kev-vulnerabilities` still returns `200`.
- Checked `/health` still returns the health message.

Notes:

- Added a dashboard panel for recent CISA KEV records.
- Shows CVE, vendor/product, date added, due date, ransomware-use status, summary, and required action.
- Added a navigation link to the vulnerability panel.
- Added a CISA KEV row to System Status.
- Kept JavaScript refresh for a separate follow-up commit.

### Responsive Dashboard Layout

Status: DONE

Commit: make dashboard layout responsive

Tested:

- Checked `/` returns `200`.
- Checked the dashboard still contains the main panels.
- Checked the responsive dashboard grid CSS is present.
- Checked `/health` still returns the health message.

Notes:

- Kept the default portrait/laptop layout close to the previous design.
- Added a dashboard grid that wraps panels into columns on wider screens.
- Increased the dashboard content width only on large and very large screens.

### Step 3: KEV Refresh Button

Status: DONE

Commit: add KEV refresh

Tested:

- Checked `/` returns `200`.
- Checked the dashboard includes the Refresh KEV button.
- Checked the dashboard includes KEV JavaScript rendering.
- Checked `/api/kev-vulnerabilities` still returns `200`.
- Checked `/health` still returns the health message.

Notes:

- Added a Refresh KEV button to the vulnerability panel.
- Added browser-side rendering for refreshed CISA KEV results.
- Kept the dashboard display limited to four vulnerabilities.

### Navigation Polish

Status: DONE

Commit: simplify dashboard navigation

Tested:

- Checked `/` returns `200`.
- Checked same-page nav links for Headlines, Intelligence, Vulnerabilities, and System are removed.
- Checked route-level nav links are still present.
- Checked `/health` still returns the health message.

Notes:

- Removed dashboard section anchors from the main menu.
- Kept Dashboard, Admin Reports, and Login/Logout links.

### Step 4: EPSS Scoring API

Status: DONE

Commit: add EPSS scoring API

Tested:

- Checked `/api/epss/CVE-2021-44228` returns `200`.
- Checked the response includes `cve`, `epss`, `percentile`, and `date`.
- Checked an unknown CVE returns a clean JSON error.
- Checked `/health` still returns the health message.

Notes:

- Added the FIRST EPSS API source.
- Added a backend-only EPSS lookup route.
- Kept KEV enrichment and dashboard labels for separate follow-up commits.

### Step 5: KEV EPSS Enrichment

Status: DONE

Commit: enrich KEV API with EPSS

Tested:

- Checked `/api/kev-vulnerabilities` returns `200`.
- Checked KEV vulnerability objects include `epss`, `epss_percentile`, `epss_date`, and `epss_label`.
- Checked `/api/epss/CVE-2021-44228` still returns `200`.
- Checked `/health` still returns the health message.

Notes:

- Added batch EPSS lookup for the KEV API.
- Kept CISA KEV records visible even if EPSS data is missing.
- Added simple backend risk labels for EPSS scores.
- Kept visible dashboard styling for a separate follow-up commit.

### Step 6: EPSS Risk Labels

Status: DONE

Commit: show EPSS risk labels

Tested:

- Checked `/` returns `200`.
- Checked the dashboard includes EPSS score text.
- Checked the dashboard includes EPSS risk badge classes.
- Checked KEV refresh JavaScript renders EPSS data.
- Checked `/health` still returns the health message.

Notes:

- Added EPSS score, percentile, update date, and risk label to KEV cards.
- Added matching EPSS rendering for refreshed KEV cards.
- Added simple EPSS badge styling.

### Step 7: CVE Graph Nodes

Status: DONE

Commit: add CVE nodes to threat graph

Tested:

- Checked `/api/threat-graph` returns `200`.
- Checked the graph response includes CVE nodes from CISA KEV data.
- Checked CVE graph nodes include EPSS fields.
- Checked every graph edge points to an existing node.
- Checked `/health` still returns the health message.

Notes:

- Added three CISA KEV-derived CVE nodes to the threat graph data.
- Added CISA KEV Catalog and FIRST EPSS source nodes.
- Added simple `listed in` and `scored by` relationships.
- Kept product/vendor graph edges for a later follow-up commit.

### Step 8: CVE Graph Visual Positions

Status: DONE

Commit: position CVE graph nodes

Tested:

- Checked `/threat-graph` returns `200`.
- Checked the graph page includes dynamic visual position logic.
- Checked `/api/threat-graph` still returns `200`.
- Checked `/health` still returns the health message.

Notes:

- Added fixed visual positions for CISA KEV and FIRST EPSS source nodes.
- Added automatic row positioning for live CVE nodes.
- Added fallback positions for future unknown graph nodes.
- Increased the visual graph height so CVE nodes have room.

### Pre-AI Integration Bundle

Status: DONE

Commit: finish pre-AI integrations

Tested:

- Checked `/` returns `200`.
- Checked `/` includes the sandboxed Analyst Briefing iframe.
- Checked `/analyst-briefing/frame` returns `200`.
- Checked `/analyst-briefing/frame` contains no `<script>` tag.
- Checked `/api/security-feeds` returns `200`.
- Checked the dashboard includes the Security RSS Feeds panel.
- Checked `/api/threat-graph` returns CVE, Product, and Vendor nodes.
- Checked every graph edge points to an existing node.
- Checked `/threat-graph` includes CVE detail rendering.
- Checked `/health` still returns the health message.

Notes:

- Added normalized The Hacker News and SecurityWeek feed support.
- Added a Security RSS Feeds dashboard panel with refresh.
- Added a sandboxed Analyst Briefing iframe on the dashboard.
- Added a simple server-rendered briefing frame that uses current feeds as mock AI input.
- Removed the Threat Graph link from the main navigation while keeping the route available.
- Added product and vendor graph nodes for CISA KEV CVEs.
- Added CVE detail fields to the threat graph selected-node panel.
- Left IOC feed implementation as a documented safety review before AI.

### AI Workbench Backend Seed

Status: DONE

Commit: seed AI workbench jobs

Tested:

- Checked `AI_WORKBENCH_SPEC.md` exists at the project root.
- Checked `POST /api/ai/jobs` creates a completed mock AI job.
- Checked `GET /api/ai/jobs/<job_id>` returns the stored job.
- Checked invalid AI actions return a JSON error.
- Checked `/health` still returns the health message.

Notes:

- Added the AI Workbench specification as a root Markdown file.
- Added an in-memory `AI_JOBS` store as the first simple job model.
- Added `POST /api/ai/jobs` and `GET /api/ai/jobs/<job_id>`.
- AI results are mocked for now so the UI can be built before Gemini is connected.
- CVE and IOC enrichment return schema-shaped mock results for now.

### AI Workbench Panel UI

Status: DONE

Commit: add AI workbench panel

Tested:

- Checked `/` returns `200`.
- Checked the dashboard includes the `AI Workbench` panel.
- Checked headline cards include `Analyze` buttons.
- Checked `POST /api/ai/jobs` still creates a completed mock AI job.
- Checked `/health` still returns the health message.

Notes:

- Added a simple AI Workbench panel to the dashboard.
- Added Result, Report, and JSON tabs.
- Added Analyze buttons to headline cards.
- The Analyze action calls the existing mock AI jobs API and renders the result.

### AI Actions Menu

Status: DONE

Commit: add AI actions menu

Tested:

- Checked `/` returns `200`.
- Checked headline cards include an `AI Actions` menu.
- Checked menu actions include Analyze, Generate report, Extract IOCs, and Extract CVEs.
- Checked `POST /api/ai/jobs` accepts each menu action.
- Checked `/health` still returns the health message.

Notes:

- Replaced the single Analyze button with a visible AI Actions dropdown.
- Kept the menu click-based instead of right-click-based.
- Added the selected action to the AI Workbench result area.

### AI Action Mock Results

Status: DONE

Commit: add action-specific AI mock results

Tested:

- Checked `POST /api/ai/jobs` returns different structured results for Analyze, Generate report, Extract IOCs, and Extract CVEs.
- Checked selected article text is included in the AI job request.
- Checked the Workbench can display extracted IOC and CVE lists.
- Checked `/` returns `200`.
- Checked `/health` still returns the health message.

Notes:

- Added simple local CVE and IOC pattern extraction for mock AI jobs.
- Kept extraction deterministic and easy to replace with Gemini later.
- Updated the Workbench result tab to show extracted CVEs and IOCs clearly.

### Sandboxed Report Preview

Status: DONE

Commit: preview reports in sandboxed frame

Tested:

- Checked `/` returns `200`.
- Checked the dashboard iframe has `sandbox` and `referrerpolicy="no-referrer"`.
- Checked `/analyst-briefing/frame` returns the empty Report Preview state.
- Checked Generate report returns `report_json`.
- Checked the dashboard JavaScript renders report JSON into iframe `srcdoc`.
- Checked `/health` still returns the health message.

Notes:

- Connected generated report JSON to the sandboxed dashboard iframe.
- Kept report rendering client-side and escaped instead of trusting raw HTML.
- Replaced the old static briefing frame with a Report Preview placeholder.

### Save Generated Reports

Status: DONE

Commit: save generated reports

Tested:

- Checked `POST /api/reports` saves report JSON.
- Checked `GET /api/reports/<report_id>` returns a saved report.
- Checked invalid report save requests return a JSON error.
- Checked the Workbench report tab includes a Save report button.
- Checked `/` and `/health` still return `200`.

Notes:

- Added an in-memory `REPORTS` store.
- Added basic report create and retrieve API routes.
- Added a Save report button for generated Workbench reports.
- Reports still reset when the Flask server restarts; persistent storage comes later.

### Saved Reports List

Status: DONE

Commit: list saved reports

Tested:

- Checked `GET /api/reports` lists saved report summaries.
- Checked saved reports can still be retrieved by ID.
- Checked the Workbench Report tab includes a Saved Reports list.
- Checked loading a saved report updates the Workbench and report preview.
- Checked `/` and `/health` still return `200`.

Notes:

- Added a lightweight saved reports list API.
- Added Saved Reports UI inside the Workbench Report tab.
- Loading a saved report reuses the same safe report renderer and sandboxed preview.

### Cloud Run Deployment Prep

Status: DONE

Commit: prepare Cloud Run deployment

Tested:

- Checked the app can be compiled by Python.
- Checked `/health` returns `CyberNews is running.`
- Checked `python src/web_app.py` respects the `PORT` environment variable.
- Checked deployment docs include Cloud Run setup commands.

Notes:

- Added a `Procfile` for Cloud Run's Python buildpack start command.
- Added `.gcloudignore` so local-only project files are not uploaded.
- Added `.env.example` to document required environment variables without secrets.
- Updated direct app startup so debug mode is opt-in with `FLASK_DEBUG=1`.
