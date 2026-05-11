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

### Dockerfile For Cloud Build

Status: DONE

Commit: add Dockerfile for Cloud Build

Tested:

- Checked the Dockerfile starts Gunicorn on Cloud Run's `PORT`.
- Checked only application source and requirements are copied into the image.
- Checked deployment docs mention the Dockerfile-based Cloud Build path.

Notes:

- Added a simple Python 3.12 slim image.
- Added `.dockerignore` to keep local-only files out of the container context.
- Kept `Procfile` in place so source deploys still work too.

### Firestore Persistence

Status: DONE

Commit: persist reports and AI jobs in Firestore

Tested:

- Checked the app imports with the new storage module.
- Checked `/health` returns `CyberNews is running.`
- Checked AI jobs can still be created and retrieved.
- Checked reports can still be saved, listed, and retrieved.

Notes:

- Added Firestore storage for saved reports and AI jobs.
- Kept a memory fallback for local development without Google Cloud credentials.
- Left admin reports and audit log in memory for now.

### Vertex AI Article Analysis

Status: DONE

Commit: connect article analysis to Vertex AI

Tested:

- Enabled the Vertex AI API in Google Cloud.
- Granted the Cloud Run service account `roles/aiplatform.user`.
- Checked article Analyze still returns a completed AI job.
- Checked the AI job is saved through the storage layer.

Notes:

- Added a small Gemini service for article analysis only.
- Kept mock fallback if Vertex AI or the SDK is unavailable.
- Other AI actions still use the mock implementation for now.

### AI Error Handling Patch

Status: DONE

Commit: handle AI service errors cleanly

Tested:

- Fixed Cloud Run environment variables after a malformed update.
- Checked live `/api/ai/jobs` returns a Gemini result from Cloud Run.
- Checked Firestore smoke-test data was removed.

Notes:

- Added safer Firestore fallback if a Firestore operation fails at runtime.
- Added a clearer AI Workbench error if the server ever returns non-JSON.

### Vertex AI Report Generation

Status: DONE

Commit: generate reports with Vertex AI

Tested:

- Checked `Generate report` returns a completed AI job.
- Checked the job uses `gemini-2.5-flash`.
- Checked the response includes structured report JSON.
- Checked the report has Executive Summary, Key Findings, and Recommended Actions.

Notes:

- Report generation now uses Gemini for article entities.
- The report is still rendered from structured JSON, not raw AI HTML.
- Mock fallback remains in place if Vertex AI is unavailable.

### Report Export Decision

Status: DONE

Commit: document report export plan

Tested:

- Documentation only.

Notes:

- Decided to keep AI reports as structured JSON.
- The dashboard renders controlled HTML from report JSON into the sandboxed iframe.
- Dynamic visuals should be represented as structured section types, such as `flowchart` or `source_links`.
- First PDF export will use browser Print / Save as PDF from the report preview.

### Report Print Export

Status: DONE

Commit: add report print export

Tested:

- Checked `/` renders successfully.
- Checked generated reports still return report JSON.
- Checked the Report tab exposes an Export PDF / Print button when a report exists.

Notes:

- Added a simple browser print path for the sandboxed report preview.
- This keeps PDF export client-side and avoids backend PDF dependencies.

### Vertex AI Extraction And Source Links

Status: DONE

Commit: extract IOCs and CVEs with Vertex AI

Tested:

- Checked `Extract IOCs` returns Gemini-structured IOC data.
- Checked `Extract CVEs` returns Gemini-structured CVE data.
- Checked `Generate report` can include a safe `source_links` section.
- Checked source links render in the Workbench report view and iframe preview.

Notes:

- IOC and CVE extraction now use Gemini for article entities.
- Report JSON supports `source_links` with only `http://` and `https://` URLs.
- Mock fallback remains in place if Vertex AI is unavailable.

### CVE Enrichment API

Status: DONE

Commit: add CVE enrichment API

Tested:

- Checked `/api/cve-enrichment/CVE-2021-44228` returns NVD data.
- Checked the response includes EPSS and CISA KEV data.
- Checked Gemini returns an explanation based only on deterministic values.
- Checked invalid CVE IDs return `400`.

Notes:

- Added NVD CVE API lookup.
- Combined NVD, CISA KEV, and EPSS into one CVE detail object.
- Added an optional `NVD_API_KEY` environment variable for higher NVD API rate limits.

### Aggregated News API

Status: DONE

Commit: add aggregated news feed API

Tested:

- Checked `/api/aggregated-news` returns one normalized item list.
- Checked NewsAPI, security RSS, and BSI advisories are included when available.
- Checked items include filter fields such as `source_type`, `category`, and `severity`.

Notes:

- Added the first backend step toward a single filterable/sortable feed.
- Dashboard UI consolidation is planned next.

### Unified Feed UI

Status: DONE

Commit: show aggregated news feed

Tested:

- Checked `/` renders successfully.
- Checked NewsAPI, security RSS, and BSI items appear in one feed.
- Checked category, severity, and source filters are available.
- Checked newest/oldest sorting is available.

Notes:

- Replaced separate RSS and BSI dashboard panels with one unified feed.
- Kept KEV vulnerabilities as a separate vulnerability intelligence panel.
- Made the unified feed scrollable.

### BleepingComputer RSS Source

Status: DONE

Commit: add BleepingComputer feed

Tested:

- Checked the BleepingComputer RSS feed returns XML.
- Checked `/api/security-feeds` includes BleepingComputer articles.
- Checked `/api/aggregated-news` includes BleepingComputer items.

Notes:

- Added BleepingComputer as another public RSS source.
- It flows through the existing normalized RSS parser and unified feed.

### Hacker News Community Signal

Status: DONE

Commit: add Hacker News community feed

Tested:

- Checked the Hacker News API returns top story IDs and story JSON.
- Checked `/api/hacker-news` returns filtered security/community items or a clear empty message.
- Checked `/api/aggregated-news` includes Hacker News when matching stories are available.

Notes:

- Added Hacker News as a community signal, not an authoritative threat intel source.
- Filtered top stories with cybersecurity-related terms.
- Added Hacker News to the unified feed source list.

### CISA Advisories Feed

Status: DONE

Commit: add CISA advisories feed

Tested:

- Checked the CISA advisories XML feed returns `200`.
- Checked `/api/cisa-advisories` returns normalized advisory items.
- Checked `/api/aggregated-news` includes `cisa-advisories` items.

Notes:

- Added official CISA advisories as a unified feed source.
- Kept CISA KEV separate as the richer vulnerability intelligence panel.

### Unified Feed Source Visibility Fix

Status: DONE

Commit: show all aggregated feed sources

Tested:

- Checked dashboard source options are built from the full aggregated feed.
- Checked the unified feed can show sources beyond the first 20 feed items.

Notes:

- Removed the dashboard's 20-item server-side slice.
- The scrollable feed now handles the larger list on the page.

### Multi-Source Feed Filter

Status: DONE

Commit: add multi-source feed filter

Tested:

- Checked `/` renders successfully.
- Checked the dashboard source filter renders checkbox options.
- Checked source options include the current aggregated feed source types.
- Checked `/api/aggregated-news` still returns the unified feed.

Notes:

- Replaced the single source select with a checkbox dropdown.
- All sources are selected by default.
- Analysts can filter by one source or several sources at the same time.

### Quick Product Fixes

Status: DONE

Commit: remove demo news and fix report print

Tested:

- Checked Python compilation.
- Checked `/` renders successfully.
- Checked `/api/live-news` no longer returns local demo articles when NewsAPI is unavailable.
- Checked `/api/articles` returns the aggregated feed instead of old mock entries.

Notes:

- Removed hardcoded demo news entries from the feed fallback path.
- Kept real RSS/advisory sources in the unified feed.
- Changed report print export to open a printable report window from the structured report JSON.

### Feed And Reporting Split

Status: DONE

Commit: split feed from AI reporting

Tested:

- Checked Python compilation.
- Checked `/` renders as the Feed page.
- Checked `/ai-reporting` renders the AI Workbench and sandboxed report viewport.
- Checked `/admin/reports` redirects to `/ai-reporting`.
- Checked `/api/aggregated-news` still returns the unified feed.

Notes:

- Renamed the main navigation item from Dashboard to Feed.
- Kept the Feed page focused on the master feed only.
- Moved the sandboxed report viewport and AI Workbench to AI & Reporting.
- Integrated admin report intake, admin reports, and audit log into AI & Reporting for admins.
- Removed the separate static Intelligence Reports feature.

### Login Gate

Status: DONE

Commit: require login for app access

Tested:

- Checked Python compilation.
- Checked logged-out `/` redirects to `/login`.
- Checked logged-out app API requests return `401` JSON.
- Checked `/health`, `/login`, and static files remain public.
- Checked login redirects back to the originally requested page.

Notes:

- Added one central Flask `before_request` login guard.
- Protected app pages and app API endpoints.
- Kept Cloud Run health checks public.

### Feed Time Filter And Paging

Status: DONE

Commit: add feed time filter and paging

Tested:

- Checked Python compilation.
- Checked the Feed page renders for a logged-in user.
- Checked the Feed page includes time filter options.
- Checked the Feed page includes Previous and Next paging controls.
- Checked `/api/aggregated-news` still returns the unified feed for logged-in users.

Notes:

- Added time window filters for all time, last 24 hours, last 7 days, and last 30 days.
- Added simple client-side pagination with 20 feed items per page.
- Kept this as a frontend step before Firestore-backed feed storage.

### User Tiers And Artifact Cleanup

Status: DONE

Commit: update users and admin artifact cleanup

Tested:

- Checked Python compilation.
- Checked `Alex` can log in as admin.
- Checked `Cybersteps` can log in as regular user.
- Checked old `alice` and `bob` accounts no longer work.
- Checked regular users cannot delete generated reports.
- Checked admins can delete generated reports.

Notes:

- Replaced the old demo accounts.
- Removed demo user hints from the login page.
- Removed the manual Admin Report feature.
- Kept two tiers: users get feed and AI features, admins can also delete generated AI reports.
