# CyberNews Week 2 Progress

## Current Step

Step 15b: Visual Graph Nodes

Status: TODO

## Progress Log

### Setup: Archive Week 1 Files

Status: DONE

Commit: 63da564 cleanup root

Tested:

- Confirmed Week 1 files moved into `week_1/`.
- Confirmed new `src/` directory exists.

Notes:

- Moved the original HTML, CSS, README, Flask app folder, and exercises folder into `week_1/`.
- Created `src/` as the workspace for the next product version.

### Step 1: Clean Shared Layout

Status: DONE

Commit: ec47a2d Week 2: clean shared page layout

Tested:

- Checked `/` returns the dashboard page.
- Checked `/health` returns the health message.

Notes:

- Created a fresh Flask app in `src/`.
- Added a shared `base.html` layout.
- Added a simple dashboard page using the shared layout.
- Added basic CSS for the Week 2 product shell.

### Step 2: Dashboard Landing Page

Status: DONE

Commit: 56aff74 Week 2: improve dashboard landing page

Tested:

- Checked `/` returns the improved dashboard page.
- Checked `/health` still returns the health message.

Notes:

- Added mock dashboard stats.
- Added mock latest headlines.
- Added mock intelligence queue items.
- Added simple system status rows.
- Kept all data hardcoded for now.

### Step 3: Article Data Shape

Status: DONE

Commit: 5d28126 Week 2: normalize article data shape

Tested:

- Checked `/` returns the dashboard page with normalized articles.
- Checked `/api/articles` returns article JSON.
- Checked `/health` still returns the health message.

Notes:

- Moved mock article data into `get_mock_articles()`.
- Added consistent article fields: id, title, summary, source, url, published, category, and severity.
- Added `/api/articles` for JSON article data.
- Updated the dashboard to use the normalized article data.

### Step 4: News Filtering

Status: DONE

Commit: 4d105f2 Week 2: add news filters

Tested:

- Checked `/` returns the dashboard page with filter controls.
- Checked `/api/articles` still returns article JSON.
- Checked `/health` still returns the health message.
- Manually confirmed the placeholder articles are affected by the filters.

Notes:

- Added category and severity dropdown filters.
- Added article data attributes for browser-side filtering.
- Added a small JavaScript filter function.
- Added an empty message for no matching articles.

### Step 5a: Basic Demo Login

Status: DONE

Commit: ffe1feb Week 2: add basic demo login

Tested:

- Checked `/login` returns the login form.
- Checked valid demo login redirects to the dashboard.
- Checked invalid login keeps the user on the login page with an error.
- Checked `/logout` clears the demo session.
- Checked admin-only navigation appears for `bob`.

Notes:

- Added hardcoded demo users.
- Added Flask session-based login and logout.
- Added login/logout navigation states.
- Added admin-only navigation visibility for the future admin reports page.

### Step 5b: Admin Report Form

Status: DONE

Commit: c928ae3 Week 2: add admin report form

Tested:

- Checked logged-out users are redirected from `/admin/reports` to `/login`.
- Checked regular user `alice` receives a 403 response.
- Checked admin user `bob` can open `/admin/reports`.
- Checked admin user `bob` can create a report.

Notes:

- Added an admin-only report form.
- Stored reports in memory for now.
- Added a saved reports list on the admin page.
- Updated the admin navigation link.

### Step 6: Password Hashing

Status: DONE

Commit: 24e5fcc Week 2: hash demo passwords

Tested:

- Checked `alice / alicepass` can still log in.
- Checked `bob / bobpass` can still log in.
- Checked wrong passwords are rejected.
- Checked admin report access still works for `bob`.
- Checked `/health` still returns the health message.

Notes:

- Replaced plain-text passwords in `USERS` with password hashes.
- Updated login to use Werkzeug `check_password_hash()`.
- Kept the visible demo credentials on the login page for testing.

### Step 7: Audit Log

Status: DONE

Commit: 480e42d Week 2: add login audit log

Tested:

- Checked failed login attempts are recorded.
- Checked successful `alice` login is recorded.
- Checked successful `bob` login is recorded.
- Checked audit log appears on `/admin/reports` for admin users.
- Checked regular user `alice` still cannot access `/admin/reports`.
- Checked `/health` still returns the health message.

Notes:

- Added an in-memory `AUDIT_LOG`.
- Recorded username, result, role, and timestamp for login attempts.
- Displayed the audit log on the admin reports page.

### Step 8: Intelligence Report Cards

Status: DONE

Commit: c5cf36d Week 2: display intelligence report cards

Tested:

- Checked `/` returns the dashboard page with intelligence report cards.
- Checked each report shows severity, source, summary, and recommended action.
- Manually confirmed report cards are visually distinct from the old queue.
- Checked login still works for `alice`.
- Checked admin reports still work for `bob`.
- Checked `/health` still returns the health message.

Notes:

- Replaced the simple intelligence queue with richer report cards.
- Added a consistent hardcoded intelligence report shape.
- Renamed the dashboard section to Intelligence Reports.

### Step 9: Live News Feed

Status: DONE

Commit: 90ed855 Week 2: add live news feed

Tested:

- Checked `/api/live-news` returns fallback articles when `NEWS_API_KEY` is missing.
- Checked `/api/live-news` returns live NewsAPI articles when `NEWS_API_KEY` is loaded.
- Checked `/api/live-news` returns normalized article objects.
- Checked `/` contains the refresh live news button and JavaScript renderer.
- Checked `/health` still returns the health message.

Notes:

- Source research completed before implementation.
- NewsAPI stays first because `NEWS_API_KEY` already exists.
- Planned endpoint: `/api/live-news`.
- Planned upstream endpoint: `https://newsapi.org/v2/everything`.
- Planned query: `q=cybersecurity`, `language=en`, `sortBy=publishedAt`.
- NewsAPI is useful for general cybersecurity news but not pure threat intelligence.
- Added NewsAPI integration with local fallback.
- Added browser-side refresh for live news.

### Step 10a: BSI Advisory API

Status: DONE

Commit: 9d0d902 Week 2: add BSI advisory API

Tested:

- Checked `/api/bsi-advisories` returns `200`.
- Checked `/api/bsi-advisories` returns normalized advisory fields.
- Checked BSI severity values are mapped to app severity labels.
- Checked `/health` still returns the health message.

Notes:

- Source research completed before implementation.
- BSI WID RSS is the preferred second source.
- Feed URL tested: `https://wid.cert-bund.de/content/public/securityAdvisory/rss`.
- No API key is needed.
- RSS fields map to `title`, `url`, `summary`, `severity`, and `published`.
- Severity values are German: `niedrig`, `mittel`, `hoch`, `kritisch`.
- This source is better for vulnerability advisories than generic news.
- This step only adds the JSON API route.
- Added RSS parsing with Python standard library XML tools.

### Step 10b: Dashboard BSI Section

Status: DONE

Commit: 36a766e Week 2: show BSI advisories on dashboard

Tested:

- Checked `/` returns the dashboard page with a BSI Advisories section.
- Checked dashboard shows BSI advisory titles, source, dates, summaries, and severity labels.
- Checked BSI title metadata tags are removed from displayed titles.
- Checked `/api/bsi-advisories` still returns live advisory JSON.
- Checked `/health` still returns the health message.

Notes:

- Planned: show BSI advisories on the dashboard.
- No JavaScript refresh yet.
- Added a read-only BSI Advisories dashboard section.
- Limited the dashboard to four advisories to keep the page readable.

### Step 10c: BSI Advisory Refresh

Status: DONE

Commit: c9a5ee2 Week 2: add BSI advisory refresh

Tested:

- Checked `/` returns the dashboard page with the BSI refresh button.
- Checked dashboard HTML contains the BSI JavaScript renderer.
- Checked `/api/bsi-advisories` returns live advisory JSON.
- Checked `/health` still returns the health message.

Notes:

- Planned: add a refresh button for BSI advisories.
- Use JavaScript to fetch `/api/bsi-advisories`.
- Added a Refresh BSI button to the BSI Advisories panel.
- Added browser-side rendering for refreshed BSI advisories.
- Kept the dashboard display limited to four BSI advisories.

### Step 11: Connect Admin Reports To Dashboard

Status: DONE

Commit: 963f3ee Week 2: show admin reports on dashboard

Tested:

- Checked `/` shows the fallback demo intelligence reports when no admin reports exist.
- Checked admin user `bob` can create a report.
- Checked `/` shows the admin-created report after it is submitted.
- Checked the dashboard intel report count updates from admin report data.
- Checked `/health` still returns the health message.

Notes:

- Planned: show admin-created reports on the main dashboard.
- Kept the existing demo intelligence reports as fallback data.
- Added a small helper that normalizes admin reports for dashboard display.
- Admin reports are still stored in memory for now.

### Step 12: Threat Graph Mock Data

Status: DONE

Commit: 4ee197e Week 2: add threat graph data API

Tested:

- Checked `/api/threat-graph` returns `200`.
- Checked the graph response contains `nodes`, `edges`, and a message.
- Checked every edge points to an existing node.
- Checked `/health` still returns the health message.

Notes:

- Added simple mock threat graph data.
- Added threat, technique, impact, target, and defense node examples.
- Added simple relationship edges like `uses`, `targets`, and `reduces risk of`.
- Added `/api/threat-graph` as the JSON endpoint for the future graph page.

### Step 13: Threat Graph Page

Status: DONE

Commit: 5b60678 Week 2: add threat graph page

Tested:

- Checked `/threat-graph` returns `200`.
- Checked the page contains the threat graph loader script.
- Checked the main navigation links to `/threat-graph`.
- Checked `/api/threat-graph` still returns graph JSON.
- Checked `/health` still returns the health message.

Notes:

- Added a Threat Graph navigation link.
- Added a `/threat-graph` route.
- Added a simple Threat Graph page.
- The page fetches `/api/threat-graph` in the browser.
- Nodes and relationships are rendered as readable cards for now.

### Step 14: Graph Details Panel

Status: DONE

Commit: af1b53e Week 2: add graph details panel

Tested:

- Checked `/threat-graph` returns `200`.
- Checked the page contains the selected node details panel.
- Checked the page contains node click handling.
- Checked `/api/threat-graph` still returns graph JSON.
- Checked `/health` still returns the health message.

Notes:

- Added a Selected Node details panel.
- Clicking a node shows its type, severity, and connected relationships.
- The selected node receives a simple highlight.
- This step does not add the visual graph view yet.

### Step 15a: Visual Graph Shell

Status: DONE

Commit: Week 2: add visual graph shell

Tested:

- Checked `/threat-graph` returns `200`.
- Checked the page contains the visual graph panel.
- Checked the page contains the empty SVG graph viewport.
- Checked the existing graph data loader still exists.
- Checked `/api/threat-graph` still returns graph JSON.
- Checked `/health` still returns the health message.

Notes:

- Planned: add a visual graph panel before using any graph library.
- Keep this step as layout only.
- Keep the existing node cards and details panel below the visual area.
- Added the visual graph shell above the readable graph data.
- No graph nodes or relationship lines are drawn yet.

### Step 15b: Visual Graph Nodes

Status: TODO

Commit: -

Tested:

- -

Notes:

- Planned: draw fixed-position SVG node circles from graph data.
- Use simple severity colors and node labels.
- Do not draw relationship lines yet.

### Step 15c: Visual Graph Relationships

Status: TODO

Commit: -

Tested:

- -

Notes:

- Planned: draw SVG lines between related nodes.
- Add relationship labels only if they stay readable.

### Step 15d: Visual Graph Selection

Status: TODO

Commit: -

Tested:

- -

Notes:

- Planned: make visual graph nodes clickable.
- Reuse the existing Selected Node details panel.
- Highlight the selected visual node and matching card.

### Step 16: Google Cloud Deployment Prep

Status: TODO

Commit: -

Tested:

- -

Notes:

- -

### Step 17: Secret Handling Notes

Status: TODO

Commit: -

Tested:

- -

Notes:

- -

### Step 18: Firestore Planning Spike

Status: TODO

Commit: -

Tested:

- -

Notes:

- -

### Step 19: Vertex AI Planning Spike

Status: TODO

Commit: -

Tested:

- -

Notes:

- -

### Step 20: Final Week 2 Polish

Status: TODO

Commit: -

Tested:

- -

Notes:

- -
