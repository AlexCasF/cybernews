# CyberNews Week 2 Plan

Week 2 is about turning the school exercise project into a more complete product.

The goal is still to keep every step small, readable, and easy to explain.

## Core Rules

- Work on one feature at a time.
- Keep each commit focused on one feature, or one small part of a feature.
- Test the current step before committing.
- Stop after each finished step so Alex can review the code or diff before pushing.
- Prefer simple code first, then improve it in small follow-up commits.

## Target Direction

The product roadmap points toward:

- A polished CyberNews dashboard
- Better authentication and role handling
- Live threat/news data
- Threat correlation with graph-style relationships
- Possible Google Cloud deployment
- Possible Vertex AI summaries later
- Possible Next.js/React frontend later

For now, we should improve the existing Flask project before replacing it.

## Step-by-Step Plan

### Step 1: Clean Shared Layout

Commit idea:

```text
Week 2: clean shared page layout
```

Work:

- Review current templates.
- Make the shared navigation and page structure consistent.
- Keep the current Flask/Jinja setup.

Test:

- Open the main routes.
- Confirm navigation still works.

### Step 2: Dashboard Landing Page

Commit idea:

```text
Week 2: improve dashboard landing page
```

Work:

- Make `/news` feel more like the main dashboard.
- Add simple dashboard sections for headlines, intelligence, and status.
- Avoid large redesigns.

Test:

- Open `/news`.
- Confirm static and live headlines still load.

### Step 3: Article Data Shape

Commit idea:

```text
Week 2: normalize article data shape
```

Work:

- Use one simple article format across local and live news.
- Include fields like title, source, url, date, and category.
- Keep mock data readable.

Test:

- Check `/api/news`.
- Check `/api/live-news`.
- Confirm the page still renders articles.

### Step 4: News Filtering

Commit idea:

```text
Week 2: add news filters
```

Work:

- Add simple category or source filters on the dashboard.
- Filter in JavaScript first.
- Keep the UI small and clear.

Test:

- Load news.
- Change filters.
- Confirm displayed articles update.

### Step 5: Admin Report Form

Commit idea:

```text
Week 2: add admin report form
```

Work:

- Add a simple admin-only form for creating mock intelligence reports.
- Store reports in memory or a local JSON file first.
- Keep validation basic.

Test:

- Log in as admin.
- Add a report.
- Confirm regular users cannot access the admin form.

### Step 6: Password Hashing

Commit idea:

```text
Week 2: hash demo passwords
```

Work:

- Replace plain-text password checks with password hashes.
- Keep the demo users simple.

Test:

- Log in as `alice`.
- Log in as `bob`.
- Try a wrong password.

### Step 7: Audit Log

Commit idea:

```text
Week 2: add login audit log
```

Work:

- Record successful and failed login attempts.
- Store timestamp, username, result, and role if available.
- Use a simple server-side log file or in-memory list.

Test:

- Make one successful login.
- Make one failed login.
- Confirm both are recorded.

### Step 8: Intelligence Report Cards

Commit idea:

```text
Week 2: display intelligence report cards
```

Work:

- Improve `/intelligence` display.
- Show role, severity, summary, and recommended action.
- Keep token-based access unchanged.

Test:

- Fetch with `analyst-token`.
- Fetch with `admin-token`.
- Try an invalid token.

### Step 9: Live News Feed

Commit idea:

```text
Week 2: add live news feed
```

Work:

- Add `/api/live-news`.
- Read `NEWS_API_KEY` from the environment.
- Fetch cybersecurity articles from NewsAPI.
- Use the `/v2/everything` endpoint with a cybersecurity query.
- Prefer `language=en` and `sortBy=publishedAt`.
- Convert live articles into the existing article shape.
- Fall back to local mock articles if the key is missing or the request fails.
- Add a dashboard button for refreshing live news.

Normalized fields:

- `id`
- `title`
- `summary`
- `source`
- `url`
- `published`
- `category`
- `severity`

Research notes:

- NewsAPI is the best first live source because the key is already available.
- It is general news search, so category/severity may need simple local defaults at first.

Test:

- Open `/api/live-news`.
- Click the dashboard refresh button.
- Temporarily test missing API key behavior.
- Confirm `/` and `/health` still work.

### Step 10: BSI Vulnerability Feed

Commit idea:

```text
Week 2: add BSI vulnerability feed
```

Work:

- Add a second live security source using the BSI WID RSS feed.
- Use `https://wid.cert-bund.de/content/public/securityAdvisory/rss`.
- Parse RSS/XML with Python standard library tools.
- Normalize vulnerability advisory items into a simple shared shape.
- Map BSI severity values like `niedrig`, `mittel`, `hoch`, and `kritisch`.
- Show the data in a small dashboard section or API endpoint.
- Keep the UI simple.

Normalized fields:

- `id`
- `title`
- `summary`
- `source`
- `url`
- `published`
- `category`
- `severity`

Research notes:

- BSI WID RSS is a strong second source because it is security-specific and does not require an API key.
- It returns German advisory text, so label the source clearly.
- RSS fields map well: `title`, `link`, `description`, `category`, and `pubDate`.

Test:

- Check the new API route.
- Confirm dashboard data still renders.
- Confirm fallback behavior if the source is unavailable.

### Step 11: Connect Admin Reports To Dashboard

Commit idea:

```text
Week 2: show admin reports on dashboard
```

Work:

- Show admin-created reports on the main dashboard.
- Keep reports in memory for now.
- Make the dashboard useful after an admin adds a report.

Test:

- Log in as admin.
- Create a report.
- Return to the dashboard.
- Confirm the report appears.

### Step 12: Threat Graph Mock Data

Commit idea:

```text
Week 2: add threat graph mock data
```

Work:

- Add a small mock graph data source.
- Use nodes like Article, CVE, IOC, Threat Actor, and MITRE Technique.
- Use edges like MENTIONS, EXPLOITS, and RELATED_TO.
- Base the mock graph on NewsAPI articles and BSI advisory data where possible.

Test:

- Add or check an API route that returns the graph JSON.

### Step 13: Threat Graph Page

Commit idea:

```text
Week 2: add threat graph page
```

Work:

- Add a basic `/threat-graph` page.
- Render mock graph data in the browser.
- Use Cytoscape.js as the first graph library.

Test:

- Open `/threat-graph`.
- Confirm nodes and edges appear.
- Click or hover a node if supported.

### Step 14: Graph Details Panel

Commit idea:

```text
Week 2: add graph node details
```

Work:

- Show simple details when a graph node is clicked.
- Display type, label, and short description.

Test:

- Click several nodes.
- Confirm the details panel updates.

### Step 15: Google Cloud Deployment Prep

Commit idea:

```text
Week 2: prepare Cloud Run deployment
```

Work:

- Add a minimal `requirements.txt`.
- Add a simple production start command.
- Add notes for required environment variables.

Test:

- Install dependencies from `requirements.txt`.
- Run the app locally.

### Step 16: Secret Handling Notes

Commit idea:

```text
Week 2: document secret handling
```

Work:

- Document that API keys belong in environment variables or Secret Manager.
- Do not commit real keys.
- Keep the note short and practical.

Test:

- Confirm no secrets are in tracked files.

### Step 17: Firestore Planning Spike

Commit idea:

```text
Week 2: document Firestore data model
```

Work:

- Sketch Firestore collections for articles, reports, users, and graph nodes.
- Do not migrate the app yet unless needed.

Test:

- Review the model for simplicity.

### Step 18: Vertex AI Planning Spike

Commit idea:

```text
Week 2: document Vertex AI summary flow
```

Work:

- Document where Vertex AI could generate summaries.
- Start with mocked AI summaries before calling the real service.
- Keep the first AI feature optional.

Test:

- Confirm the plan does not block the current app.

### Step 19: Final Week 2 Polish

Commit idea:

```text
Week 2: polish dashboard for demo
```

Work:

- Fix small layout issues.
- Check wording.
- Remove dead links or broken UI.
- Keep changes small.

Test:

- Run through the demo as a user.
- Run through the demo as an admin.
- Check the main API routes.

## Not Yet

These are good ideas, but probably not first:

- Full Next.js migration
- FastAPI rewrite
- Real PostgreSQL schema
- Redis workers
- WebSockets
- A2UI implementation
- Full graph database migration

We can revisit these after the Flask product version is stronger.
