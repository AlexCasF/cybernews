# CyberNews Week 3 Plan

Week 3 is about adding stronger threat intelligence data sources.

The goal is to move from "news dashboard" toward "vulnerability intelligence dashboard" while keeping each commit small and readable.

## Core Rules

- Work on one feature at a time.
- Keep each commit focused on one small feature or one part of a feature.
- Test the current step before committing.
- Stop after each finished step so Alex can review before pushing.
- Prefer public/free sources first.
- Keep API output normalized and easy to inspect.

## Target Direction

Week 3 should focus on:

- CISA KEV known exploited vulnerabilities
- EPSS exploit probability scoring
- More cybersecurity RSS sources
- CVE nodes in the threat graph
- A small path toward IOC enrichment later

Do not start Vertex AI, Next.js, FastAPI, or Firestore migration until the normal live data features work well.

## Step-by-Step Plan

### Step 1: CISA KEV API

Commit idea:

```text
add CISA KEV API
```

Work:

- Add a CISA KEV source URL.
- Fetch the public KEV JSON catalog.
- Normalize the newest vulnerabilities into a simple shape.
- Add `/api/kev-vulnerabilities`.
- Do not add dashboard UI yet.

Normalized fields:

- `id`
- `cve`
- `vendor`
- `product`
- `title`
- `summary`
- `date_added`
- `due_date`
- `known_ransomware_use`
- `required_action`
- `source`

Test:

- Check `/api/kev-vulnerabilities`.
- Confirm it returns vulnerability JSON.
- Confirm `/health` still works.

### Step 2: Vulnerability Dashboard Panel

Commit idea:

```text
show KEV vulnerabilities
```

Work:

- Add a dashboard section for known exploited vulnerabilities.
- Show CVE ID, vendor/product, title, date added, due date, and ransomware-use status.
- Keep the list short.

Test:

- Open `/`.
- Confirm the vulnerability panel appears.
- Confirm missing/failed KEV data shows a simple message.

### Step 3: KEV Refresh Button

Commit idea:

```text
add KEV refresh
```

Work:

- Add a browser-side refresh button.
- Fetch `/api/kev-vulnerabilities`.
- Re-render vulnerability cards without reloading the page.

Test:

- Click the refresh button.
- Confirm the list updates or shows a clear error message.

### Step 4: EPSS Scoring API

Commit idea:

```text
add EPSS scoring API
```

Work:

- Add a helper that queries FIRST EPSS by CVE ID.
- Add a simple route such as `/api/epss/<cve_id>`.
- Return `cve`, `epss`, `percentile`, and `date`.

Test:

- Check `/api/epss/CVE-2021-44228`.
- Confirm `/health` still works.

### Step 5: EPSS Labels On Vulnerabilities

Commit idea:

```text
show EPSS scores on KEV cards
```

Work:

- Add EPSS values to displayed KEV vulnerabilities.
- Show a simple risk label such as Low, Medium, High, or Very High.
- Keep the logic easy to explain.

Test:

- Open the dashboard.
- Confirm vulnerabilities show EPSS score labels.

### Step 6: CVE Graph Nodes

Commit idea:

```text
add CVE nodes to threat graph
```

Work:

- Add CVE/vulnerability nodes to `/api/threat-graph`.
- Connect CVEs to affected products or mock threat actors.
- Keep the visual graph simple.

Test:

- Open `/api/threat-graph`.
- Open `/threat-graph`.
- Confirm CVE nodes appear and details still work.

### Step 7: RSS Source Normalization

Commit idea:

```text
normalize RSS news sources
```

Work:

- Add a small reusable RSS parser helper.
- Keep BSI working.
- Prepare source definitions for The Hacker News, SecurityWeek, and BleepingComputer.
- Add only one new source if the diff gets too large.

Test:

- Check existing BSI route.
- Check one new RSS route or combined source route.

### Step 8: More Cybersecurity News Sources

Commit idea:

```text
add security RSS feeds
```

Work:

- Add The Hacker News and SecurityWeek as normalized sources.
- Show source names clearly.
- Keep NewsAPI as optional/general news.

Test:

- Confirm new feed data appears.
- Confirm a failed source does not break the dashboard.

### Step 9: IOC Source Spike

Commit idea:

```text
document IOC source plan
```

Work:

- Review URLhaus, MalwareBazaar, and OpenPhish terms.
- Decide which one is safest for a school demo.
- Do not download malware samples.

Test:

- Confirm the plan is clear before coding.

### Step 10: Mock AI Enrichment

Commit idea:

```text
add mock AI enrichment
```

Work:

- Add a mocked summary or recommendation for one vulnerability or article.
- Keep this as a placeholder for Vertex AI.

Test:

- Confirm the UI explains the result as a demo/mock analysis.

## Not Yet

- Full Next.js migration
- FastAPI rewrite
- Real graph database
- Firestore migration
- Real Vertex AI calls
- WebSockets
- Malware sample download or analysis
