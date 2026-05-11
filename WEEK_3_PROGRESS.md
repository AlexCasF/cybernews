# CyberNews Week 3 Progress

## Current Step

Step 2: Vulnerability Dashboard Panel

Status: DONE

## Progress Log

### Data Source Research

Status: DONE

Commit: Week 3: document data source plan

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

Commit: Week 3: add CISA KEV API

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

Commit: Week 3: show KEV vulnerabilities

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
