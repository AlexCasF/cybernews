# CyberNews Week 3 Progress

## Current Step

Step 6: EPSS Risk Labels

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

### Responsive Dashboard Layout

Status: DONE

Commit: Week 3: make dashboard layout responsive

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

Commit: Week 3: add KEV refresh

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

Commit: Week 3: simplify dashboard navigation

Tested:

- Checked `/` returns `200`.
- Checked same-page nav links for Headlines, Intelligence, Vulnerabilities, and System are removed.
- Checked route-level nav links are still present.
- Checked `/health` still returns the health message.

Notes:

- Removed dashboard section anchors from the main menu.
- Kept Dashboard, Threat Graph, Admin Reports, and Login/Logout links.

### Step 4: EPSS Scoring API

Status: DONE

Commit: Week 3: add EPSS scoring API

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

Commit: Week 3: enrich KEV API with EPSS

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

Commit: Week 3: show EPSS risk labels

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
