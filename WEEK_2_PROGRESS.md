# CyberNews Week 2 Progress

## Current Step

Step 9: Threat Graph Mock Data

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

Commit: Week 2: display intelligence report cards

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

### Step 9: Threat Graph Mock Data

Status: TODO

Commit: -

Tested:

- -

Notes:

- -

### Step 10: Threat Graph Page

Status: TODO

Commit: -

Tested:

- -

Notes:

- -

### Step 11: Graph Details Panel

Status: TODO

Commit: -

Tested:

- -

Notes:

- -

### Step 12: Google Cloud Deployment Prep

Status: TODO

Commit: -

Tested:

- -

Notes:

- -

### Step 13: Secret Handling Notes

Status: TODO

Commit: -

Tested:

- -

Notes:

- -

### Step 14: Firestore Planning Spike

Status: TODO

Commit: -

Tested:

- -

Notes:

- -

### Step 15: Vertex AI Planning Spike

Status: TODO

Commit: -

Tested:

- -

Notes:

- -

### Step 16: Final Week 2 Polish

Status: TODO

Commit: -

Tested:

- -

Notes:

- -
