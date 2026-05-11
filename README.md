# CyberNews

CyberNews is a small Flask cybersecurity dashboard for a school project.

It includes:

- Local demo headlines with filters
- Live NewsAPI headline refresh
- BSI advisory feed refresh
- Demo login with user and admin roles
- Admin-created intelligence reports
- A simple threat graph with clickable nodes
- Cloud Run deployment notes

## Run Locally

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the app:

```bash
python -m flask --app src/web_app.py run --port 5050
```

Open:

```text
http://127.0.0.1:5050/
```

## Environment Variables

- `NEWS_API_KEY`: enables live NewsAPI headlines.
- `SECRET_KEY`: protects Flask sessions.
- `PORT`: optional local port when running `python src/web_app.py`.
- `FLASK_DEBUG`: set to `1` only for local debugging.

The app still runs without `NEWS_API_KEY`, but live news falls back to local demo articles.

Copy `.env.example` if you want a local checklist of the values you need. Do not commit real secrets.

## Demo Users

```text
alice / alicepass  -> user
bob / bobpass      -> admin
```

## Main Routes

- `/` - dashboard
- `/login` - login page
- `/admin/reports` - admin report form
- `/threat-graph` - threat graph page
- `/api/ai/jobs` - AI Workbench job endpoint
- `/api/reports` - saved report list/create endpoint
- `/health` - health check

## Deploy

Deployment notes for Google Cloud Run are in `DEPLOYMENT.md`.
