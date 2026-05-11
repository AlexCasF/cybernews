# CyberNews Deployment Notes

## Local Setup

Install dependencies:

```bash
pip install -r requirements.txt
```

Run locally:

```bash
python -m flask --app src/web_app.py run --port 5050
```

## Environment Variables

- `NEWS_API_KEY`: used for live NewsAPI headlines.
- `SECRET_KEY`: used by Flask to protect sessions.

Do not commit real secret values.

For local PowerShell testing:

```powershell
$env:NEWS_API_KEY = "your-newsapi-key"
$env:SECRET_KEY = "your-local-secret-key"
```

For Cloud Run:

- Store real values outside Git.
- Start with Cloud Run environment variables for a simple school demo.
- Later, move sensitive values into Google Secret Manager.
- Keep `SECRET_KEY` different between local development and production.

## Cloud Run Start Command

For Google Cloud Run, use:

```bash
gunicorn --bind 0.0.0.0:$PORT src.web_app:app
```

Cloud Run provides the `PORT` variable automatically.

## Pre-Deploy Checklist

- Confirm `requirements.txt` installs successfully.
- Confirm `/health` returns `CyberNews is running.`
- Confirm `NEWS_API_KEY` is set if live news should work.
- Confirm `SECRET_KEY` is set before deploying publicly.
- Confirm no real API keys or secrets are committed.
