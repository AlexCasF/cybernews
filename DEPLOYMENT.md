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

## Cloud Run Start Command

For Google Cloud Run, use:

```bash
gunicorn --bind 0.0.0.0:$PORT src.web_app:app
```

Cloud Run provides the `PORT` variable automatically.
