# CyberNews Deployment Notes

This project is prepared for Google Cloud Run using either Python buildpacks or the included `Dockerfile`.

Cloud Run deploys from source with `gcloud run deploy --source .`, then starts the app with the `Procfile` command:

```text
web: gunicorn --bind 0.0.0.0:$PORT src.web_app:app
```

Cloud Run provides the `PORT` environment variable automatically, and the app must listen on that port.

For Cloud Build CI/CD, use the `Dockerfile`. It installs `requirements.txt`, copies `src/`, and starts the same Gunicorn command.

Sources:

- https://cloud.google.com/run/docs/deploying-source-code
- https://cloud.google.com/run/docs/container-contract

## Required Files

- `requirements.txt` lists Python dependencies.
- `Procfile` tells Cloud Run how to start Gunicorn.
- `.gcloudignore` keeps local-only files out of the source upload.
- `Dockerfile` gives Cloud Build a predictable container build.
- `.dockerignore` keeps local-only files out of the container image.
- `.env.example` documents local environment variables without real secrets.

## Environment Variables

- `SECRET_KEY`: required for production session security.
- `NEWS_API_KEY`: optional, enables live NewsAPI headlines.
- `GOOGLE_CLOUD_PROJECT`: Google Cloud project used by Vertex AI.
- `VERTEX_AI_LOCATION`: Vertex AI location, currently `global`.
- `GEMINI_MODEL`: Gemini model name, currently `gemini-2.5-flash`.
- `PORT`: provided by Cloud Run automatically.
- `FLASK_DEBUG`: local-only; do not set this to `1` in production.

For a simple school demo, Cloud Run environment variables are fine. Later, move secrets such as `SECRET_KEY` and API keys into Secret Manager.

The app uses Firestore automatically when Google Cloud credentials are available. Locally, it falls back to in-memory storage if Firestore cannot be reached.

Article analysis uses Gemini through Vertex AI when available. If Vertex AI is unavailable, the app falls back to the existing mock AI result so the dashboard still works.

The Cloud Run runtime service account needs `roles/aiplatform.user` to call Gemini through Vertex AI.

## Local Smoke Test

PowerShell:

```powershell
pip install -r requirements.txt
$env:PORT = "5050"
$env:FLASK_DEBUG = "1"
python src/web_app.py
```

Open:

```text
http://127.0.0.1:5050/
http://127.0.0.1:5050/health
```

The health route should return:

```text
CyberNews is running.
```

## Cloud Run First Deploy

Replace `PROJECT_ID`, region, and secret values with your own.

PowerShell:

```powershell
gcloud auth login
gcloud config set project PROJECT_ID

gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com

gcloud run deploy cybernews `
  --source . `
  --region europe-west1 `
  --allow-unauthenticated `
  --set-env-vars SECRET_KEY="replace-with-a-long-random-secret",NEWS_API_KEY="replace-with-newsapi-key"
```

If you do not have a NewsAPI key ready, deploy with only `SECRET_KEY`. The dashboard will still work, but live NewsAPI headlines will fall back to local demo data.

## Cloud Build CI/CD Notes

When setting up a Cloud Build trigger in the Google Cloud Console:

- Repository: this GitHub repository.
- Event: push to `main`.
- Build type: Dockerfile.
- Dockerfile location: `Dockerfile`.
- Image name example: `europe-west1-docker.pkg.dev/PROJECT_ID/cybernews/cybernews:$COMMIT_SHA`.

Then configure the trigger or a follow-up deploy step to deploy that image to Cloud Run.

For first setup, the Console flow is easier. Later we can add a `cloudbuild.yaml` when we want the build and deploy steps versioned in Git.

## Update Environment Variables Later

```powershell
gcloud run services update cybernews `
  --region europe-west1 `
  --set-env-vars SECRET_KEY="replace-with-a-long-random-secret",NEWS_API_KEY="replace-with-newsapi-key"
```

## Redeploy After Code Changes

Run the same deploy command again:

```powershell
gcloud run deploy cybernews `
  --source . `
  --region europe-west1 `
  --allow-unauthenticated
```

## After Deploy

Open the Cloud Run service URL and check:

- `/health`
- `/`
- `/api/reports`
- Live source buttons on the dashboard
- AI Workbench report save/load flow
- Firestore collections named `reports` and `ai_jobs`

## Current Limitation

These data types are now stored in Firestore when deployed to Cloud Run:

- AI jobs
- saved reports

Some data is still stored in memory:

- admin-created reports
- audit log

The remaining in-memory data is acceptable for the current demo, but it resets when the service restarts or scales down.

## Delete the Demo Service

```powershell
gcloud run services delete cybernews --region europe-west1
```
