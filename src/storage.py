try:
    from google.cloud import firestore
except ImportError:
    firestore = None


MEMORY_AI_JOBS = {}
MEMORY_REPORTS = {}
FIRESTORE_CLIENT = None
FIRESTORE_CHECKED = False


def get_firestore_client():
    global FIRESTORE_CHECKED, FIRESTORE_CLIENT

    if firestore is None:
        return None

    if FIRESTORE_CHECKED:
        return FIRESTORE_CLIENT

    FIRESTORE_CHECKED = True

    try:
        FIRESTORE_CLIENT = firestore.Client()
    except Exception:
        FIRESTORE_CLIENT = None

    return FIRESTORE_CLIENT


def save_ai_job(job):
    db = get_firestore_client()

    if db:
        try:
            db.collection("ai_jobs").document(job["job_id"]).set(job)
            return
        except Exception:
            pass

    MEMORY_AI_JOBS[job["job_id"]] = job


def get_ai_job(job_id):
    db = get_firestore_client()

    if db:
        try:
            document = db.collection("ai_jobs").document(job_id).get()
        except Exception:
            return MEMORY_AI_JOBS.get(job_id)

        if document.exists:
            return document.to_dict()

        return None

    return MEMORY_AI_JOBS.get(job_id)


def save_report(report):
    db = get_firestore_client()

    if db:
        try:
            db.collection("reports").document(report["report_id"]).set(report)
            return
        except Exception:
            pass

    MEMORY_REPORTS[report["report_id"]] = report


def get_report(report_id):
    db = get_firestore_client()

    if db:
        try:
            document = db.collection("reports").document(report_id).get()
        except Exception:
            return MEMORY_REPORTS.get(report_id)

        if document.exists:
            return document.to_dict()

        return None

    return MEMORY_REPORTS.get(report_id)


def list_reports():
    db = get_firestore_client()

    if db:
        try:
            reports = [document.to_dict() for document in db.collection("reports").stream()]
        except Exception:
            reports = list(MEMORY_REPORTS.values())
    else:
        reports = list(MEMORY_REPORTS.values())

    return sorted(
        reports,
        key=lambda report: report["created_at"],
        reverse=True,
    )
