import hashlib
import re
from datetime import datetime
from urllib.parse import urlparse

try:
    from google.cloud import firestore
except ImportError:
    firestore = None


MEMORY_AI_JOBS = {}
MEMORY_REPORTS = {}
MEMORY_FEED_ITEMS = {}
MEMORY_ARTICLE_CORRELATIONS = {}
MEMORY_EXTERNAL_CONTEXT_CACHE = {}
MEMORY_ANALYST_FEEDBACK = {}
MEMORY_REPORT_VERSIONS = {}
MEMORY_DETECTION_RULES = {}
FIRESTORE_CLIENT = None
FIRESTORE_CHECKED = False
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_PATTERN = re.compile(r"https?://[^\s]+")
EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}\b")
HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
WORD_PATTERN = re.compile(r"[a-z][a-z0-9-]{3,}")
STOP_WORDS = {
    "about",
    "after",
    "also",
    "been",
    "from",
    "have",
    "into",
    "more",
    "news",
    "over",
    "that",
    "their",
    "this",
    "with",
}


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


def save_analyst_feedback(feedback):
    db = get_firestore_client()

    if db:
        try:
            db.collection("analyst_feedback").document(feedback["feedback_id"]).set(feedback)
            return
        except Exception:
            pass

    MEMORY_ANALYST_FEEDBACK[feedback["feedback_id"]] = feedback


def list_analyst_feedback(job_id=None):
    db = get_firestore_client()

    if db:
        try:
            feedback_items = [document.to_dict() for document in db.collection("analyst_feedback").stream()]
        except Exception:
            feedback_items = list(MEMORY_ANALYST_FEEDBACK.values())
    else:
        feedback_items = list(MEMORY_ANALYST_FEEDBACK.values())

    if job_id:
        feedback_items = [
            item
            for item in feedback_items
            if item.get("job_id") == job_id
        ]

    return sorted(feedback_items, key=lambda item: item.get("created_at", ""), reverse=True)


def save_report(report):
    db = get_firestore_client()

    if db:
        try:
            db.collection("reports").document(report["report_id"]).set(report)
            return
        except Exception:
            pass

    MEMORY_REPORTS[report["report_id"]] = report


def save_report_version(version):
    db = get_firestore_client()

    if db:
        try:
            db.collection("report_versions").document(version["version_id"]).set(version)
            return
        except Exception:
            pass

    MEMORY_REPORT_VERSIONS[version["version_id"]] = version


def list_report_versions(report_id):
    db = get_firestore_client()

    if db:
        try:
            versions = [
                document.to_dict()
                for document in db.collection("report_versions")
                .where("report_id", "==", report_id)
                .stream()
            ]
        except Exception:
            versions = [
                version
                for version in MEMORY_REPORT_VERSIONS.values()
                if version.get("report_id") == report_id
            ]
    else:
        versions = [
            version
            for version in MEMORY_REPORT_VERSIONS.values()
            if version.get("report_id") == report_id
        ]

    return sorted(versions, key=lambda version: version.get("created_at", ""))


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


def save_detection_rule(rule):
    db = get_firestore_client()

    if db:
        try:
            db.collection("detection_rules").document(rule["rule_id"]).set(rule)
            return
        except Exception:
            pass

    MEMORY_DETECTION_RULES[rule["rule_id"]] = rule


def get_detection_rule(rule_id):
    db = get_firestore_client()

    if db:
        try:
            document = db.collection("detection_rules").document(rule_id).get()
        except Exception:
            return MEMORY_DETECTION_RULES.get(rule_id)

        if document.exists:
            return document.to_dict()

        return None

    return MEMORY_DETECTION_RULES.get(rule_id)


def list_detection_rules():
    db = get_firestore_client()

    if db:
        try:
            rules = [document.to_dict() for document in db.collection("detection_rules").stream()]
        except Exception:
            rules = list(MEMORY_DETECTION_RULES.values())
    else:
        rules = list(MEMORY_DETECTION_RULES.values())

    return sorted(rules, key=lambda rule: rule.get("created_at", ""), reverse=True)


def delete_report(report_id):
    db = get_firestore_client()
    deleted = False

    if db:
        try:
            document = db.collection("reports").document(report_id)
            snapshot = document.get()

            if snapshot.exists:
                document.delete()
                deleted = True
        except Exception:
            pass

    if report_id in MEMORY_REPORTS:
        del MEMORY_REPORTS[report_id]
        deleted = True

    return deleted


def get_feed_item(item_id):
    db = get_firestore_client()

    if db:
        try:
            document = db.collection("feed_items").document(item_id).get()
        except Exception:
            return MEMORY_FEED_ITEMS.get(item_id)

        if document.exists:
            return document.to_dict()

        return None

    return MEMORY_FEED_ITEMS.get(item_id)


def normalize_terms(values):
    normalized = []

    for value in values:
        clean_value = str(value).strip().lower()

        if clean_value and clean_value not in normalized:
            normalized.append(clean_value)

    return normalized


def build_article_index_fields(item):
    text = f"{item.get('title', '')} {item.get('summary', '')}"
    lower_text = text.lower()
    words = [
        word
        for word in WORD_PATTERN.findall(lower_text)
        if word not in STOP_WORDS
    ]
    keyphrases = []
    title_words = [
        word
        for word in WORD_PATTERN.findall(str(item.get("title", "")).lower())
        if word not in STOP_WORDS
    ]

    for index in range(max(0, len(title_words) - 1)):
        phrase = f"{title_words[index]} {title_words[index + 1]}"

        if phrase not in keyphrases:
            keyphrases.append(phrase)

    urls = URL_PATTERN.findall(text)
    parsed_url = urlparse(item.get("url", ""))
    source_hostname = parsed_url.netloc.lower()
    ioc_values = urls + IPV4_PATTERN.findall(text) + EMAIL_PATTERN.findall(text) + HASH_PATTERN.findall(text)

    return {
        "search_terms": normalize_terms(words[:40]),
        "keyphrases": keyphrases[:12],
        "cve_ids": sorted({match.upper() for match in CVE_PATTERN.findall(text)}),
        "ioc_values": normalize_terms(ioc_values),
        "entity_terms": normalize_terms(title_words[:12]),
        "source_hostname": source_hostname,
        "indexed_at": datetime.utcnow().isoformat(),
        "index_version": "article-index-v1",
    }


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


def save_feed_items(feed_items):
    db = get_firestore_client()
    saved_count = 0

    indexed_items = []

    for item in feed_items:
        indexed_item = dict(item)
        indexed_item.update(build_article_index_fields(indexed_item))
        indexed_items.append(indexed_item)

    if db:
        for item in indexed_items:
            try:
                db.collection("feed_items").document(item["id"]).set(item)
                saved_count += 1
            except Exception:
                MEMORY_FEED_ITEMS[item["id"]] = item
                saved_count += 1

        return saved_count

    for item in indexed_items:
        MEMORY_FEED_ITEMS[item["id"]] = item
        saved_count += 1

    return saved_count


def list_feed_items():
    db = get_firestore_client()

    if db:
        try:
            feed_items = [document.to_dict() for document in db.collection("feed_items").stream()]
        except Exception:
            feed_items = list(MEMORY_FEED_ITEMS.values())
    else:
        feed_items = list(MEMORY_FEED_ITEMS.values())

    return sorted(
        feed_items,
        key=lambda item: item.get("published_sort", ""),
        reverse=True,
    )


def save_article_index(item_id, index_fields):
    item = get_feed_item(item_id)

    if not item:
        return False

    item.update(index_fields)
    save_feed_items([item])
    return True


def get_correlation_id(primary_article_id, related_article_id):
    digest = hashlib.sha256(f"{primary_article_id}|{related_article_id}".encode("utf-8")).hexdigest()[:24]
    return f"corr-{digest}"


def save_article_correlations(article_id, correlations):
    db = get_firestore_client()
    saved_count = 0

    if db:
        for correlation in correlations:
            correlation_id = get_correlation_id(article_id, correlation["related_article_id"])
            try:
                db.collection("article_correlations").document(correlation_id).set(correlation)
                saved_count += 1
            except Exception:
                MEMORY_ARTICLE_CORRELATIONS[correlation_id] = correlation
                saved_count += 1

        return saved_count

    for correlation in correlations:
        correlation_id = get_correlation_id(article_id, correlation["related_article_id"])
        MEMORY_ARTICLE_CORRELATIONS[correlation_id] = correlation
        saved_count += 1

    return saved_count


def list_article_correlations(article_id):
    db = get_firestore_client()

    if db:
        try:
            correlations = [
                document.to_dict()
                for document in db.collection("article_correlations")
                .where("primary_article_id", "==", article_id)
                .stream()
            ]
        except Exception:
            correlations = [
                correlation
                for correlation in MEMORY_ARTICLE_CORRELATIONS.values()
                if correlation.get("primary_article_id") == article_id
            ]
    else:
        correlations = [
            correlation
            for correlation in MEMORY_ARTICLE_CORRELATIONS.values()
            if correlation.get("primary_article_id") == article_id
        ]

    return sorted(correlations, key=lambda correlation: correlation.get("score", 0), reverse=True)


def get_external_cache_id(item):
    raw_key = f"{item.get('origin', '')}|{item.get('query', '')}|{item.get('url', '')}|{item.get('title', '')}|{item.get('cve_id', '')}"
    digest = hashlib.sha256(raw_key.lower().encode("utf-8")).hexdigest()[:24]
    return f"ext-{digest}"


def save_external_context_cache(items):
    db = get_firestore_client()
    saved_count = 0

    for item in items:
        cache_item = dict(item)
        cache_item.setdefault("first_seen_by_app", datetime.utcnow().isoformat())
        cache_item["last_used_at"] = datetime.utcnow().isoformat()
        cache_item.setdefault("ttl_days", 30)
        cache_id = get_external_cache_id(cache_item)

        if db:
            try:
                db.collection("external_context_cache").document(cache_id).set(cache_item)
                saved_count += 1
                continue
            except Exception:
                pass

        MEMORY_EXTERNAL_CONTEXT_CACHE[cache_id] = cache_item
        saved_count += 1

    return saved_count


def list_external_context_cache(query_key=None):
    db = get_firestore_client()

    if db:
        try:
            items = [document.to_dict() for document in db.collection("external_context_cache").stream()]
        except Exception:
            items = list(MEMORY_EXTERNAL_CONTEXT_CACHE.values())
    else:
        items = list(MEMORY_EXTERNAL_CONTEXT_CACHE.values())

    if query_key:
        clean_key = query_key.lower()
        items = [
            item
            for item in items
            if clean_key in str(item.get("query", "")).lower()
        ]

    return items
