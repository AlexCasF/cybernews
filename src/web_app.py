import html
import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from uuid import uuid4

from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from src.agentic_workflow import run_agentic_article_action
from src.ai_service import (
    explain_cve_risk,
    generate_detection_rule_ai,
    iterate_report_with_ai,
)
from src.storage import (
    delete_report,
    get_ai_job,
    get_detection_rule,
    get_feed_item,
    get_report,
    list_article_correlations,
    list_ai_artifacts,
    list_ai_evidence,
    list_ai_jobs,
    list_detection_rules,
    list_feed_items,
    list_reports,
    save_ai_job,
    save_ai_artifact,
    save_ai_evidence,
    save_analyst_feedback,
    save_detection_rule,
    save_feed_items,
    save_report,
    save_report_version,
    update_article_correlation_status,
)


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")

INITIAL_BACKFILL_DAYS = int(os.getenv("INITIAL_BACKFILL_DAYS", "30"))
ARTICLE_RETENTION_POLICY = os.getenv("ARTICLE_RETENTION_POLICY", "keep_all")
EXTERNAL_SEARCH_POLICY = os.getenv("EXTERNAL_SEARCH_POLICY", "auto")

USERS = {
    "Alex": {
        "password_hash": "scrypt:32768:8:1$fTWfMRT6mzUwlYkT$92d77430ce3f9049b1aec1b090dbc28efbf800510e452e884df92e3871d1e2e1faefa4647185433e5b8bde15f397999f02688201056afb43135419ff4982431f",
        "role": "admin",
    },
    "Cybersteps": {
        "password_hash": "scrypt:32768:8:1$rVJ43bC4mPB3jEGm$542fa68a32bc8a300e98fafd6b3dd1d48876df6041b6080417176e1ee50ae2de72bc5fc03d1d6eacd767b88ee2eec0b4ad867cdac0f17c320d38933b5d482968",
        "role": "user",
    },
}
AUDIT_LOG = []
NEWSAPI_URL = "https://newsapi.org/v2/everything"
HN_TOP_STORIES_URL = "https://hacker-news.firebaseio.com/v0/topstories.json"
HN_ITEM_URL = "https://hacker-news.firebaseio.com/v0/item/{item_id}.json"
BSI_RSS_URL = "https://wid.cert-bund.de/content/public/securityAdvisory/rss"
CISA_ADVISORIES_RSS_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SECURITY_RSS_SOURCES = [
    {
        "name": "The Hacker News",
        "url": "https://thehackernews.com/feeds/posts/default",
    },
    {
        "name": "SecurityWeek",
        "url": "https://www.securityweek.com/feed/",
    },
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
    },
]
NEWSAPI_BACKFILL_QUERIES = [
    "cybersecurity",
    "CVE OR vulnerability",
    "ransomware OR malware",
    "phishing OR breach",
]
HN_SECURITY_TERMS = [
    "security",
    "cyber",
    "vulnerability",
    "cve",
    "malware",
    "ransomware",
    "phishing",
    "breach",
    "exploit",
    "privacy",
    "encryption",
    "authentication",
]
AI_ACTIONS = {
    "summarize",
    "analyze",
    "extract_iocs",
    "extract_cves",
    "show_connections",
    "generate_report",
    "cve_enrichment",
    "ioc_enrichment",
    "attack_mapping",
    "severity_classification",
    "generate_detection",
    "recommend_remediation",
}
AI_ENTITY_TYPES = {
    "article",
    "advisory",
    "cve",
    "ioc",
    "attack_technique",
    "incident",
    "report",
}
AI_CONTEXT_DEPTHS = {"low", "medium", "high"}
AI_OUTPUT_FORMATS = {"structured_json", "html_report", "both"}


def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def record_login_attempt(username, success, role=""):
    AUDIT_LOG.append(
        {
            "timestamp": get_timestamp(),
            "username": username or "unknown",
            "result": "success" if success else "failed",
            "role": role,
        }
    )


def get_current_user():
    username = session.get("username")

    if not username or username not in USERS:
        return None

    return {
        "username": username,
        "role": USERS[username]["role"],
    }


def user_is_admin(user):
    return user and user["role"] == "admin"


def is_safe_next_url(next_url):
    return next_url and next_url.startswith("/") and not next_url.startswith("//")


@app.before_request
def require_login():
    public_endpoints = {"login", "logout", "health", "static"}

    if request.endpoint in public_endpoints:
        return None

    if get_current_user():
        return None

    if request.path.startswith("/api/"):
        return jsonify({"error": "Login required."}), 401

    return redirect(url_for("login", next=request.path))


def guess_article_category(text):
    lower_text = text.lower()

    if "phishing" in lower_text:
        return "Phishing"

    if "malware" in lower_text or "ransomware" in lower_text:
        return "Malware"

    if "vulnerability" in lower_text or "bug" in lower_text or "cve" in lower_text:
        return "Vulnerability"

    return "News"


def guess_article_severity(category):
    if category == "Vulnerability":
        return "High"

    if category in ["Malware", "Phishing"]:
        return "Medium"

    return "Low"


def normalize_newsapi_article(article, index):
    title = article.get("title") or "Untitled article"
    summary = article.get("description") or "No summary available."
    category = guess_article_category(f"{title} {summary}")

    return {
        "id": f"live-{index}",
        "title": title,
        "summary": summary,
        "source": article.get("source", {}).get("name") or "NewsAPI",
        "url": article.get("url") or "#",
        "published": (article.get("publishedAt") or "")[:10] or "Unknown date",
        "category": category,
        "severity": guess_article_severity(category),
    }


def get_live_news_articles(days=None, page_size=50, queries=None):
    api_key = os.getenv("NEWS_API_KEY")

    if not api_key:
        return {
            "articles": [],
            "source": "newsapi",
            "message": "NEWS_API_KEY is missing. NewsAPI articles are unavailable.",
        }

    query_list = queries or ["cybersecurity"]
    live_articles = []
    seen_urls = set()
    failed_queries = 0

    for search_query in query_list:
        params = {
            "q": search_query,
            "language": "en",
            "sortBy": "publishedAt",
            "pageSize": min(page_size, 100),
            "apiKey": api_key,
        }

        if days:
            params["from"] = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")

        try:
            with urlopen(f"{NEWSAPI_URL}?{urlencode(params)}", timeout=10) as response:
                data = json.loads(response.read().decode("utf-8"))
        except Exception:
            failed_queries += 1
            continue

        if data.get("status") != "ok":
            failed_queries += 1
            continue

        for article in data.get("articles", []):
            url = article.get("url")

            if not article.get("title") or not url or url in seen_urls:
                continue

            seen_urls.add(url)
            live_articles.append(normalize_newsapi_article(article, len(live_articles) + 1))

    if not live_articles:
        return {
            "articles": [],
            "source": "newsapi",
            "message": "No NewsAPI articles were found." if failed_queries == 0 else "NewsAPI is unavailable right now.",
        }

    return {
        "articles": live_articles,
        "source": "newsapi",
        "message": f"NewsAPI articles loaded from {len(query_list) - failed_queries} query set(s).",
    }


def normalize_bsi_severity(severity):
    severity_map = {
        "kritisch": "Critical",
        "hoch": "High",
        "mittel": "Medium",
        "niedrig": "Low",
    }

    return severity_map.get(severity.lower(), "Unknown")


def get_element_text(parent, name, default=""):
    element = parent.find(name)

    if element is None or element.text is None:
        return default

    return element.text.strip()


def clean_bsi_title(title):
    return re.sub(r"^(\[[^\]]+\]\s*)+", "", title).strip()


def clean_text(text):
    without_tags = re.sub(r"<[^>]+>", "", text or "")
    return html.unescape(without_tags).strip()


def normalize_bsi_item(item, index):
    title = get_element_text(item, "title", "Untitled advisory")
    severity = get_element_text(item, "category", "unknown")

    return {
        "id": f"bsi-{index}",
        "title": clean_bsi_title(title),
        "summary": get_element_text(item, "description", "No summary available."),
        "source": "BSI WID",
        "url": get_element_text(item, "link", "#"),
        "published": get_element_text(item, "pubDate", "Unknown date"),
        "category": "Vulnerability Advisory",
        "severity": normalize_bsi_severity(severity),
    }


def get_atom_link(entry):
    atom_namespace = "{http://www.w3.org/2005/Atom}"
    link = entry.find(f"{atom_namespace}link")

    if link is None:
        return "#"

    return link.get("href") or "#"


def normalize_atom_entry(entry, source_name, source_slug, index):
    atom_namespace = "{http://www.w3.org/2005/Atom}"
    title = get_element_text(entry, f"{atom_namespace}title", "Untitled article")
    summary = get_element_text(entry, f"{atom_namespace}summary", "")
    content = get_element_text(entry, f"{atom_namespace}content", "")
    published = get_element_text(entry, f"{atom_namespace}published", "")
    updated = get_element_text(entry, f"{atom_namespace}updated", "Unknown date")
    clean_summary = clean_text(summary or content) or "No summary available."
    category = guess_article_category(f"{title} {clean_summary}")

    return {
        "id": f"{source_slug}-{index}",
        "title": clean_text(title),
        "summary": clean_summary,
        "source": source_name,
        "url": get_atom_link(entry),
        "published": (published or updated)[:10],
        "category": category,
        "severity": guess_article_severity(category),
    }


def normalize_rss_item(item, source_name, source_slug, index):
    title = get_element_text(item, "title", "Untitled article")
    summary = get_element_text(item, "description", "No summary available.")
    clean_summary = clean_text(summary) or "No summary available."
    category = guess_article_category(f"{title} {clean_summary}")

    return {
        "id": f"{source_slug}-{index}",
        "title": clean_text(title),
        "summary": clean_summary,
        "source": source_name,
        "url": get_element_text(item, "link", "#"),
        "published": get_element_text(item, "pubDate", "Unknown date"),
        "category": category,
        "severity": guess_article_severity(category),
    }


def get_security_rss_articles():
    articles = []
    failed_sources = []

    for source in SECURITY_RSS_SOURCES:
        source_slug = re.sub(r"[^a-z0-9]+", "-", source["name"].lower()).strip("-")

        try:
            request_data = Request(
                source["url"],
                headers={"User-Agent": "CyberNewsSchoolProject/1.0"},
            )

            with urlopen(request_data, timeout=8) as response:
                feed_data = response.read()

            root = ET.fromstring(feed_data)
        except Exception:
            failed_sources.append(source["name"])
            continue

        if root.tag.endswith("feed"):
            atom_namespace = "{http://www.w3.org/2005/Atom}"
            entries = root.findall(f"{atom_namespace}entry")
            articles.extend(
                normalize_atom_entry(entry, source["name"], source_slug, index + 1)
                for index, entry in enumerate(entries)
            )
        else:
            items = root.findall("./channel/item")
            articles.extend(
                normalize_rss_item(item, source["name"], source_slug, index + 1)
                for index, item in enumerate(items)
            )

    if articles and failed_sources:
        message = "Security RSS feeds loaded, but some sources were unavailable."
    elif articles:
        message = "Security RSS feeds loaded."
    else:
        message = "Security RSS feeds are unavailable right now."

    return {
        "articles": articles,
        "failed_sources": failed_sources,
        "message": message,
        "source": "security-rss",
    }


def is_hn_security_story(story):
    text = f"{story.get('title', '')} {story.get('url', '')}".lower()
    return any(term in text for term in HN_SECURITY_TERMS)


def normalize_hn_story(story, index):
    title = clean_text(story.get("title", "Untitled HN story"))
    url = story.get("url") or f"https://news.ycombinator.com/item?id={story.get('id')}"
    comments_url = f"https://news.ycombinator.com/item?id={story.get('id')}"
    score = story.get("score", 0)
    comments = story.get("descendants", 0)
    published = datetime.fromtimestamp(story.get("time", 0)).strftime("%Y-%m-%d")
    category = guess_article_category(title)

    return {
        "id": f"hn-{story.get('id', index)}",
        "title": title,
        "summary": f"Hacker News discussion signal: {score} points and {comments} comments. Comments: {comments_url}",
        "source": "Hacker News",
        "url": url,
        "published": published,
        "category": category,
        "severity": guess_article_severity(category),
    }


def get_hacker_news_security_articles(max_scan=25, max_results=8):
    try:
        with urlopen(HN_TOP_STORIES_URL, timeout=8) as response:
            story_ids = json.loads(response.read().decode("utf-8"))
    except Exception:
        return {
            "articles": [],
            "source": "hacker-news",
            "message": "Hacker News community signals are unavailable right now.",
        }

    articles = []

    for story_id in story_ids[:max_scan]:
        if len(articles) >= max_results:
            break

        try:
            with urlopen(HN_ITEM_URL.format(item_id=story_id), timeout=1.5) as response:
                story = json.loads(response.read().decode("utf-8"))
        except Exception:
            continue

        if story.get("type") != "story" or not is_hn_security_story(story):
            continue

        articles.append(normalize_hn_story(story, len(articles) + 1))

    return {
        "articles": articles,
        "source": "hacker-news",
        "message": "Hacker News community signals loaded." if articles else "No relevant Hacker News security stories found right now.",
    }


def get_feed_sort_value(published):
    if not published or published == "Unknown date":
        return ""

    try:
        return datetime.fromisoformat(published[:10]).isoformat()
    except ValueError:
        pass

    try:
        return parsedate_to_datetime(published).isoformat()
    except (TypeError, ValueError):
        return str(published)


def get_feed_item_id(source_type, title, url):
    raw_key = f"{source_type}|{url}|{title}".lower()
    digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:20]

    return f"{source_type}-{digest}"


def is_feed_item_recent(item, days):
    published_sort = item.get("published_sort", "")

    if not published_sort:
        return False

    try:
        published_date = datetime.fromisoformat(published_sort[:10])
    except ValueError:
        return False

    return published_date >= datetime.now() - timedelta(days=days)


def normalize_aggregated_item(item, source_type):
    title = item.get("title", "Untitled item")
    url = item.get("url", "#")
    published = item.get("published", "Unknown date")

    return {
        "id": get_feed_item_id(source_type, title, url),
        "title": title,
        "summary": item.get("summary", "No summary available."),
        "source": item.get("source", source_type),
        "source_type": source_type,
        "url": url,
        "published": published,
        "published_sort": get_feed_sort_value(published),
        "category": item.get("category", "News"),
        "severity": item.get("severity", "Low"),
    }


def get_aggregated_news_feed(save_to_store=False, days=None):
    feed_items = []
    messages = []
    seen_keys = set()

    newsapi_queries = NEWSAPI_BACKFILL_QUERIES if save_to_store else ["cybersecurity"]
    newsapi_page_size = 100 if save_to_store else 50

    source_results = [
        ("newsapi", get_live_news_articles(days=days, page_size=newsapi_page_size, queries=newsapi_queries), "articles"),
        ("security-rss", get_security_rss_articles(), "articles"),
        ("hacker-news", get_hacker_news_security_articles(), "articles"),
        ("bsi", get_bsi_advisories(), "advisories"),
        ("cisa-advisories", get_cisa_advisories(), "advisories"),
    ]

    for source_type, result, item_key in source_results:
        messages.append(result.get("message", ""))

        for item in result.get(item_key, []):
            normalized = normalize_aggregated_item(item, source_type)
            dedupe_key = normalized["url"] if normalized["url"] != "#" else normalized["title"].lower()

            if dedupe_key in seen_keys:
                continue

            seen_keys.add(dedupe_key)
            feed_items.append(normalized)

    if days is not None:
        feed_items = [item for item in feed_items if is_feed_item_recent(item, days)]

    feed_items.sort(
        key=lambda item: item["published_sort"],
        reverse=True,
    )

    saved_count = save_feed_items(feed_items) if save_to_store else 0

    return {
        "items": feed_items,
        "count": len(feed_items),
        "saved_count": saved_count,
        "messages": [message for message in messages if message],
        "source": "aggregated-news",
        "message": "Aggregated news feed loaded.",
    }


def get_stored_news_feed():
    feed_items = list_feed_items()

    return {
        "items": feed_items,
        "count": len(feed_items),
        "saved_count": 0,
        "messages": [],
        "source": "stored-feed",
        "message": "Stored feed loaded." if feed_items else "No stored feed items yet.",
    }


def get_dashboard_feed():
    stored_feed = get_stored_news_feed()

    if stored_feed["items"]:
        return stored_feed

    return get_aggregated_news_feed()


def sync_feed_items(days=INITIAL_BACKFILL_DAYS):
    return get_aggregated_news_feed(save_to_store=True, days=days)


def get_bsi_advisories():
    try:
        with urlopen(BSI_RSS_URL, timeout=8) as response:
            rss_data = response.read()

        root = ET.fromstring(rss_data)
        items = root.findall("./channel/item")
    except Exception:
        return {
            "advisories": [],
            "source": "fallback",
            "message": "BSI advisories are unavailable right now.",
        }

    advisories = [
        normalize_bsi_item(item, index + 1)
        for index, item in enumerate(items)
    ]

    return {
        "advisories": advisories,
        "source": "bsi",
        "message": "BSI advisories loaded.",
    }


def get_cisa_advisories():
    try:
        request_data = Request(
            CISA_ADVISORIES_RSS_URL,
            headers={"User-Agent": "CyberNewsSchoolProject/1.0"},
        )

        with urlopen(request_data, timeout=8) as response:
            rss_data = response.read()

        root = ET.fromstring(rss_data)
        items = root.findall("./channel/item")
    except Exception:
        return {
            "advisories": [],
            "source": "cisa-advisories",
            "message": "CISA advisories are unavailable right now.",
        }

    advisories = [
        normalize_rss_item(item, "CISA Advisories", "cisa-advisories", index + 1)
        for index, item in enumerate(items)
    ]

    for advisory in advisories:
        advisory["category"] = "Vulnerability Advisory"
        advisory["severity"] = guess_article_severity(advisory["category"])

    return {
        "advisories": advisories,
        "source": "cisa-advisories",
        "message": "CISA advisories loaded.",
    }


def get_epss_label(epss_value):
    try:
        epss_number = float(epss_value)
    except (TypeError, ValueError):
        return "Unknown"

    if epss_number >= 0.9:
        return "Very High"

    if epss_number >= 0.5:
        return "High"

    if epss_number >= 0.1:
        return "Medium"

    return "Low"


def get_epss_scores(cve_ids):
    clean_cve_ids = [
        cve_id.upper()
        for cve_id in cve_ids
        if cve_id and cve_id != "Unknown CVE"
    ]

    if not clean_cve_ids:
        return {}

    query = urlencode({"cve": ",".join(clean_cve_ids)})

    try:
        with urlopen(f"{EPSS_URL}?{query}", timeout=8) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception:
        return {}

    return {
        score.get("cve", "").upper(): {
            "epss": score.get("epss", "Unknown"),
            "epss_percentile": score.get("percentile", "Unknown"),
            "epss_date": score.get("date", "Unknown date"),
            "epss_label": get_epss_label(score.get("epss")),
        }
        for score in data.get("data", [])
        if score.get("cve")
    }


def normalize_kev_vulnerability(vulnerability, index, epss_scores=None):
    cve = vulnerability.get("cveID") or "Unknown CVE"
    epss_data = (epss_scores or {}).get(cve.upper(), {})

    return {
        "id": f"kev-{index}",
        "cve": cve,
        "vendor": vulnerability.get("vendorProject") or "Unknown vendor",
        "product": vulnerability.get("product") or "Unknown product",
        "title": vulnerability.get("vulnerabilityName") or "Untitled vulnerability",
        "summary": vulnerability.get("shortDescription") or "No summary available.",
        "date_added": vulnerability.get("dateAdded") or "Unknown date",
        "due_date": vulnerability.get("dueDate") or "Unknown date",
        "epss": epss_data.get("epss", "Unknown"),
        "epss_percentile": epss_data.get("epss_percentile", "Unknown"),
        "epss_date": epss_data.get("epss_date", "Unknown date"),
        "epss_label": epss_data.get("epss_label", "Unknown"),
        "known_ransomware_use": vulnerability.get("knownRansomwareCampaignUse") or "Unknown",
        "required_action": vulnerability.get("requiredAction") or "Review vendor guidance.",
        "source": "CISA KEV",
    }


def get_kev_vulnerabilities():
    try:
        request_data = Request(
            CISA_KEV_URL,
            headers={"User-Agent": "CyberNewsSchoolProject/1.0"},
        )

        with urlopen(request_data, timeout=8) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception:
        return {
            "vulnerabilities": [],
            "source": "fallback",
            "message": "CISA KEV vulnerabilities are unavailable right now.",
        }

    vulnerabilities = sorted(
        data.get("vulnerabilities", []),
        key=lambda vulnerability: vulnerability.get("dateAdded", ""),
        reverse=True,
    )

    latest_vulnerabilities = vulnerabilities[:10]
    epss_scores = get_epss_scores(
        [
            vulnerability.get("cveID")
            for vulnerability in latest_vulnerabilities
        ]
    )

    return {
        "vulnerabilities": [
            normalize_kev_vulnerability(vulnerability, index + 1, epss_scores)
            for index, vulnerability in enumerate(latest_vulnerabilities)
        ],
        "source": "cisa-kev",
        "catalog_version": data.get("catalogVersion", "Unknown"),
        "date_released": data.get("dateReleased", "Unknown"),
        "message": "CISA KEV vulnerabilities loaded.",
    }


def get_epss_score(cve_id):
    query = urlencode({"cve": cve_id})

    try:
        with urlopen(f"{EPSS_URL}?{query}", timeout=8) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception:
        return {
            "error": "EPSS score is unavailable right now.",
            "status": 503,
        }

    scores = data.get("data", [])

    if not scores:
        return {
            "error": f"No EPSS score found for {cve_id}.",
            "status": 404,
        }

    score = scores[0]

    return {
        "cve": score.get("cve", cve_id),
        "epss": score.get("epss", "0"),
        "percentile": score.get("percentile", "0"),
        "epss_label": get_epss_label(score.get("epss")),
        "date": score.get("date", "Unknown date"),
        "source": "FIRST EPSS",
        "message": "EPSS score loaded.",
        "status": 200,
    }


def get_nvd_cve(cve_id):
    query = urlencode({"cveId": cve_id})
    headers = {"User-Agent": "CyberNewsSchoolProject/1.0"}
    nvd_api_key = os.getenv("NVD_API_KEY")

    if nvd_api_key:
        headers["apiKey"] = nvd_api_key

    try:
        request_data = Request(f"{NVD_CVE_URL}?{query}", headers=headers)

        with urlopen(request_data, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception:
        return {
            "found": False,
            "error": "NVD data is unavailable right now.",
        }

    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:
        return {
            "found": False,
            "error": f"No NVD record found for {cve_id}.",
        }

    cve_data = vulnerabilities[0].get("cve", {})
    metrics = cve_data.get("metrics", {})

    return {
        "found": True,
        "cve_id": cve_data.get("id", cve_id),
        "published": cve_data.get("published", "Unknown date"),
        "last_modified": cve_data.get("lastModified", "Unknown date"),
        "status": cve_data.get("vulnStatus", "Unknown"),
        "description": get_nvd_description(cve_data),
        "cvss": get_nvd_cvss(metrics),
        "affected_products": get_nvd_affected_products(cve_data),
        "references": get_nvd_references(cve_data),
        "source": "NVD",
    }


def get_nvd_description(cve_data):
    for description in cve_data.get("descriptions", []):
        if description.get("lang") == "en":
            return description.get("value", "")

    return "No description available."


def get_nvd_cvss(metrics):
    for metric_name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_entries = metrics.get(metric_name, [])

        if not metric_entries:
            continue

        metric_data = metric_entries[0].get("cvssData", {})

        return {
            "version": metric_data.get("version", "Unknown"),
            "score": metric_data.get("baseScore"),
            "severity": metric_data.get("baseSeverity") or metric_entries[0].get("baseSeverity"),
            "vector": metric_data.get("vectorString", ""),
        }

    return {
        "version": "Unknown",
        "score": None,
        "severity": "Unknown",
        "vector": "",
    }


def get_nvd_affected_products(cve_data):
    products = []

    for configuration in cve_data.get("configurations", []):
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                parts = criteria.split(":")

                if len(parts) >= 6:
                    vendor = parts[3].replace("_", " ")
                    product = parts[4].replace("_", " ")
                    label = f"{vendor} {product}".strip()

                    if label and label not in products:
                        products.append(label)

    return products[:8]


def get_nvd_references(cve_data):
    references = []
    reference_data = cve_data.get("references", [])

    if isinstance(reference_data, dict):
        reference_data = reference_data.get("referenceData", [])

    for reference in reference_data:
        url = reference.get("url", "")

        if url.startswith(("https://", "http://")):
            references.append(url)

    return references[:5]


def get_kev_entry(cve_id):
    try:
        request_data = Request(
            CISA_KEV_URL,
            headers={"User-Agent": "CyberNewsSchoolProject/1.0"},
        )

        with urlopen(request_data, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception:
        return {
            "is_known_exploited": False,
            "error": "CISA KEV data is unavailable right now.",
        }

    for vulnerability in data.get("vulnerabilities", []):
        if vulnerability.get("cveID", "").upper() == cve_id.upper():
            return {
                "is_known_exploited": True,
                "vendor": vulnerability.get("vendorProject", "Unknown vendor"),
                "product": vulnerability.get("product", "Unknown product"),
                "title": vulnerability.get("vulnerabilityName", "Untitled vulnerability"),
                "date_added": vulnerability.get("dateAdded", "Unknown date"),
                "due_date": vulnerability.get("dueDate", "Unknown date"),
                "known_ransomware_use": vulnerability.get("knownRansomwareCampaignUse", "Unknown"),
                "required_action": vulnerability.get("requiredAction", "Review vendor guidance."),
                "source": "CISA KEV",
            }

    return {
        "is_known_exploited": False,
        "source": "CISA KEV",
    }


def classify_cve_risk(nvd_data, epss_data, kev_data):
    cvss_score = ((nvd_data.get("cvss") or {}).get("score"))
    epss_label = epss_data.get("epss_label", "Unknown")

    if kev_data.get("is_known_exploited") and epss_label in {"High", "Very High"}:
        return "critical"

    if isinstance(cvss_score, (int, float)) and cvss_score >= 9:
        return "critical"

    if kev_data.get("is_known_exploited"):
        return "high"

    if isinstance(cvss_score, (int, float)) and cvss_score >= 7:
        return "high"

    if epss_label == "Very High":
        return "high"

    if epss_label in {"Medium", "High"}:
        return "medium"

    return "low"


def build_cve_enrichment(cve_id):
    clean_cve_id = cve_id.upper()
    nvd_data = get_nvd_cve(clean_cve_id)
    epss_data = get_epss_score(clean_cve_id)
    epss_data.pop("status", None)
    kev_data = get_kev_entry(clean_cve_id)

    enrichment = {
        "cve_id": clean_cve_id,
        "risk_classification": classify_cve_risk(nvd_data, epss_data, kev_data),
        "nvd": nvd_data,
        "epss": epss_data,
        "kev": kev_data,
        "ai_explanation": None,
    }

    try:
        enrichment["ai_explanation"] = explain_cve_risk(enrichment)
    except Exception as error:
        enrichment["ai_explanation"] = {
            "reasoning": "AI explanation is unavailable. Use the deterministic NVD, EPSS, and CISA KEV values above.",
            "recommended_action": "Review deterministic enrichment data before prioritizing.",
            "assumptions": [str(error)],
            "confidence": 0.0,
            "model": "unavailable",
        }

    return enrichment


def extract_cves_from_text(text):
    return sorted(set(match.upper() for match in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)))


def extract_iocs_from_text(text):
    patterns = [
        ("ipv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        ("url", r"https?://[^\s]+"),
        ("email", r"\b[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}\b"),
        ("hash", r"\b[a-fA-F0-9]{32,64}\b"),
    ]
    iocs = []

    for ioc_type, pattern in patterns:
        for match in re.findall(pattern, text):
            iocs.append(
                {
                    "type": ioc_type,
                    "value": match.rstrip(".,;"),
                    "confidence": 0.8,
                }
            )

    return iocs


def build_article_mock_result(action, entity_id, selected_text):
    text = selected_text or f"article {entity_id}"
    extracted_cves = extract_cves_from_text(text)
    extracted_iocs = extract_iocs_from_text(text)
    first_line = text.splitlines()[0] if text else f"article {entity_id}"

    if action == "extract_iocs":
        return {
            "summary": "IOC extraction completed using simple local patterns.",
            "extracted_cves": [],
            "extracted_iocs": extracted_iocs,
            "extracted_entities": {
                "vendors": [],
                "products": [],
                "malware_families": [],
                "threat_actors": [],
            },
            "attack_mappings": [],
            "recommended_actions": [
                "Review extracted IOCs before blocking or escalating.",
                "Confirm every IOC with a trusted reputation source.",
            ],
            "confidence": 0.65 if extracted_iocs else 0.35,
            "evidence": [first_line],
        }

    if action == "extract_cves":
        return {
            "summary": "CVE extraction completed using simple local patterns.",
            "extracted_cves": extracted_cves,
            "extracted_iocs": [],
            "extracted_entities": {
                "vendors": [],
                "products": [],
                "malware_families": [],
                "threat_actors": [],
            },
            "attack_mappings": [],
            "recommended_actions": [
                "Enrich extracted CVEs with CISA KEV, EPSS, and NVD data.",
                "Do not treat missing CVEs as proof that no vulnerability is involved.",
            ],
            "confidence": 0.7 if extracted_cves else 0.35,
            "evidence": [first_line],
        }

    if action == "generate_report":
        return {
            "summary": {
                "executive": f"Draft report created for article {entity_id}.",
                "technical": "This report is generated from dashboard article context and mock AI logic.",
                "key_points": [
                    first_line,
                    "Structured report JSON is ready for safe rendering.",
                ],
            },
            "extracted_cves": extracted_cves,
            "extracted_iocs": extracted_iocs,
            "extracted_entities": {
                "vendors": [],
                "products": [],
                "malware_families": [],
                "threat_actors": [],
            },
            "attack_mappings": [],
            "recommended_actions": [
                "Review the draft report.",
                "Save only after analyst validation.",
            ],
            "confidence": 0.6,
            "evidence": [first_line],
        }

    return {
        "summary": {
            "executive": f"Article {entity_id} may need analyst review.",
            "technical": "This mock analysis summarizes article context and checks for simple CVE/IOC patterns.",
            "key_points": [
                first_line,
                f"{len(extracted_cves)} CVE candidate(s) found.",
                f"{len(extracted_iocs)} IOC candidate(s) found.",
            ],
        },
        "extracted_cves": extracted_cves,
        "extracted_iocs": extracted_iocs,
        "extracted_entities": {
            "vendors": [],
            "products": [],
            "malware_families": [],
            "threat_actors": [],
        },
        "attack_mappings": [],
        "recommended_actions": [
            "Read the source article.",
            "Run extraction actions if the article mentions indicators or CVEs.",
        ],
        "confidence": 0.6,
        "evidence": [first_line],
    }


def build_mock_ai_result(action, entity_type, entity_id, selected_text):
    if action == "cve_enrichment":
        return {
            "cve_id": entity_id.upper(),
            "summary": "Mock CVE enrichment. Real KEV, EPSS, and NVD lookup comes next.",
            "cvss": None,
            "epss": None,
            "kev": {
                "is_known_exploited": False,
                "due_date": None,
                "known_ransomware_use": None,
            },
            "affected_products": [],
            "references": [],
            "risk_classification": "low",
            "recommended_action": "Check deterministic vulnerability sources before acting.",
            "reasoning": "No deterministic enrichment source was queried in this first AI job seed.",
            "evidence": [],
        }

    if action == "ioc_enrichment":
        return {
            "ioc": entity_id,
            "ioc_type": "unknown",
            "summary": "Mock IOC investigation. External reputation lookup comes later.",
            "first_seen": None,
            "last_seen": None,
            "sightings": [],
            "related_articles": [],
            "related_cves": [],
            "related_malware": [],
            "related_actors": [],
            "recommended_action": "investigate",
            "confidence": 0.4,
            "evidence": ["IOC value was provided by the analyst."],
        }

    if entity_type == "article":
        return build_article_mock_result(action, entity_id, selected_text)

    return build_article_mock_result(action, entity_id, selected_text)


def build_mock_report_json(entity_type, entity_id, result_json):
    summary = result_json.get("summary", "")

    if isinstance(summary, dict):
        summary_text = summary.get("executive", "No summary available.")
    else:
        summary_text = summary or "No summary available."

    return {
        "title": "Threat Intelligence Report",
        "subtitle": f"{entity_type}: {entity_id}",
        "created_at": get_timestamp(),
        "source_entities": [
            {
                "type": entity_type,
                "id": entity_id,
                "label": entity_id,
            }
        ],
        "sections": [
            {
                "type": "summary",
                "heading": "Executive Summary",
                "content": summary_text,
            },
            {
                "type": "recommendations",
                "heading": "Recommended Actions",
                "items": result_json.get("recommended_actions", []),
            },
        ],
    }


def get_ioc_values(result_json):
    values = []

    for ioc in result_json.get("extracted_iocs", []):
        if isinstance(ioc, dict) and ioc.get("value"):
            values.append(str(ioc["value"]))

    return values


def get_related_feed_keywords(text):
    stop_words = {
        "about",
        "after",
        "article",
        "before",
        "cyber",
        "from",
        "have",
        "into",
        "news",
        "that",
        "their",
        "there",
        "this",
        "with",
    }
    words = re.findall(r"[A-Za-z][A-Za-z0-9-]{4,}", text.lower())
    keywords = []

    for word in words:
        if word in stop_words or word in keywords:
            continue

        keywords.append(word)

        if len(keywords) >= 8:
            break

    return keywords


def find_related_feed_items(selected_text, result_json, entity_id, limit=5):
    cves = [cve.upper() for cve in result_json.get("extracted_cves", [])]
    ioc_values = get_ioc_values(result_json)
    keywords = get_related_feed_keywords(selected_text)
    related_items = []

    for item in list_feed_items():
        if item.get("id") == entity_id:
            continue

        haystack = f"{item.get('title', '')} {item.get('summary', '')}".lower()
        matched_terms = []
        score = 0

        for cve in cves:
            if cve.lower() in haystack:
                matched_terms.append(cve)
                score += 6

        for ioc in ioc_values:
            if ioc and ioc.lower() in haystack:
                matched_terms.append(ioc)
                score += 5

        for keyword in keywords:
            if keyword in haystack:
                matched_terms.append(keyword)
                score += 1

        if score > 0:
            related_items.append(
                {
                    "title": item.get("title", "Untitled item"),
                    "source": item.get("source", "Unknown source"),
                    "published": item.get("published", "Unknown date"),
                    "url": item.get("url", "#"),
                    "matched_terms": matched_terms[:6],
                    "score": score,
                }
            )

    return sorted(related_items, key=lambda item: item["score"], reverse=True)[:limit]


def get_cve_enrichments(result_json):
    enrichments = []

    for cve_id in result_json.get("extracted_cves", [])[:3]:
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", str(cve_id).upper()):
            continue

        enrichments.append(build_cve_enrichment(str(cve_id).upper()))

    return enrichments


def enrich_ai_result(result_json, selected_text, entity_id):
    text_cves = extract_cves_from_text(selected_text)
    existing_cves = [str(cve).upper() for cve in result_json.get("extracted_cves", [])]
    result_json["extracted_cves"] = sorted(set(existing_cves + text_cves))

    existing_iocs = result_json.get("extracted_iocs", [])
    text_iocs = extract_iocs_from_text(selected_text)
    seen_iocs = {
        (str(ioc.get("type", "")), str(ioc.get("value", "")))
        for ioc in existing_iocs
        if isinstance(ioc, dict)
    }

    for ioc in text_iocs:
        key = (ioc["type"], ioc["value"])

        if key not in seen_iocs:
            existing_iocs.append(ioc)
            seen_iocs.add(key)

    result_json["extracted_iocs"] = existing_iocs
    result_json["related_articles"] = find_related_feed_items(selected_text, result_json, entity_id)
    result_json["cve_enrichments"] = get_cve_enrichments(result_json)

    if result_json["related_articles"]:
        result_json.setdefault("evidence", []).append("Related feed items were found in stored news/RSS data.")

    if result_json["cve_enrichments"]:
        result_json.setdefault("evidence", []).append("CVE enrichment was loaded from NVD, CISA KEV, and EPSS data.")

    return result_json


def add_enrichment_sections_to_report(report_json, result_json):
    sections = report_json.setdefault("sections", [])
    related_articles = result_json.get("related_articles", [])
    cve_enrichments = result_json.get("cve_enrichments", [])

    if related_articles:
        sections.append(
            {
                "type": "source_links",
                "heading": "Related Feed Items",
                "links": [
                    {
                        "label": f"{item['title']} ({item['source']})",
                        "url": item["url"],
                    }
                    for item in related_articles
                    if item.get("url", "#") != "#"
                ],
            }
        )

    if cve_enrichments:
        sections.append(
            {
                "type": "table",
                "heading": "CVE Enrichment",
                "columns": ["CVE", "Risk", "EPSS", "KEV", "NVD Summary"],
                "rows": [
                    [
                        enrichment.get("cve_id", ""),
                        enrichment.get("risk_classification", "unknown"),
                        str(enrichment.get("epss", {}).get("epss", "unknown")),
                        "yes" if enrichment.get("kev", {}).get("is_known_exploited") else "no",
                        enrichment.get("nvd", {}).get("summary", "No NVD summary available.")[:180],
                    ]
                    for enrichment in cve_enrichments
                ],
            }
        )

    return report_json


def get_prompt_version(action, model):
    if model == "mock-ai-v1":
        return "mock-v1"

    if action == "generate_report":
        return "article-report-v1"

    if action == "extract_iocs":
        return "article-ioc-extraction-v1"

    if action == "extract_cves":
        return "article-cve-extraction-v1"

    return "article-analysis-v1"


def save_ai_job_artifacts(job):
    created_at = job.get("created_at", get_timestamp())
    artifacts = [
        {
            "artifact_id": f"{job['job_id']}-result",
            "job_id": job["job_id"],
            "artifact_type": "result_json",
            "content_json": job.get("result_json", {}),
            "created_by": job.get("created_by", ""),
            "created_at": created_at,
        }
    ]

    if job.get("report_json"):
        artifacts.append(
            {
                "artifact_id": f"{job['job_id']}-report",
                "job_id": job["job_id"],
                "artifact_type": "report_json",
                "content_json": job.get("report_json", {}),
                "created_by": job.get("created_by", ""),
                "created_at": created_at,
            }
        )

    if job.get("context_bundle"):
        artifacts.append(
            {
                "artifact_id": f"{job['job_id']}-context",
                "job_id": job["job_id"],
                "artifact_type": "context_bundle",
                "content_json": job.get("context_bundle", {}),
                "created_by": job.get("created_by", ""),
                "created_at": created_at,
            }
        )

    for artifact in artifacts:
        save_ai_artifact(artifact)

    evidence_values = []

    for item in job.get("evidence", []):
        evidence_values.append(
            {
                "evidence_type": "model_evidence",
                "content": str(item),
                "source_ref": "",
            }
        )

    for entry in job.get("retrieval_trace", []):
        evidence_values.append(
            {
                "evidence_type": "retrieval_trace",
                "content": f"{entry.get('step', '')}: {entry.get('details', '')}",
                "source_ref": entry.get("step", ""),
            }
        )

    for source in job.get("related_sources", []):
        evidence_values.append(
            {
                "evidence_type": "related_source",
                "content": source.get("why_related") or source.get("title", ""),
                "source_ref": source.get("source_ref", ""),
                "source_url": source.get("url", ""),
            }
        )

    for index, evidence in enumerate(evidence_values, start=1):
        save_ai_evidence(
            {
                "evidence_id": f"{job['job_id']}-evidence-{index}",
                "job_id": job["job_id"],
                "created_by": job.get("created_by", ""),
                "created_at": created_at,
                **evidence,
            }
        )


def create_ai_job(payload, current_user):
    action = payload.get("action", "")
    entity_type = payload.get("entity_type", "")
    entity_id = str(payload.get("entity_id", "")).strip()
    context_depth = payload.get("context_depth", "medium")
    output_format = payload.get("output_format", "structured_json")
    external_search_policy = payload.get("external_search_policy", EXTERNAL_SEARCH_POLICY)

    if action not in AI_ACTIONS:
        return None, "Unsupported AI action."

    if entity_type not in AI_ENTITY_TYPES:
        return None, "Unsupported entity type."

    if not entity_id:
        return None, "Missing entity_id."

    if context_depth not in AI_CONTEXT_DEPTHS:
        return None, "Unsupported context_depth."

    if output_format not in AI_OUTPUT_FORMATS:
        return None, "Unsupported output_format."

    if external_search_policy not in {"off", "auto", "force"}:
        return None, "Unsupported external_search_policy."

    if action == "cve_enrichment" and entity_type != "cve":
        return None, "CVE enrichment requires a cve entity."

    if action == "ioc_enrichment" and entity_type != "ioc":
        return None, "IOC enrichment requires an ioc entity."

    job_id = str(uuid4())
    created_at = get_timestamp()
    selected_text = payload.get("selected_text", "")
    model = "mock-ai-v1"
    warnings = []
    agentic_actions = {"analyze", "generate_report", "extract_iocs", "extract_cves"}

    context_bundle = {}
    retrieval_plan = {}
    retrieval_trace = []
    related_sources = []
    source_map = {}

    if action in agentic_actions and entity_type == "article":
        agentic_result = run_agentic_article_action(
            action=action,
            entity_id=entity_id,
            selected_text=selected_text,
            context_depth=context_depth,
            output_format=output_format,
            external_search_policy=external_search_policy,
            created_at=created_at,
        )
        result_json = agentic_result["result_json"]
        report_json = agentic_result["report_json"]
        model = agentic_result["model"]
        warnings.extend(agentic_result["warnings"])
        context_bundle = agentic_result["context_bundle"]
        retrieval_plan = agentic_result["retrieval_plan"]
        retrieval_trace = agentic_result["retrieval_trace"]
        related_sources = agentic_result["related_sources"]
        source_map = agentic_result["source_map"]
    else:
        result_json = build_mock_ai_result(action, entity_type, entity_id, selected_text)
        report_json = None
        warnings.append("Mock AI result. Gemini is only connected for article analysis, report generation, IOC extraction, and CVE extraction.")

    if report_json is None and (output_format in {"html_report", "both"} or action == "generate_report"):
        report_json = build_mock_report_json(entity_type, entity_id, result_json)

    job = {
        "job_id": job_id,
        "status": "completed",
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "selected_text": selected_text,
        "context_depth": context_depth,
        "output_format": output_format,
        "external_search_policy": external_search_policy,
        "model": model,
        "prompt_version": get_prompt_version(action, model),
        "result_json": result_json,
        "report_json": report_json,
        "context_bundle": context_bundle,
        "retrieval_plan": retrieval_plan,
        "retrieval_trace": retrieval_trace,
        "related_sources": related_sources,
        "source_map": source_map,
        "rendered_html": None,
        "confidence": result_json.get("confidence", 0.7),
        "warnings": warnings,
        "evidence": result_json.get("evidence", []),
        "created_by": current_user["username"] if current_user else "guest",
        "created_at": created_at,
        "completed_at": created_at,
    }

    if report_json:
        report_id = str(uuid4())
        report = {
            "report_id": report_id,
            "title": report_json.get("title") or "Threat Intelligence Report",
            "source_job_id": job_id,
            "report_json": report_json,
            "created_by": current_user["username"] if current_user else "guest",
            "created_at": created_at,
            "updated_at": created_at,
            "save_mode": "automatic",
        }
        save_report(report)
        job["auto_saved_report_id"] = report_id
    else:
        job["auto_saved_report_id"] = None

    save_ai_job_artifacts(job)
    save_ai_job(job)

    return job, ""


def create_report(payload, current_user):
    report_json = payload.get("report_json")

    if not isinstance(report_json, dict):
        return None, "report_json must be an object."

    report_id = str(uuid4())
    created_at = get_timestamp()
    title = report_json.get("title") or "Threat Intelligence Report"

    report = {
        "report_id": report_id,
        "title": title,
        "source_job_id": payload.get("source_job_id", ""),
        "report_json": report_json,
        "created_by": current_user["username"] if current_user else "guest",
        "created_at": created_at,
        "updated_at": created_at,
    }
    save_report(report)

    return report, ""


def get_entity_payload(entity_type, entity_id):
    if entity_type == "article":
        article = get_feed_item(entity_id)

        if not article:
            return None

        return {
            "entity_type": "article",
            "entity_id": entity_id,
            "entity": article,
        }

    if entity_type == "report":
        report = get_report(entity_id)

        if not report:
            return None

        return {
            "entity_type": "report",
            "entity_id": entity_id,
            "entity": report,
        }

    if entity_type == "cve":
        return {
            "entity_type": "cve",
            "entity_id": entity_id.upper(),
            "entity": build_cve_enrichment(entity_id),
        }

    return None


def get_entity_connections_payload(entity_type, entity_id):
    source_entity = {
        "type": entity_type,
        "id": entity_id,
        "label": entity_id,
    }

    if entity_type != "article":
        return {
            "source_entity": source_entity,
            "connections": [],
        }

    article = get_feed_item(entity_id) or {}
    source_entity["label"] = article.get("title", entity_id)
    correlations = list_article_correlations(entity_id)
    connections = []

    for correlation in correlations:
        target_id = correlation.get("related_article_id", "")
        connections.append(
            {
                "target_type": "article",
                "target_id": target_id,
                "target_label": correlation.get("related_title", target_id),
                "relationship": ", ".join(correlation.get("relation_types", [])) or "related_to",
                "confidence": correlation.get("confidence", 0.0),
                "evidence": correlation.get("evidence", []),
                "matched_terms": correlation.get("matched_terms", []),
                "status": correlation.get("status", "needs_review"),
            }
        )

    return {
        "source_entity": source_entity,
        "connections": connections,
    }


def create_ai_feedback(job_id, payload, current_user):
    if not get_ai_job(job_id):
        return None, "AI job not found."

    feedback = {
        "feedback_id": str(uuid4()),
        "job_id": job_id,
        "rating": str(payload.get("rating", "neutral")),
        "comment": str(payload.get("comment", "")).strip(),
        "created_by": current_user["username"] if current_user else "guest",
        "created_at": get_timestamp(),
    }
    save_analyst_feedback(feedback)
    return feedback, ""


def regenerate_ai_job(job_id, payload, current_user):
    old_job = get_ai_job(job_id)

    if not old_job:
        return None, "AI job not found."

    analyst_goal = str(payload.get("analyst_goal", "")).strip()
    selected_text = old_job.get("selected_text", "")

    if analyst_goal:
        selected_text = f"{selected_text}\nAnalyst goal: {analyst_goal}"

    new_payload = {
        "action": old_job.get("action", ""),
        "entity_type": old_job.get("entity_type", ""),
        "entity_id": old_job.get("entity_id", ""),
        "selected_text": selected_text,
        "context_depth": payload.get("context_depth", old_job.get("context_depth", "medium")),
        "output_format": old_job.get("output_format", "structured_json"),
        "external_search_policy": payload.get("external_search_policy", old_job.get("external_search_policy", EXTERNAL_SEARCH_POLICY)),
    }

    return create_ai_job(new_payload, current_user)


def render_section_html(section):
    heading = html.escape(str(section.get("heading", "Section")))
    section_type = section.get("type", "paragraph")

    if section_type in {"bullet_list", "recommendations"}:
        items = "".join(f"<li>{html.escape(str(item))}</li>" for item in section.get("items", []))
        return f"<section><h2>{heading}</h2><ul>{items}</ul></section>"

    if section_type == "numbered_list":
        items = "".join(f"<li>{html.escape(str(item))}</li>" for item in section.get("items", []))
        return f"<section><h2>{heading}</h2><ol>{items}</ol></section>"

    if section_type == "source_links":
        links = []

        for link in section.get("links", []):
            url = str(link.get("url", ""))

            if not url.startswith(("https://", "http://")):
                continue

            label = html.escape(str(link.get("label", url)))
            safe_url = html.escape(url, quote=True)
            links.append(f'<li><a href="{safe_url}" target="_blank" rel="noopener noreferrer">{label}</a></li>')

        return f"<section><h2>{heading}</h2><ul>{''.join(links)}</ul></section>"

    if section_type == "table":
        headers = "".join(f"<th>{html.escape(str(column))}</th>" for column in section.get("columns", []))
        rows = []

        for row in section.get("rows", []):
            row_values = row if isinstance(row, list) else list(row.values())
            cells = "".join(f"<td>{html.escape(str(value))}</td>" for value in row_values)
            rows.append(f"<tr>{cells}</tr>")

        return f"<section><h2>{heading}</h2><table><thead><tr>{headers}</tr></thead><tbody>{''.join(rows)}</tbody></table></section>"

    content = html.escape(str(section.get("content", "")))
    return f"<section><h2>{heading}</h2><p>{content}</p></section>"


def render_report_export_html(report):
    report_json = report.get("report_json", {})
    title = html.escape(str(report_json.get("title", "Threat Intelligence Report")))
    subtitle = html.escape(str(report_json.get("subtitle", "")))
    created_at = html.escape(str(report_json.get("created_at", report.get("created_at", ""))))
    sections = "".join(render_section_html(section) for section in report_json.get("sections", []))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>
    body {{ margin: 0; font-family: Arial, sans-serif; color: #172026; background: #f5f7f8; }}
    main {{ display: grid; gap: 14px; max-width: 960px; margin: 0 auto; padding: 20px; }}
    header, section {{ padding: 14px; background: white; border: 1px solid #dbe3e7; }}
    header {{ border-left: 5px solid #28d7d0; }}
    h1, h2, p {{ margin: 0; }}
    h1 {{ font-size: 1.5rem; }}
    h2 {{ margin-bottom: 8px; font-size: 1rem; }}
    .meta {{ margin-top: 6px; color: #5a6872; }}
    ul, ol {{ margin: 8px 0 0; padding-left: 20px; }}
    li {{ margin-bottom: 6px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #dbe3e7; }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>{title}</h1>
      <p class="meta">{subtitle}</p>
      <p class="meta">Created at {created_at}</p>
    </header>
    {sections}
  </main>
</body>
</html>"""


def iterate_report(report_id, payload, current_user):
    report = get_report(report_id)

    if not report:
        return None, "Report not found."

    instruction = str(payload.get("instruction", "")).strip()

    if not instruction:
        return None, "instruction is required."

    created_at = get_timestamp()
    version = {
        "version_id": str(uuid4()),
        "report_id": report_id,
        "report_json": report.get("report_json", {}),
        "created_by": current_user["username"] if current_user else "guest",
        "created_at": created_at,
        "iteration_note": instruction,
    }
    save_report_version(version)

    report_json = dict(report.get("report_json", {}))
    warnings = []

    try:
        report_json, model = iterate_report_with_ai(report_json, instruction, created_at)
        warnings.append(f"Report iterated with {model}.")
    except Exception as error:
        sections = list(report_json.get("sections", []))
        sections.append(
            {
                "type": "summary",
                "heading": "Analyst Iteration",
                "content": instruction,
            }
        )
        report_json["sections"] = sections
        warnings.append(f"AI iteration unavailable, saved analyst note only: {error}")

    report_json["updated_at"] = created_at
    report["report_json"] = report_json
    report["updated_at"] = created_at
    report["last_iteration_note"] = instruction
    report["iteration_warnings"] = warnings
    save_report(report)

    return report, ""


def clean_detection_terms(values):
    clean_terms = []

    for value in values:
        clean_value = re.sub(r"[^a-zA-Z0-9_.:/-]", "", str(value))[:80]

        if clean_value and clean_value not in clean_terms:
            clean_terms.append(clean_value)

    return clean_terms[:8]


def build_detection_content(rule_type, title, terms):
    if not terms:
        terms = ["suspicious"]

    quoted_terms = ", ".join(f'"{term}"' for term in terms)

    if rule_type == "sigma":
        term_lines = "\n".join(f"      - '{term}'" for term in terms)
        return f"""title: {title}
status: experimental
description: Draft rule generated by CyberNews. Requires analyst review.
logsource:
  product: windows
detection:
  selection:
    CommandLine|contains:
{term_lines}
  condition: selection
falsepositives:
  - Legitimate administrative activity
level: medium"""

    if rule_type == "yara":
        string_lines = "\n".join(f"    $s{index} = \"{term}\" ascii nocase" for index, term in enumerate(terms, start=1))
        return f"""rule CyberNews_Draft_{hashlib.sha1(title.encode('utf-8')).hexdigest()[:8]} {{
  meta:
    description = \"Draft rule generated by CyberNews. Requires analyst review.\"
  strings:
{string_lines}
  condition:
    any of them
}}"""

    if rule_type == "kql":
        return f"""DeviceEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ({quoted_terms})
| project Timestamp, DeviceName, AccountName, ProcessCommandLine"""

    return f"""index=*
({ " OR ".join(terms) })
| table _time host source sourcetype _raw"""


def create_detection_rule(payload, current_user):
    rule_type = str(payload.get("rule_type", "sigma")).lower()

    if rule_type not in {"sigma", "yara", "kql", "splunk"}:
        return None, "Unsupported rule_type."

    entity_type = str(payload.get("entity_type", "article"))
    entity_id = str(payload.get("entity_id", "")).strip()
    source_text = str(payload.get("source_text", "")).strip()

    if entity_type == "article" and entity_id and not source_text:
        article = get_feed_item(entity_id) or {}
        source_text = f"{article.get('title', '')}\n{article.get('summary', '')}"

    if not source_text:
        return None, "source_text or a valid article entity is required."

    cves = extract_cves_from_text(source_text)
    iocs = [ioc["value"] for ioc in extract_iocs_from_text(source_text)]
    detection_goal = str(payload.get("detection_goal", "Detect suspicious activity related to the selected intelligence.")).strip()
    terms = clean_detection_terms(cves + iocs + source_text.split()[:6])
    title = str(payload.get("title", f"CyberNews Draft Detection for {entity_id or 'selected intelligence'}")).strip()
    ai_model = "deterministic-template"
    warnings = ["Draft only. Needs analyst review. Do not auto-deploy."]

    try:
        ai_rule, ai_model = generate_detection_rule_ai(rule_type, title, source_text, detection_goal)
        title = ai_rule["title"] or title
        description = ai_rule["description"]
        required_logs = ai_rule["required_logs"] or ["Relevant endpoint, network, or SIEM logs depending on environment."]
        rule_content = ai_rule["rule_content"] or build_detection_content(rule_type, title, terms)
        attack_mappings = ai_rule["attack_mappings"]
        false_positive_notes = ai_rule["false_positive_notes"] or ["Generated rule is broad and must be tuned before use."]
        test_notes = ai_rule["test_notes"] or "Run against a small historical dataset before production use."
        confidence = ai_rule["confidence"]
        warnings = ai_rule["warnings"]
    except Exception as error:
        description = "Draft detection rule generated from CyberNews context."
        required_logs = ["Relevant endpoint, network, or SIEM logs depending on environment."]
        rule_content = build_detection_content(rule_type, title, terms)
        attack_mappings = []
        false_positive_notes = ["Generated rule is broad and must be tuned before use."]
        test_notes = "Run against a small historical dataset before production use."
        confidence = 0.45
        warnings.append(f"AI generation unavailable, used deterministic template: {error}")

    rule = {
        "rule_id": str(uuid4()),
        "rule_type": rule_type,
        "title": title,
        "description": description,
        "detection_goal": detection_goal,
        "required_logs": required_logs,
        "rule_content": rule_content,
        "attack_mappings": attack_mappings,
        "false_positive_notes": false_positive_notes,
        "test_notes": test_notes,
        "confidence": confidence,
        "warnings": warnings,
        "model": ai_model,
        "source_entity": {"type": entity_type, "id": entity_id},
        "status": "needs_review",
        "created_by": current_user["username"] if current_user else "guest",
        "created_at": get_timestamp(),
        "reviewed_by": "",
        "reviewed_at": "",
        "review_notes": "",
    }
    save_detection_rule(rule)
    return rule, ""


def review_detection_rule(rule_id, payload, current_user):
    rule = get_detection_rule(rule_id)

    if not rule:
        return None, "Detection rule not found."

    status = str(payload.get("status", "needs_review"))

    if status not in {"needs_review", "approved", "rejected"}:
        return None, "Unsupported review status."

    rule["status"] = status
    rule["review_notes"] = str(payload.get("review_notes", "")).strip()
    rule["reviewed_by"] = current_user["username"] if current_user else "guest"
    rule["reviewed_at"] = get_timestamp()
    save_detection_rule(rule)

    return rule, ""


def get_graph_severity_from_epss_label(epss_label):
    if epss_label == "Very High":
        return "Critical"

    if epss_label == "High":
        return "High"

    if epss_label == "Medium":
        return "Medium"

    return "Low"


def make_graph_id(prefix, value):
    clean_value = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return f"{prefix}-{clean_value or 'unknown'}"


def add_graph_node(nodes, node_ids, node):
    if node["id"] in node_ids:
        return

    nodes.append(node)
    node_ids.add(node["id"])


def get_threat_graph_data():
    nodes = [
        {
            "id": "parcel-phishing",
            "label": "Parcel Phishing Campaign",
            "type": "Threat",
            "severity": "Medium",
        },
        {
            "id": "fake-delivery-emails",
            "label": "Fake Delivery Emails",
            "type": "Technique",
            "severity": "Medium",
        },
        {
            "id": "credential-theft",
            "label": "Credential Theft",
            "type": "Impact",
            "severity": "High",
        },
        {
            "id": "affected-users",
            "label": "Affected Users",
            "type": "Target",
            "severity": "Medium",
        },
        {
            "id": "awareness-training",
            "label": "Awareness Training",
            "type": "Defense",
            "severity": "Low",
        },
    ]
    edges = [
        {
            "source": "parcel-phishing",
            "target": "fake-delivery-emails",
            "label": "uses",
        },
        {
            "source": "fake-delivery-emails",
            "target": "affected-users",
            "label": "targets",
        },
        {
            "source": "fake-delivery-emails",
            "target": "credential-theft",
            "label": "can lead to",
        },
        {
            "source": "awareness-training",
            "target": "credential-theft",
            "label": "reduces risk of",
        },
    ]
    node_ids = {node["id"] for node in nodes}
    kev_vulnerabilities = get_kev_vulnerabilities()["vulnerabilities"][:3]

    if kev_vulnerabilities:
        nodes.extend(
            [
                {
                    "id": "cisa-kev-catalog",
                    "label": "CISA KEV Catalog",
                    "type": "Source",
                    "severity": "Low",
                },
                {
                    "id": "first-epss",
                    "label": "FIRST EPSS",
                    "type": "Scoring Source",
                    "severity": "Low",
                },
            ]
        )
        node_ids.update({"cisa-kev-catalog", "first-epss"})

    for vulnerability in kev_vulnerabilities:
        cve_node_id = vulnerability["cve"].lower()
        product_node_id = make_graph_id("product", vulnerability["product"])
        vendor_node_id = make_graph_id("vendor", vulnerability["vendor"])

        add_graph_node(
            nodes,
            node_ids,
            {
                "id": cve_node_id,
                "label": vulnerability["cve"],
                "type": "CVE",
                "severity": get_graph_severity_from_epss_label(vulnerability["epss_label"]),
                "title": vulnerability["title"],
                "vendor": vulnerability["vendor"],
                "product": vulnerability["product"],
                "epss": vulnerability["epss"],
                "epss_label": vulnerability["epss_label"],
                "due_date": vulnerability["due_date"],
                "required_action": vulnerability["required_action"],
            },
        )
        add_graph_node(
            nodes,
            node_ids,
            {
                "id": product_node_id,
                "label": vulnerability["product"],
                "type": "Product",
                "severity": get_graph_severity_from_epss_label(vulnerability["epss_label"]),
            },
        )
        add_graph_node(
            nodes,
            node_ids,
            {
                "id": vendor_node_id,
                "label": vulnerability["vendor"],
                "type": "Vendor",
                "severity": "Low",
            },
        )
        edges.extend(
            [
                {
                    "source": cve_node_id,
                    "target": product_node_id,
                    "label": "affects",
                },
                {
                    "source": product_node_id,
                    "target": vendor_node_id,
                    "label": "made by",
                },
                {
                    "source": cve_node_id,
                    "target": "cisa-kev-catalog",
                    "label": "listed in",
                },
                {
                    "source": cve_node_id,
                    "target": "first-epss",
                    "label": "scored by",
                },
            ]
        )

    return {
        "nodes": nodes,
        "edges": edges,
        "message": "Threat graph data loaded with CISA KEV CVE nodes.",
    }


def get_article_categories(articles):
    return sorted({article["category"] for article in articles} | {"News"})


def get_article_severities():
    return ["High", "Medium", "Low"]


def get_feed_source_types(feed_items):
    source_labels = {
        "newsapi": "NewsAPI",
        "security-rss": "Security RSS",
        "hacker-news": "Hacker News",
        "bsi": "BSI",
        "cisa-advisories": "CISA Advisories",
    }

    return [
        {
            "value": source_type,
            "label": source_labels.get(source_type, source_type),
        }
        for source_type in sorted({item["source_type"] for item in feed_items})
    ]


@app.route("/")
def home():
    feed_data = get_dashboard_feed()
    articles = feed_data["items"]

    return render_template(
        "dashboard.html",
        page_title="Feed",
        articles=articles,
        categories=get_article_categories(articles),
        severities=get_article_severities(),
        feed_sources=get_feed_source_types(articles),
        feed_message=feed_data["message"],
        initial_backfill_days=INITIAL_BACKFILL_DAYS,
        current_user=get_current_user(),
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = USERS.get(username)

        if user and check_password_hash(user["password_hash"], password):
            record_login_attempt(username, True, user["role"])
            session["username"] = username
            sync_result = sync_feed_items()
            session["last_feed_sync"] = get_timestamp()
            session["last_feed_sync_count"] = sync_result["saved_count"]
            next_url = request.args.get("next", "")

            if is_safe_next_url(next_url):
                return redirect(next_url)

            return redirect(url_for("home"))

        record_login_attempt(username, False)
        error = "Invalid username or password."

    return render_template("login.html", error=error, current_user=get_current_user())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/ai-reporting")
def ai_reporting():
    current_user = get_current_user()

    if not current_user:
        return redirect(url_for("login"))

    return render_template(
        "ai_reporting.html",
        audit_log=AUDIT_LOG,
        current_user=current_user,
    )


@app.route("/threat-graph")
def threat_graph():
    return render_template(
        "threat_graph.html",
        current_user=get_current_user(),
    )


@app.route("/analyst-briefing/frame")
def analyst_briefing_frame():
    return render_template("analyst_briefing_frame.html")


@app.route("/api/ai/jobs", methods=["GET", "POST"])
def api_create_ai_job():
    if request.method == "GET":
        jobs = list_ai_jobs()

        return jsonify(
            {
                "jobs": [
                    {
                        "job_id": job["job_id"],
                        "status": job.get("status", ""),
                        "action": job.get("action", ""),
                        "entity_type": job.get("entity_type", ""),
                        "entity_id": job.get("entity_id", ""),
                        "created_by": job.get("created_by", ""),
                        "created_at": job.get("created_at", ""),
                        "auto_saved_report_id": job.get("auto_saved_report_id"),
                    }
                    for job in jobs
                ],
                "count": len(jobs),
            }
        )

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required."}), 400

    job, error = create_ai_job(payload, get_current_user())

    if error:
        return jsonify({"error": error}), 400

    return jsonify(job), 201


@app.route("/api/ai/jobs/<job_id>")
def api_get_ai_job(job_id):
    job = get_ai_job(job_id)

    if not job:
        return jsonify({"error": "AI job not found."}), 404

    return jsonify(job)


@app.route("/api/ai/jobs/<job_id>/stream")
def api_stream_ai_job(job_id):
    job = get_ai_job(job_id)

    if not job:
        return jsonify({"error": "AI job not found."}), 404

    def generate():
        yield f"event: status\ndata: {json.dumps(job)}\n\n"

    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/ai/jobs/<job_id>/artifacts")
def api_ai_job_artifacts(job_id):
    if not get_ai_job(job_id):
        return jsonify({"error": "AI job not found."}), 404

    return jsonify(
        {
            "artifacts": list_ai_artifacts(job_id),
            "count": len(list_ai_artifacts(job_id)),
        }
    )


@app.route("/api/ai/jobs/<job_id>/evidence")
def api_ai_job_evidence(job_id):
    if not get_ai_job(job_id):
        return jsonify({"error": "AI job not found."}), 404

    return jsonify(
        {
            "evidence": list_ai_evidence(job_id),
            "count": len(list_ai_evidence(job_id)),
        }
    )


@app.route("/api/ai/jobs/<job_id>/feedback", methods=["POST"])
def api_ai_job_feedback(job_id):
    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required."}), 400

    feedback, error = create_ai_feedback(job_id, payload, get_current_user())

    if error:
        return jsonify({"error": error}), 404

    return jsonify(feedback), 201


@app.route("/api/ai/jobs/<job_id>/regenerate", methods=["POST"])
def api_ai_job_regenerate(job_id):
    payload = request.get_json(silent=True) or {}

    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body must be an object."}), 400

    job, error = regenerate_ai_job(job_id, payload, get_current_user())

    if error:
        return jsonify({"error": error}), 400

    return jsonify(job), 201


@app.route("/api/entities/<entity_type>/<entity_id>")
def api_get_entity(entity_type, entity_id):
    if entity_type not in AI_ENTITY_TYPES:
        return jsonify({"error": "Unsupported entity type."}), 400

    payload = get_entity_payload(entity_type, entity_id)

    if not payload:
        return jsonify({"error": "Entity not found."}), 404

    return jsonify(payload)


@app.route("/api/entities/<entity_type>/<entity_id>/connections")
def api_get_entity_connections(entity_type, entity_id):
    if entity_type not in AI_ENTITY_TYPES:
        return jsonify({"error": "Unsupported entity type."}), 400

    return jsonify(get_entity_connections_payload(entity_type, entity_id))


@app.route("/api/entities/article/<entity_id>/connections/<target_id>/review", methods=["POST"])
def api_review_article_connection(entity_id, target_id):
    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required."}), 400

    status = str(payload.get("status", "needs_review"))

    if status not in {"approved", "rejected", "needs_review"}:
        return jsonify({"error": "Unsupported review status."}), 400

    current_user = get_current_user()
    correlation = update_article_correlation_status(
        entity_id,
        target_id,
        status,
        reviewed_by=current_user["username"] if current_user else "guest",
        review_notes=str(payload.get("review_notes", "")).strip(),
    )

    if not correlation:
        return jsonify({"error": "Connection not found."}), 404

    return jsonify(correlation)


@app.route("/api/reports", methods=["POST"])
def api_create_report():
    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required."}), 400

    report, error = create_report(payload, get_current_user())

    if error:
        return jsonify({"error": error}), 400

    return jsonify(report), 201


@app.route("/api/reports")
def api_list_reports():
    reports = list_reports()

    return jsonify(
        {
            "reports": [
                {
                    "report_id": report["report_id"],
                    "title": report["title"],
                    "created_by": report["created_by"],
                    "created_at": report["created_at"],
                }
                for report in reports
            ],
            "count": len(reports),
        }
    )


@app.route("/api/reports/<report_id>", methods=["GET", "DELETE"])
def api_get_report(report_id):
    if request.method == "DELETE":
        current_user = get_current_user()

        if not user_is_admin(current_user):
            return jsonify({"error": "Admins only."}), 403

        if not delete_report(report_id):
            return jsonify({"error": "Report not found."}), 404

        return jsonify({"message": "Report deleted.", "report_id": report_id})

    report = get_report(report_id)

    if not report:
        return jsonify({"error": "Report not found."}), 404

    return jsonify(report)


@app.route("/api/reports/<report_id>/iterate", methods=["POST"])
def api_iterate_report(report_id):
    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required."}), 400

    report, error = iterate_report(report_id, payload, get_current_user())

    if error:
        return jsonify({"error": error}), 400

    return jsonify(report)


@app.route("/api/reports/<report_id>/export/html")
def api_export_report_html(report_id):
    report = get_report(report_id)

    if not report:
        return jsonify({"error": "Report not found."}), 404

    return Response(render_report_export_html(report), mimetype="text/html")


@app.route("/api/detections", methods=["GET"])
def api_list_detections():
    return jsonify(
        {
            "rules": list_detection_rules(),
            "count": len(list_detection_rules()),
        }
    )


@app.route("/api/detections/generate", methods=["POST"])
def api_generate_detection():
    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required."}), 400

    rule, error = create_detection_rule(payload, get_current_user())

    if error:
        return jsonify({"error": error}), 400

    return jsonify(rule), 201


@app.route("/api/detections/<rule_id>/review", methods=["POST"])
def api_review_detection(rule_id):
    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required."}), 400

    rule, error = review_detection_rule(rule_id, payload, get_current_user())

    if error:
        return jsonify({"error": error}), 400

    return jsonify(rule)


@app.route("/api/articles")
def api_articles():
    return jsonify(get_aggregated_news_feed())


@app.route("/api/live-news")
def api_live_news():
    return jsonify(get_live_news_articles())


@app.route("/api/bsi-advisories")
def api_bsi_advisories():
    return jsonify(get_bsi_advisories())


@app.route("/api/security-feeds")
def api_security_feeds():
    return jsonify(get_security_rss_articles())


@app.route("/api/hacker-news")
def api_hacker_news():
    return jsonify(get_hacker_news_security_articles())


@app.route("/api/cisa-advisories")
def api_cisa_advisories():
    return jsonify(get_cisa_advisories())


@app.route("/api/aggregated-news")
def api_aggregated_news():
    return jsonify(sync_feed_items())


@app.route("/api/feed-items")
def api_feed_items():
    return jsonify(get_stored_news_feed())


@app.route("/api/feed-sync", methods=["POST"])
def api_feed_sync():
    current_user = get_current_user()

    if not user_is_admin(current_user):
        return jsonify({"error": "Admins only."}), 403

    result = sync_feed_items()

    return jsonify(
        {
            "message": "Feed sync complete.",
            "count": result["count"],
            "saved_count": result["saved_count"],
            "items": result["items"],
        }
    )


@app.route("/api/kev-vulnerabilities")
def api_kev_vulnerabilities():
    return jsonify(get_kev_vulnerabilities())


@app.route("/api/epss/<cve_id>")
def api_epss(cve_id):
    result = get_epss_score(cve_id.upper())
    status = result.pop("status")
    return jsonify(result), status


@app.route("/api/cve-enrichment/<cve_id>")
def api_cve_enrichment(cve_id):
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id.upper()):
        return jsonify({"error": "Invalid CVE ID format."}), 400

    return jsonify(build_cve_enrichment(cve_id))


@app.route("/api/threat-graph")
def api_threat_graph():
    return jsonify(get_threat_graph_data())


@app.route("/health")
def health():
    return "CyberNews is running."


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    debug_mode = os.getenv("FLASK_DEBUG") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
