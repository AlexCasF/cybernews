import html
import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from uuid import uuid4

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from src.storage import get_ai_job, get_report, list_reports, save_ai_job, save_report


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")

USERS = {
    "alice": {
        "password_hash": "scrypt:32768:8:1$xfwMCTRrSH4FHpxC$71e60605e56b791e7e77a86445d316c1e86d705119ba37bd454566e45713b68d41c45a76c46ce9a7e5cd54e1653ed3210f1bf4a0d3dad2af13a745cb6aed2cb9",
        "role": "user",
    },
    "bob": {
        "password_hash": "scrypt:32768:8:1$5XuElFcWxCS0LADI$c1320b95dca5b078efcdca3a5570a6cba150b452a069af919e117cea541f8b9a0992859145b81060d63f5a509ebe3c8ab21fa6d9cad7256cd3f9719ca5debe2c",
        "role": "admin",
    },
}
ADMIN_REPORTS = []
AUDIT_LOG = []
NEWSAPI_URL = "https://newsapi.org/v2/everything"
BSI_RSS_URL = "https://wid.cert-bund.de/content/public/securityAdvisory/rss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
SECURITY_RSS_SOURCES = [
    {
        "name": "The Hacker News",
        "url": "https://thehackernews.com/feeds/posts/default",
    },
    {
        "name": "SecurityWeek",
        "url": "https://www.securityweek.com/feed/",
    },
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


def get_mock_articles():
    return [
        {
            "id": 1,
            "title": "Critical VPN bug exploited by ransomware group",
            "summary": "Administrators are urged to patch affected VPN gateways quickly.",
            "source": "CyberDaily",
            "url": "#",
            "published": "2026-05-08",
            "category": "Vulnerability",
            "severity": "High",
        },
        {
            "id": 2,
            "title": "Phishing campaign uses fake parcel tracking emails",
            "summary": "Attackers are copying delivery notices to steal account credentials.",
            "source": "ThreatWire",
            "url": "#",
            "published": "2026-05-08",
            "category": "Phishing",
            "severity": "Medium",
        },
        {
            "id": 3,
            "title": "New malware hides inside browser extensions",
            "summary": "Researchers found extensions collecting browser data in the background.",
            "source": "Malware Lab",
            "url": "#",
            "published": "2026-05-07",
            "category": "Malware",
            "severity": "Medium",
        },
    ]


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


def get_live_news_articles():
    api_key = os.getenv("NEWS_API_KEY")

    if not api_key:
        return {
            "articles": get_mock_articles(),
            "source": "fallback",
            "message": "NEWS_API_KEY is missing. Showing local demo articles.",
        }

    query = urlencode(
        {
            "q": "cybersecurity",
            "language": "en",
            "sortBy": "publishedAt",
            "pageSize": 6,
            "apiKey": api_key,
        }
    )

    try:
        with urlopen(f"{NEWSAPI_URL}?{query}", timeout=8) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception:
        return {
            "articles": get_mock_articles(),
            "source": "fallback",
            "message": "Live news is unavailable. Showing local demo articles.",
        }

    if data.get("status") != "ok":
        return {
            "articles": get_mock_articles(),
            "source": "fallback",
            "message": "NewsAPI returned an error. Showing local demo articles.",
        }

    live_articles = [
        normalize_newsapi_article(article, index + 1)
        for index, article in enumerate(data.get("articles", []))
        if article.get("title") and article.get("url")
    ]

    if not live_articles:
        return {
            "articles": get_mock_articles(),
            "source": "fallback",
            "message": "No live articles were found. Showing local demo articles.",
        }

    return {
        "articles": live_articles,
        "source": "newsapi",
        "message": "Live NewsAPI articles loaded.",
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
                for index, entry in enumerate(entries[:4])
            )
        else:
            items = root.findall("./channel/item")
            articles.extend(
                normalize_rss_item(item, source["name"], source_slug, index + 1)
                for index, item in enumerate(items[:4])
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
        for index, item in enumerate(items[:8])
    ]

    return {
        "advisories": advisories,
        "source": "bsi",
        "message": "BSI advisories loaded.",
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


def get_dashboard_stats(articles, intelligence_reports, kev_vulnerabilities):
    return [
        {
            "label": "Tracked headlines",
            "value": str(len(articles)),
            "note": "shown on the dashboard",
        },
        {
            "label": "Intel reports",
            "value": str(len(intelligence_reports)),
            "note": "ready for analyst review",
        },
        {
            "label": "Known exploited CVEs",
            "value": str(len(kev_vulnerabilities)),
            "note": "from CISA KEV",
        },
        {
            "label": "System status",
            "value": "Online",
            "note": "local dashboard is healthy",
        },
    ]


def get_intelligence_reports():
    return [
        {
            "title": "Repeated admin login failures",
            "severity": "High",
            "source": "Authentication logs",
            "summary": "Multiple failed admin logins appeared in a short time window.",
            "action": "Check source IP addresses and confirm whether the attempts were expected.",
        },
        {
            "title": "Possible exposed development server",
            "severity": "Medium",
            "source": "External scan",
            "summary": "A development host may be reachable from the public internet.",
            "action": "Verify firewall rules and remove public access if it is not required.",
        },
        {
            "title": "Phishing theme increase",
            "severity": "Low",
            "source": "News monitoring",
            "summary": "Several new headlines mention parcel delivery phishing campaigns.",
            "action": "Prepare a short awareness note for users.",
        },
    ]


def get_dashboard_intelligence_reports():
    if not ADMIN_REPORTS:
        return get_intelligence_reports()

    return [
        {
            "title": report["title"],
            "severity": report["severity"],
            "source": f"Admin report by {report['created_by']}",
            "summary": report["summary"],
            "action": f"Created at {report['created_at']}. Review and assign next steps.",
        }
        for report in reversed(ADMIN_REPORTS)
    ]


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


def create_ai_job(payload, current_user):
    action = payload.get("action", "")
    entity_type = payload.get("entity_type", "")
    entity_id = str(payload.get("entity_id", "")).strip()
    context_depth = payload.get("context_depth", "medium")
    output_format = payload.get("output_format", "structured_json")

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

    if action == "cve_enrichment" and entity_type != "cve":
        return None, "CVE enrichment requires a cve entity."

    if action == "ioc_enrichment" and entity_type != "ioc":
        return None, "IOC enrichment requires an ioc entity."

    job_id = str(uuid4())
    created_at = get_timestamp()
    selected_text = payload.get("selected_text", "")
    result_json = build_mock_ai_result(action, entity_type, entity_id, selected_text)
    report_json = None

    if output_format in {"html_report", "both"} or action == "generate_report":
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
        "model": "mock-ai-v1",
        "prompt_version": "mock-v1",
        "result_json": result_json,
        "report_json": report_json,
        "rendered_html": None,
        "confidence": result_json.get("confidence", 0.7),
        "warnings": ["Mock AI result. Gemini is not connected yet."],
        "evidence": result_json.get("evidence", []),
        "created_by": current_user["username"] if current_user else "guest",
        "created_at": created_at,
        "completed_at": created_at,
    }
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


def get_system_status():
    return [
        {"name": "Local dashboard", "state": "Ready"},
        {"name": "Live news refresh", "state": "Ready"},
        {"name": "Security RSS feeds", "state": "Ready"},
        {"name": "BSI advisory feed", "state": "Ready"},
        {"name": "CISA KEV feed", "state": "Ready"},
        {"name": "Demo authentication", "state": "Ready"},
        {"name": "Report preview frame", "state": "Ready"},
        {"name": "Correlation data", "state": "Ready"},
    ]


def get_article_categories(articles):
    return sorted({article["category"] for article in articles} | {"News"})


def get_article_severities():
    return ["High", "Medium", "Low"]


@app.route("/")
def home():
    articles = get_mock_articles()
    intelligence_reports = get_dashboard_intelligence_reports()
    bsi_data = get_bsi_advisories()
    kev_data = get_kev_vulnerabilities()
    kev_vulnerabilities = kev_data["vulnerabilities"][:4]
    security_rss_data = get_security_rss_articles()

    return render_template(
        "dashboard.html",
        page_title="Dashboard",
        stats=get_dashboard_stats(articles, intelligence_reports, kev_vulnerabilities),
        articles=articles,
        categories=get_article_categories(articles),
        severities=get_article_severities(),
        intelligence_reports=intelligence_reports,
        bsi_advisories=bsi_data["advisories"][:4],
        bsi_message=bsi_data["message"],
        kev_vulnerabilities=kev_vulnerabilities,
        kev_message=kev_data["message"],
        security_rss_articles=security_rss_data["articles"][:6],
        security_rss_message=security_rss_data["message"],
        system_status=get_system_status(),
        current_user=get_current_user(),
        last_updated=datetime.now().strftime("%Y-%m-%d %H:%M"),
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
            return redirect(url_for("home"))

        record_login_attempt(username, False)
        error = "Invalid username or password."

    return render_template("login.html", error=error, current_user=get_current_user())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/admin/reports", methods=["GET", "POST"])
def admin_reports():
    current_user = get_current_user()

    if not current_user:
        return redirect(url_for("login"))

    if not user_is_admin(current_user):
        return "Access denied. Admins only.", 403

    error = ""

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        severity = request.form.get("severity", "").strip()
        summary = request.form.get("summary", "").strip()

        if title and severity and summary:
            ADMIN_REPORTS.append(
                {
                    "id": len(ADMIN_REPORTS) + 1,
                    "title": title,
                    "severity": severity,
                    "summary": summary,
                    "created_by": current_user["username"],
                    "created_at": get_timestamp(),
                }
            )
            return redirect(url_for("admin_reports"))

        error = "Please fill in all report fields."

    return render_template(
        "admin_reports.html",
        reports=ADMIN_REPORTS,
        audit_log=AUDIT_LOG,
        error=error,
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


@app.route("/api/ai/jobs", methods=["POST"])
def api_create_ai_job():
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


@app.route("/api/reports/<report_id>")
def api_get_report(report_id):
    report = get_report(report_id)

    if not report:
        return jsonify({"error": "Report not found."}), 404

    return jsonify(report)


@app.route("/api/articles")
def api_articles():
    return jsonify(get_mock_articles())


@app.route("/api/live-news")
def api_live_news():
    return jsonify(get_live_news_articles())


@app.route("/api/bsi-advisories")
def api_bsi_advisories():
    return jsonify(get_bsi_advisories())


@app.route("/api/security-feeds")
def api_security_feeds():
    return jsonify(get_security_rss_articles())


@app.route("/api/kev-vulnerabilities")
def api_kev_vulnerabilities():
    return jsonify(get_kev_vulnerabilities())


@app.route("/api/epss/<cve_id>")
def api_epss(cve_id):
    result = get_epss_score(cve_id.upper())
    status = result.pop("status")
    return jsonify(result), status


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
