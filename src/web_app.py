import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlencode
from urllib.request import urlopen

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash


app = Flask(__name__)
app.secret_key = "dev-secret-key"

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


def get_dashboard_stats(articles):
    return [
        {
            "label": "Tracked headlines",
            "value": str(len(articles)),
            "note": "from demo sources",
        },
        {"label": "Intel reports", "value": "3", "note": "ready for analyst review"},
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


def get_system_status():
    return [
        {"name": "Local feed", "state": "Ready"},
        {"name": "Live feed", "state": "Planned"},
        {"name": "Authentication", "state": "Planned"},
    ]


def get_article_categories(articles):
    return sorted({article["category"] for article in articles} | {"News"})


def get_article_severities():
    return ["High", "Medium", "Low"]


@app.route("/")
def home():
    articles = get_mock_articles()
    bsi_data = get_bsi_advisories()

    return render_template(
        "dashboard.html",
        page_title="Dashboard",
        stats=get_dashboard_stats(articles),
        articles=articles,
        categories=get_article_categories(articles),
        severities=get_article_severities(),
        intelligence_reports=get_intelligence_reports(),
        bsi_advisories=bsi_data["advisories"][:4],
        bsi_message=bsi_data["message"],
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


@app.route("/api/articles")
def api_articles():
    return jsonify(get_mock_articles())


@app.route("/api/live-news")
def api_live_news():
    return jsonify(get_live_news_articles())


@app.route("/api/bsi-advisories")
def api_bsi_advisories():
    return jsonify(get_bsi_advisories())


@app.route("/health")
def health():
    return "CyberNews is running."


if __name__ == "__main__":
    app.run(debug=True)
