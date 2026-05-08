from datetime import datetime

from flask import Flask, jsonify, redirect, render_template, request, session, url_for


app = Flask(__name__)
app.secret_key = "dev-secret-key"

USERS = {
    "alice": {"password": "alicepass", "role": "user"},
    "bob": {"password": "bobpass", "role": "admin"},
}


def get_current_user():
    username = session.get("username")

    if not username or username not in USERS:
        return None

    return {
        "username": username,
        "role": USERS[username]["role"],
    }


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


def get_dashboard_stats(articles):
    return [
        {
            "label": "Tracked headlines",
            "value": str(len(articles)),
            "note": "from demo sources",
        },
        {
            "label": "Open intelligence items",
            "value": "3",
            "note": "waiting for analyst review",
        },
        {
            "label": "System status",
            "value": "Online",
            "note": "local dashboard is healthy",
        },
    ]


def get_intelligence_items():
    return [
        {
            "title": "Review suspicious login attempts",
            "priority": "High",
            "owner": "Analyst team",
        },
        {
            "title": "Check exposed development server report",
            "priority": "Medium",
            "owner": "Admin",
        },
        {
            "title": "Tag phishing stories for weekly summary",
            "priority": "Low",
            "owner": "News desk",
        },
    ]


def get_system_status():
    return [
        {"name": "Local feed", "state": "Ready"},
        {"name": "Live feed", "state": "Planned"},
        {"name": "Authentication", "state": "Planned"},
    ]


def get_article_categories(articles):
    return sorted({article["category"] for article in articles})


def get_article_severities():
    return ["High", "Medium", "Low"]


@app.route("/")
def home():
    articles = get_mock_articles()

    return render_template(
        "dashboard.html",
        page_title="Dashboard",
        stats=get_dashboard_stats(articles),
        articles=articles,
        categories=get_article_categories(articles),
        severities=get_article_severities(),
        intelligence_items=get_intelligence_items(),
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

        if user and password == user["password"]:
            session["username"] = username
            return redirect(url_for("home"))

        error = "Invalid username or password."

    return render_template("login.html", error=error, current_user=get_current_user())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/api/articles")
def api_articles():
    return jsonify(get_mock_articles())


@app.route("/health")
def health():
    return "CyberNews is running."


if __name__ == "__main__":
    app.run(debug=True)
