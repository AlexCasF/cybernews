from datetime import datetime

from flask import Flask, render_template


app = Flask(__name__)


@app.route("/")
def home():
    stats = [
        {
            "label": "Tracked headlines",
            "value": "8",
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

    headlines = [
        {
            "title": "Critical VPN bug exploited by ransomware group",
            "source": "CyberDaily",
            "category": "Vulnerability",
            "published": "2026-05-08",
        },
        {
            "title": "Phishing campaign uses fake parcel tracking emails",
            "source": "ThreatWire",
            "category": "Phishing",
            "published": "2026-05-08",
        },
        {
            "title": "New malware hides inside browser extensions",
            "source": "Malware Lab",
            "category": "Malware",
            "published": "2026-05-07",
        },
    ]

    intelligence_items = [
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

    system_status = [
        {"name": "Local feed", "state": "Ready"},
        {"name": "Live feed", "state": "Planned"},
        {"name": "Authentication", "state": "Planned"},
    ]

    return render_template(
        "dashboard.html",
        page_title="Dashboard",
        stats=stats,
        headlines=headlines,
        intelligence_items=intelligence_items,
        system_status=system_status,
        last_updated=datetime.now().strftime("%Y-%m-%d %H:%M"),
    )


@app.route("/health")
def health():
    return "CyberNews is running."


if __name__ == "__main__":
    app.run(debug=True)
