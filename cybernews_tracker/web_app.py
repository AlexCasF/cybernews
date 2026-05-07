from datetime import date, datetime

from flask import Flask, render_template


app = Flask(__name__)


@app.route("/")
def home():
    return "Welcome to CyberNews Tracker!"


@app.route("/news")
def news():
    username = "Alex"
    articles = [
        {
            "title": "New Security Patch Released Today",
            "summary": "Admins are encouraged to update their systems before the weekend.",
            "date": "2026-05-07",
        },
        {
            "title": "Phishing Scam Targets Online Users",
            "summary": "Users are advised to check email links carefully before clicking.",
            "date": "2026-05-06",
        },
        {
            "title": "AI Tool Detects Malware Faster Than Ever",
            "summary": "Researchers say automated detection can help teams respond sooner.",
            "date": "2026-05-05",
        },
    ]
    last_updated = datetime.now().strftime("%Y-%m-%d %H:%M")

    return render_template(
        "news.html",
        username=username,
        articles=articles,
        last_updated=last_updated,
    )


@app.route("/status")
def status():
    return "Application is running."


@app.route("/info")
def info():
    today = date.today()
    return f"Today's date is {today}."


@app.route("/greet/<name>")
def greet(name):
    return f"Hello, {name}!"


@app.route("/calculate/add/<int:num1>/<int:num2>")
def add_numbers(num1, num2):
    result = num1 + num2
    return f"The sum of {num1} and {num2} is {result}."


@app.route("/robots.txt")
def robots_txt():
    return (
        "User-agent: *\n"
        "Allow: /\n\n"
        "# A robot walks into a bar. The bartender asks, \"What'll ya have?\"\n"
        "# The robot says, \"Well, it's been a long day and I need to loosen up. "
        "How about a screwdriver?\"\n"
        "Sitemap: /sitemap.xml\n"
    ), 200, {"Content-Type": "text/plain"}


@app.route("/sitemap.xml")
def sitemap_xml():
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        "  <url>\n"
        "    <loc>/</loc>\n"
        "  </url>\n"
        "  <url>\n"
        "    <loc>/status</loc>\n"
        "  </url>\n"
        "  <url>\n"
        "    <loc>/info</loc>\n"
        "  </url>\n"
        "</urlset>\n"
    ), 200, {"Content-Type": "application/xml"}


if __name__ == "__main__":
    app.run(debug=True)
