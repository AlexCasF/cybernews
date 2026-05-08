import re
import secrets
from datetime import date, datetime

from flask import Flask, make_response, redirect, render_template, request, url_for


app = Flask(__name__)
sessions = {}
USERS = {
    "alice": {"password": "alicepass", "role": "user"},
    "bob": {"password": "bobpass", "role": "admin"},
}


def get_current_user():
    session_token = request.cookies.get("session_token")

    if not session_token:
        return None

    return sessions.get(session_token)


@app.route("/")
def home():
    return "Welcome to CyberNews Tracker!"


@app.route("/news")
def news():
    current_user = get_current_user()
    username = "Guest"

    if current_user:
        username = current_user["username"]

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
        current_user=current_user,
        articles=articles,
        last_updated=last_updated,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username")
    password = request.form.get("password")

    user = USERS.get(username)

    if not user or user["password"] != password:
        return render_template("login.html", error="Invalid username or password.")

    session_token = secrets.token_urlsafe(24)
    sessions[session_token] = {
        "username": username,
        "role": user["role"],
        "login_time": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }

    response = make_response(redirect(url_for("news")))
    response.set_cookie(
        "session_token",
        session_token,
        httponly=True,
        samesite="Lax",
        secure=request.is_secure,
    )

    return response


@app.route("/dashboard")
def dashboard():
    current_user = get_current_user()

    if not current_user:
        return "Access denied. Please log in first.", 403

    return render_template("dashboard.html", current_user=current_user)


@app.route("/admin/dashboard")
def admin_dashboard():
    current_user = get_current_user()

    if not current_user:
        return "Access denied. Please log in first.", 403

    if current_user["role"] != "admin":
        return "Access denied. Admins only.", 403

    return render_template("admin_dashboard.html", current_user=current_user)


@app.route("/logout")
def logout():
    session_token = request.cookies.get("session_token")

    if session_token in sessions:
        sessions.pop(session_token)

    response = make_response(redirect(url_for("news")))
    response.delete_cookie("session_token")

    return response


@app.route("/cookie_check")
def cookie_check():
    response = make_response(render_template("cookie_check.html"))
    response.set_cookie("visible_cookie", "JavaScript can read this one")
    response.set_cookie(
        "hidden_cookie",
        "JavaScript cannot read this one",
        httponly=True,
        samesite="Lax",
        secure=request.is_secure,
    )

    return response


@app.route("/contact")
def contact():
    return render_template("contact_form.html")


@app.route("/submit-message", methods=["POST"])
def submit_message():
    name = request.form.get("name")
    email = request.form.get("email")
    message = request.form.get("message")
    email_pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    if not re.match(email_pattern, email):
        return render_template(
            "contact_form.html",
            error="Please enter a valid email address.",
            name=name,
            email=email,
            message=message,
        )

    return render_template(
        "confirmation.html",
        name=name,
        email=email,
        message=message,
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
