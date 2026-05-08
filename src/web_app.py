from datetime import datetime

from flask import Flask, render_template


app = Flask(__name__)


@app.route("/")
def home():
    return render_template(
        "dashboard.html",
        page_title="Dashboard",
        last_updated=datetime.now().strftime("%Y-%m-%d %H:%M"),
    )


@app.route("/health")
def health():
    return "CyberNews is running."


if __name__ == "__main__":
    app.run(debug=True)
