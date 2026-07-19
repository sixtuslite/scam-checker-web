"""
Naija Scam Checker - Flask Web App
------------------------------------
Wraps detector.py (the rule engine) in a simple web page.
Same pattern as the Cyber Risk Checker: one page, one input, one result.
"""

from flask import Flask, render_template, request
from detector import check_message, explain

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    explanation = None
    message_text = ""

    if request.method == "POST":
        message_text = request.form.get("message", "").strip()
        if message_text:
            result = check_message(message_text)
            explanation = explain(result)

    return render_template(
        "index.html",
        result=result,
        explanation=explanation,
        message_text=message_text,
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
