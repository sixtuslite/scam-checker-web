"""
Naija Scam Checker - Flask Web App
------------------------------------
Wraps detector.py (the rule engine) in a simple web page.
Same pattern as the Cyber Risk Checker: one page, one input, one result.
"""

import os
from flask import Flask, render_template, request
from detector import check_message, explain, get_reason_chips, what_to_do

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    explanation = None
    chips = None
    action = None
    message_text = ""

    if request.method == "POST":
        message_text = request.form.get("message", "").strip()
        if message_text:
            result = check_message(message_text)
            explanation = explain(result)
            chips = get_reason_chips(result)
            action = what_to_do(result)

    return render_template(
        "index.html",
        result=result,
        explanation=explanation,
        chips=chips,
        action=action,
        message_text=message_text,
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
