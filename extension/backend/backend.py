from flask import Flask, request, jsonify
from flask_cors import CORS
from web_vuln_scanner import scan_sql_injection, scan_xss

app = Flask(__name__)
CORS(app)  # Allow Chrome extension requests


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    # CALL YOUR SCANNER FUNCTIONS
    sql_results = scan_sql_injection(url)
    xss_results = scan_xss(url)

    # RETURN STRUCTURED JSON
    return jsonify({
        "target": url,
        "sql_injection": {
            "vulnerable": len(sql_results) > 0,
            "count": len(sql_results),
            "details": sql_results
        },
        "xss": {
            "vulnerable": len(xss_results) > 0,
            "count": len(xss_results),
            "details": xss_results
        }
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
