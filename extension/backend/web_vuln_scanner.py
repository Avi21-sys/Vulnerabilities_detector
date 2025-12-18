from pprint import pprint
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
from payloads import SQL_ERRORS, sql_payloads, XSS_PAYLOADS  # import payloads

# Set global session
session = requests.Session()
session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# Define a global timeout (in seconds) for all requests
REQUEST_TIMEOUT = 20

def get_forms(url):
    try:
        res = session.get(url, timeout=REQUEST_TIMEOUT)
        res.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] Error fetching forms from {url}: {e}")
        return []
    soup = BeautifulSoup(res.content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all("input"):
        inputs.append({
            "type": input_tag.attrs.get("type", "text"),
            "name": input_tag.attrs.get("name"),
            "value": input_tag.attrs.get("value", "")
        })

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_sql_vulnerable(response):
    if response is None:
        return False
    content = response.content.decode(errors="ignore").lower()
    return any(re.search(error.lower(), content) for error in SQL_ERRORS)

def scan_sql_injection(url):
    results = []
    forms = get_forms(url)

    for form in forms:
        details = get_form_details(form)
        for payload in sql_payloads:  # Use full list of SQL injection payloads
            data = {}

            for input_tag in details["inputs"]:
                if not input_tag["name"]:
                    continue

                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag["name"]] = input_tag["value"] + payload
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = payload

            form_url = urljoin(url, details["action"])

            try:
                res = (
                    session.post(form_url, data=data, timeout=REQUEST_TIMEOUT)
                    if details["method"] == "post"
                    else session.get(form_url, params=data, timeout=REQUEST_TIMEOUT)
                )
                res.raise_for_status()
            except requests.RequestException as e:
                print(f"[!] Request error during SQL injection scan: {e}")
                continue

            if is_sql_vulnerable(res):
                results.append({
                    "form_action": form_url,
                    "payload": payload,
                    "form_details": details
                })
                break

    return results

def submit_xss_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}

    for input_tag in form_details["inputs"]:
        if not input_tag["name"]:
            continue

        if input_tag["type"] in ["text", "search"]:
            data[input_tag["name"]] = payload
        elif input_tag["value"]:
            data[input_tag["name"]] = input_tag["value"]

    try:
        res = (
            session.post(target_url, data=data, timeout=REQUEST_TIMEOUT)
            if form_details["method"] == "post"
            else session.get(target_url, params=data, timeout=REQUEST_TIMEOUT)
        )
        res.raise_for_status()
        return res
    except requests.RequestException as e:
        print(f"[!] Request error during XSS scan: {e}")
        return None

def scan_xss(url):
    results = []
    forms = get_forms(url)

    for form in forms:
        details = get_form_details(form)
        for payload in XSS_PAYLOADS:
            res = submit_xss_form(details, url, payload)
            if res and payload in res.text:
                results.append({
                    "form_action": urljoin(url, details["action"]),
                    "payload": payload,
                    "form_details": details
                })
                break

    return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python web_vuln_scanner.py <url>")
        exit(1)

    target_url = sys.argv[1]

    print("----- SQL Injection Scan -----")
    sql_results = scan_sql_injection(target_url)
    for res in sql_results:
        print(f"[!] SQL Injection found in form at {res['form_action']} with payload: {res['payload']}")
        pprint(res['form_details'])

    print("\n----- XSS Scan -----")
    xss_results = scan_xss(target_url)
    for res in xss_results:
        print(f"[!] XSS found in form at {res['form_action']} with payload: {res['payload']}")
        pprint(res['form_details'])
