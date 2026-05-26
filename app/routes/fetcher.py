from flask import Blueprint, request, jsonify, render_template
from flask_login import login_required
from app.utils.validators import validate_url
from app.utils.logger import log_event
import requests as http_requests

fetcher_bp = Blueprint("fetcher", __name__, url_prefix="/fetcher")


@fetcher_bp.route("/")
@login_required
def fetch_page():
    return render_template("fetcher/index.html")


@fetcher_bp.route("/fetch-site", methods=["POST"])
@login_required
def fetch_site():
    url = request.form.get("url", "").strip()

    # FIX A10: Validate URL before making any request
    # Blocks: localhost, private IPs, cloud metadata, non-http schemes
    if not validate_url(url):
        log_event("ssrf_blocked", user_id=request.remote_addr,
                  details=f"Blocked URL: {url}",
                  ip_address=request.remote_addr, status="failure")
        return jsonify({"error": "Invalid or disallowed URL. Internal addresses are not permitted."}), 400

    try:
        # FIX A10: Only follow redirects to safe URLs, short timeout
        response = http_requests.get(
            url,
            timeout=5,
            allow_redirects=False,  # FIX A10: Don't follow redirects (could redirect to internal)
            headers={"User-Agent": "SecureVault/1.0"}
        )

        title = ""
        content = response.text

        if "<title>" in content.lower():
            start = content.lower().find("<title>") + 7
            end = content.lower().find("</title>")
            if end > start:
                title = content[start:end].strip()[:200]  # FIX: Limit title length

        log_event("site_fetch", user_id=request.remote_addr,
                  details=f"Fetched: {url}",
                  ip_address=request.remote_addr)

        # FIX A10: Never return response body — only the title
        return jsonify({
            "title": title,
            "status": response.status_code
            # Removed "preview" field that was leaking response content
        })

    except http_requests.exceptions.Timeout:
        return jsonify({"error": "Request timed out"}), 408
    except Exception:
        # FIX A02: Don't expose internal error details
        return jsonify({"error": "Failed to fetch the URL"}), 500
