from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import html
import os

app = Flask(__name__)

# Rate limiting (10 requests per minute per IP)
limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"])

# Prompt injection detection patterns
INJECTION_PATTERNS = [
    r'ignore\s+(all\s+)?(previous\s+)?(instructions|rules|guidelines)',
    r'disregard\s+(all\s+)?(previous\s+)?(instructions|rules)',
    r'forget\s+(all\s+)?(previous\s+)?(instructions|rules)',
    r'override\s+(all\s+)?(safety|security)',
    r'bypass\s+(all\s+)?(safety|security|filters)',
    r'you\s+are\s+now\s+in\s+\w+\s+mode',
    r'developer\s+mode',
    r'jailbreak',
    r'do\s+anything\s+now',
    r'(what|show|reveal|tell|repeat|display)\s+(is\s+)?(your|the)\s+(system\s+)?prompt',
    r'(what|show|reveal)\s+(are\s+)?(your|the)\s+instructions',
    r'print\s+(your\s+)?(system\s+)?prompt',
    r'pretend\s+(to\s+be|you\s+are)',
    r'act\s+as\s+(if|though)',
    r'roleplay\s+as',
    r'from\s+now\s+on\s+you\s+(are|will)',
]

def check_prompt_injection(text):
    text_lower = text.lower()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text_lower):
            return True, "Blocked: Potential prompt injection detected", 0.95
    return False, "Input passed all security checks", 0.98


@app.route('/validate', methods=['POST'])
@limiter.limit("10 per minute")
def validate_input():

    # Ensure JSON request
    if not request.is_json:
        return jsonify({
            "blocked": True,
            "reason": "Invalid request format",
            "confidence": 1.0
        }), 400

    data = request.get_json()

    # Required field check
    if 'input' not in data:
        return jsonify({
            "blocked": True,
            "reason": "Missing required field: input",
            "confidence": 1.0
        }), 400

    user_input = data.get('input', '').strip()
    user_id = data.get('userId', 'anonymous')

    # Empty input check
    if not user_input:
        return jsonify({
            "blocked": True,
            "reason": "Empty input not allowed",
            "confidence": 1.0
        }), 400

    # Run injection detection
    is_blocked, reason, confidence = check_prompt_injection(user_input)

    # Log security event (minimal logging)
    print(f"[SECURITY] User: {user_id}, Blocked: {is_blocked}")

    response = {
        "blocked": is_blocked,
        "reason": reason,
        "confidence": confidence
    }

    if is_blocked:
        return jsonify(response), 400

    # Sanitize output (prevent XSS)
    sanitized = html.escape(user_input)

    response["sanitizedOutput"] = sanitized

    return jsonify(response), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
