# -*- coding: utf-8 -*-
"""
CyberShield - Password Security Analyzer
Author: Senior Cybersecurity Engineer / Full-Stack Web Developer
Description: Flask Application entry point. Routes requests to analyze password strength,
generate secure passwords, hash passwords, and display findings via a modern web interface.
"""

import os
from flask import Flask, render_template, request, jsonify

# Import security modules from our local package
from utils.checker import check_password_strength
from utils.entropy import calculate_entropy
from utils.cracktime import estimate_crack_time, calculate_scenarios
from utils.hashing import generate_hashes
from utils.generator import generate_password
from utils.validator import is_valid_password, sanitize_password

app = Flask(__name__)

# Configure secret key for security (standard Flask requirement)
app.secret_key = os.urandom(24)

@app.route("/", methods=["GET"])
def index():
    """
    Renders the central Security Dashboard index page.
    """
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Handles classic multi-page POST form submissions.
    Processes the password and renders a detailed 'result.html' dashboard.
    """
    raw_password = request.form.get("password", "")
    
    # Sanitize and validate password length/characters
    password = sanitize_password(raw_password)
    
    if not password:
        return render_template("index.html", error="Please enter a password to analyze.")
        
    if not is_valid_password(password):
        # Allow validation failure to guide user to safe limits without throwing raw crashes
        return render_template("index.html", error="Invalid character input or password exceeds safe limits (128 characters).")
        
    # Run full analytics sequence
    analysis = check_password_strength(password)
    entropy_val, entropy_level, entropy_desc = calculate_entropy(password)
    crack_time, crack_desc = estimate_crack_time(entropy_val)
    scenarios = calculate_scenarios(entropy_val)
    hashes = generate_hashes(password)
    
    # Render final technical report
    return render_template(
        "result.html",
        password=password,
        score=analysis["score"],
        strength=analysis["strength"],
        badge_class=analysis["badge_class"],
        color_class=analysis["color_class"],
        progress_class=analysis["progress_class"],
        gauge_color=analysis["gauge_color"],
        warnings=analysis["warnings"],
        suggestions=analysis["suggestions"],
        checks=analysis.get("checks", {}),
        metrics=analysis["metrics"],
        entropy=entropy_val,
        entropy_level=entropy_level,
        entropy_desc=entropy_desc,
        crack_time=crack_time,
        crack_desc=crack_desc,
        scenarios=scenarios,
        hashes=hashes
    )

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    AJAX endpoint for asynchronous, real-time password analysis while typing.
    Expects JSON payload with the 'password' parameter.
    """
    data = request.get_json() or {}
    raw_password = data.get("password", "")
    
    password = sanitize_password(raw_password)
    
    if not password:
        return jsonify({
            "error": "Password field is empty."
        }), 400
        
    if not is_valid_password(password):
        return jsonify({
            "error": "Invalid character format or password exceeds maximum length limits."
        }), 400
        
    # Analyze
    analysis = check_password_strength(password)
    entropy_val, entropy_level, entropy_desc = calculate_entropy(password)
    crack_time, crack_desc = estimate_crack_time(entropy_val)
    scenarios = calculate_scenarios(entropy_val)
    hashes = generate_hashes(password)
    
    return jsonify({
        "password": password,
        "score": analysis["score"],
        "strength": analysis["strength"],
        "badge_class": analysis["badge_class"],
        "color_class": analysis["color_class"],
        "progress_class": analysis["progress_class"],
        "gauge_color": analysis["gauge_color"],
        "warnings": analysis["warnings"],
        "suggestions": analysis["suggestions"],
        "checks": analysis.get("checks", {}),
        "metrics": analysis["metrics"],
        "entropy": entropy_val,
        "entropy_level": entropy_level,
        "entropy_desc": entropy_desc,
        "crack_time": crack_time,
        "crack_desc": crack_desc,
        "scenarios": scenarios,
        "hashes": hashes
    })

@app.route("/api/generate", methods=["POST"])
def api_generate():
    """
    AJAX endpoint for securing and retrieving random generated keys.
    """
    data = request.get_json() or {}
    
    try:
        length = int(data.get("length", 16))
        # Enforce reasonable parameters
        length = max(8, min(64, length))
    except (ValueError, TypeError):
        length = 16
        
    use_upper = bool(data.get("upper", True))
    use_lower = bool(data.get("lower", True))
    use_digits = bool(data.get("digits", True))
    use_symbols = bool(data.get("symbols", True))
    exclude_similar = bool(data.get("exclude_similar", data.get("excludeSimilar", False)))
    exclude_ambiguous = bool(data.get("exclude_ambiguous", data.get("excludeAmbiguous", False)))
    
    # Generate secure password
    pwd = generate_password(
        length=length,
        use_upper=use_upper,
        use_lower=use_lower,
        use_digits=use_digits,
        use_symbols=use_symbols,
        exclude_similar=exclude_similar,
        exclude_ambiguous=exclude_ambiguous
    )
    
    # Evaluate strength of generated password for confidence checks
    analysis = check_password_strength(pwd)
    entropy_val, _, _ = calculate_entropy(pwd)
    crack_time, _ = estimate_crack_time(entropy_val)
    
    return jsonify({
        "password": pwd,
        "length": len(pwd),
        "strength": analysis["strength"],
        "score": analysis["score"],
        "crack_time": crack_time
    })

# Main execution loop
if __name__ == "__main__":
    # Bind to 0.0.0.0 and port 5000 for standard local testing
    print("[*] Launching CyberShield Password Security Analyzer Backend...")
    app.run(host="0.0.0.0", port=5000, debug=True)
