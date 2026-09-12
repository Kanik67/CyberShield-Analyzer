# -*- coding: utf-8 -*-
"""
CyberShield - Password Strength Checking Engine
Author: Senior Cybersecurity Engineer
Description: Inspects password composition, runs dictionary checks, detects sequences,
repeated chars, and keyboard layouts, then scores the password with tailored recommendations.
"""

import os
import re

def load_common_passwords() -> set[str]:
    """
    Loads common insecure passwords from common_passwords.txt.
    
    Returns:
        set: A lookup set of common passwords in lowercase.
    """
    common_set = set()
    # Find common_passwords.txt relative to this script's directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    file_path = os.path.join(base_dir, 'common_passwords.txt')
    
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    cleaned = line.strip().lower()
                    if cleaned:
                        common_set.add(cleaned)
        except Exception:
            # Fallback if there is an error reading the file
            pass
            
    # Always include standard fallbacks in case file is unreadable
    fallbacks = {'123456', '123456789', 'password', 'qwerty', 'admin', 'welcome', 'letmein'}
    common_set.update(fallbacks)
    return common_set

def detect_sequential(password: str) -> bool:
    """
    Detects if there are sequential alphabetical or numerical sequences
    of length 3 or more (e.g., 'abc', '789', '321').
    
    Args:
        password (str): The password to analyze.
        
    Returns:
        bool: True if sequential sequences exist.
    """
    p = password.lower()
    
    # Check alphabetical and numerical sequences
    for i in range(len(p) - 2):
        char1, char2, char3 = p[i], p[i+1], p[i+2]
        
        # Check numerical sequence (ascending/descending)
        if char1.isdigit() and char2.isdigit() and char3.isdigit():
            val1, val2, val3 = int(char1), int(char2), int(char3)
            if (val2 == val1 + 1 and val3 == val2 + 1) or (val2 == val1 - 1 and val3 == val2 - 1):
                return True
                
        # Check alphabetical sequence (ascending/descending)
        if char1.isalpha() and char2.isalpha() and char3.isalpha():
            ord1, ord2, ord3 = ord(char1), ord(char2), ord(char3)
            if (ord2 == ord1 + 1 and ord3 == ord2 + 1) or (ord2 == ord1 - 1 and ord3 == ord2 - 1):
                return True
                
    return False

def detect_repeated(password: str) -> bool:
    """
    Detects if the password has the same character repeated consecutively 
    3 or more times (e.g. 'aaa', '111', '!!!') or repeating sequence groups.
    """
    return bool(re.search(r'(.)\1\1', password) or re.search(r'(.{2,4})\1', password))

def detect_dates_and_patterns(password: str) -> bool:
    """
    Detects obvious calendar years (1950-2039), date formats, or keyboard patterns.
    """
    if re.search(r'(?:19[5-9]\d|20[0-3]\d)', password):
        return True
    if re.search(r'(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])', password):
        return True
    return detect_keyboard_patterns(password)

def detect_keyboard_patterns(password: str) -> bool:
    """
    Detects common keyboard walk sequences of length 4 or more
    on a standard QWERTY layout (e.g. 'qwer', 'asdf', 'zxcv').
    
    Args:
        password (str): The password to analyze.
        
    Returns:
        bool: True if keyboard patterns are found.
    """
    p = password.lower()
    qwerty_rows = [
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1234567890"
    ]
    
    for row in qwerty_rows:
        # Forward pattern (length 4)
        for i in range(len(row) - 3):
            sub = row[i:i+4]
            rev_sub = sub[::-1]
            if sub in p or rev_sub in p:
                return True
                
    return False

def check_password_strength(password: str) -> dict:
    """
    Analyzes the strength of a password by checking multiple vectors:
    length, case variation, numbers, symbols, sequential patterns, repeats, keyboard walks,
    and matching against a known common password database.
    
    Args:
        password (str): The password to inspect.
        
    Returns:
        dict: A structured report containing strength indicators, score, badges, and recommendations.
    """
    if not password:
        return {
            "score": 0,
            "strength": "None",
            "badge_class": "bg-gray-800 text-gray-400 border-gray-700",
            "color_class": "text-gray-400",
            "suggestions": ["Please enter a password to run the analyzer."],
            "warnings": [],
            "metrics": {}
        }
        
    length = len(password)
    
    # Composition metrics
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_symbols = any(not c.isalnum() for c in password)
    
    common_passwords = load_common_passwords()
    is_common = password.lower() in common_passwords
    is_sequential = detect_sequential(password)
    is_repeated = detect_repeated(password)
    is_keyboard = detect_keyboard_patterns(password)
    
    is_dates = detect_dates_and_patterns(password)
    
    # Character class counts
    upper_count = sum(1 for c in password if c.isupper())
    lower_count = sum(1 for c in password if c.islower())
    digits_count = sum(1 for c in password if c.isdigit())
    symbols_count = sum(1 for c in password if not c.isalnum())
    unique_count = len(set(password))
    unique_ratio = round(unique_count / max(1, length), 2)

    # ----------------------------------------------------
    # Scoring Algorithm
    # Max Score: 100 points
    # ----------------------------------------------------
    score = 0
    
    # 1. Length Points (Max 50 points)
    if length <= 4:
        score += 5
    elif length <= 7:
        score += 15
    elif length <= 11:
        score += 30
    elif length <= 15:
        score += 45
    else:
        score += 50
        
    # 2. Composition Bonuses (Max 40 points)
    if has_lower:
        score += 10
    if has_upper:
        score += 10
    if has_digits:
        score += 10
    if has_symbols:
        score += 10
        
    # 3. Dynamic Length & Diversity Bonus
    if length >= 16:
        score += 10
    if unique_ratio >= 0.8 and length >= 10:
        score += 5
        
    # 4. Deductions (Penalties)
    if (has_lower or has_upper) and not has_digits and not has_symbols:
        score -= 15
    if has_digits and not has_lower and not has_upper and not has_symbols:
        score -= 15
        
    # Pattern penalties
    if is_sequential:
        score -= 15
    if is_repeated:
        score -= 15
    if is_keyboard or is_dates:
        score -= 15
        
    # Critical dictionary penalty
    if is_common:
        score = 0
        
    # Clamp score between 0 and 100
    score = max(0, min(100, score))
    
    # ----------------------------------------------------
    # Strength Categorization (5 Standard Tiers)
    # ----------------------------------------------------
    if score < 25:
        strength = "Very Weak"
        badge_class = "bg-rose-500/10 text-rose-400 border border-rose-500/20"
        color_class = "text-rose-500"
        progress_class = "bg-rose-500"
        gauge_color = "#f43f5e"
    elif score < 50:
        strength = "Weak"
        badge_class = "bg-orange-500/10 text-orange-400 border border-orange-500/20"
        color_class = "text-orange-500"
        progress_class = "bg-orange-500"
        gauge_color = "#f97316"
    elif score < 70:
        strength = "Fair"
        badge_class = "bg-amber-500/10 text-amber-400 border border-amber-500/20"
        color_class = "text-amber-500"
        progress_class = "bg-amber-500"
        gauge_color = "#f59e0b"
    elif score < 85:
        strength = "Strong"
        badge_class = "bg-sky-500/10 text-sky-400 border border-sky-500/20"
        color_class = "text-sky-500"
        progress_class = "bg-sky-500"
        gauge_color = "#0ea5e9"
    else:
        strength = "Very Strong"
        badge_class = "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
        color_class = "text-emerald-500"
        progress_class = "bg-emerald-500"
        gauge_color = "#10b981"
        
    # ----------------------------------------------------
    # Warnings & Actionable Recommendations
    # ----------------------------------------------------
    warnings = []
    suggestions = []
    
    if is_common:
        warnings.append("CRITICAL: This password is on the list of most common insecure passwords!")
        suggestions.append("Change this password immediately. Avoid words that appear in dictionary files or common lists.")
        
    if length < 8:
        warnings.append("Dangerous Length: Passwords under 8 characters are extremely easy to brute-force.")
        suggestions.append("Increase password length to at least 12-16 characters. Every single added character increases strength exponentially.")
    elif length < 12:
        warnings.append("Sub-optimal Length: Standard security policies require 12+ characters for reliable security.")
        suggestions.append("Aim for a length of 12 or 16+ characters to survive modern distributed GPU attacks.")
        
    if not has_upper:
        suggestions.append("Add uppercase letters (A-Z) to mix character casing and expand the entropy search pool.")
    if not has_lower:
        suggestions.append("Add lowercase letters (a-z) to include standard lower alphabets.")
    if not has_digits:
        suggestions.append("Integrate numerical digits (0-9) to secure your password against pure alphabetical search rigs.")
    if not has_symbols:
        suggestions.append("Add special characters or symbols (e.g., @, #, $, %, !, *) to disrupt automated dictionary matches.")
        
    if is_repeated:
        warnings.append("Pattern Detected: Same character is repeating 3+ times consecutively or in identical chunks.")
        suggestions.append("Remove repeated groups (e.g., 'aaa', '111') which reduce pattern unpredictability.")
        
    if is_sequential:
        warnings.append("Pattern Detected: Sequential numbers/letters found (e.g., '123', 'abc').")
        suggestions.append("Avoid standard keyboard sequences or sequential progressions (e.g., abc, 123, zyx) as attackers optimize for these.")
        
    if is_keyboard or is_dates:
        warnings.append("Pattern Detected: Obvious keyboard layouts or calendar dates/years found.")
        suggestions.append("Do not walk keyboard rows or include birth years or dates.")
        
    if score >= 85 and not warnings:
        suggestions.append("Excellent job! Your password meets top-tier cybersecurity standards. It is secure for deployment.")

    # 6 Security checks matrix
    checks = {
        "length": {
            "passed": length >= 12,
            "title": "Password Length",
            "detail": f"{length} characters (12+ recommended)"
        },
        "repeated": {
            "passed": not is_repeated,
            "title": "Repeated Characters / Groups",
            "detail": "Consecutive repeated characters or repeating chunks detected" if is_repeated else "No excessive repeating character runs"
        },
        "sequential": {
            "passed": not is_sequential,
            "title": "Sequential Patterns",
            "detail": "Contains sequential letters or numbers (e.g. 123, abc)" if is_sequential else "No predictable sequential character series"
        },
        "common": {
            "passed": not is_common,
            "title": "Common Word / Leaked Check",
            "detail": "Matches a top common or breached password" if is_common else "Not present in top common password dictionaries"
        },
        "dates": {
            "passed": not is_dates,
            "title": "Obvious Dates & Key Walks",
            "detail": "Contains calendar date, 4-digit year, or keyboard walk" if is_dates else "No obvious dates or layout walks"
        },
        "diversity": {
            "passed": (has_lower and has_upper and has_digits and has_symbols),
            "title": "Character Diversity",
            "detail": "Missing one or more character classes" if not (has_lower and has_upper and has_digits and has_symbols) else "All 4 character classes utilized"
        }
    }
        
    return {
        "score": score,
        "strength": strength,
        "badge_class": badge_class,
        "color_class": color_class,
        "progress_class": progress_class,
        "gauge_color": gauge_color,
        "warnings": warnings,
        "suggestions": suggestions,
        "checks": checks,
        "metrics": {
            "length": length,
            "uppercase": upper_count,
            "lowercase": lower_count,
            "numbers": digits_count,
            "symbols": symbols_count,
            "unique": unique_count,
            "unique_ratio": unique_ratio,
            "has_lower": has_lower,
            "has_upper": has_upper,
            "has_digits": has_digits,
            "has_symbols": has_symbols,
            "is_common": is_common,
            "is_sequential": is_sequential,
            "is_repeated": is_repeated,
            "is_keyboard": is_keyboard,
            "is_dates": is_dates
        }
    }
