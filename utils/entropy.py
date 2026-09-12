# -*- coding: utf-8 -*-
"""
CyberShield - Information Theory Entropy Module
Author: Senior Cybersecurity Engineer
Description: Calculates the Shannon entropy of a password to quantify its theoretical strength.
Formula: Entropy (H) = Length (L) * log2(Character Pool Size (R))
"""

import math

def calculate_entropy(password: str) -> tuple[float, str, str]:
    """
    Computes Shannon entropy for a given password.
    
    Character Set Ranges:
    - Lowercase letters (a-z): 26
    - Uppercase letters (A-Z): 26
    - Numerical digits (0-9): 10
    - Special symbols: 33 (standard ASCII punctuation)
    - Non-ASCII/Unicode: 128 (broad assumption for international/emojis)
    
    Args:
        password (str): The password to analyze.
        
    Returns:
        tuple: (entropy_value, entropy_level, description)
    """
    if not password:
        return 0.0, "None", "No password provided."
        
    length = len(password)
    
    # Identify active character sets
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    
    # Standard printable symbols/punctuation count is 33
    has_symbols = any(not c.isalnum() and ord(c) < 128 for c in password)
    has_unicode = any(ord(c) >= 128 for c in password)
    
    # Calculate Pool Size (R)
    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digits:
        pool_size += 10
    if has_symbols:
        pool_size += 33
    if has_unicode:
        pool_size += 128
        
    if pool_size == 0:
        pool_size = 1  # Base safety boundary
        
    # Apply entropy formula: H = L * log2(R)
    entropy = length * math.log2(pool_size)
    entropy_rounded = round(entropy, 2)
    
    # Categorize entropy based on NIST standards and industry norms
    if entropy_rounded < 28:
        level = "Very Weak"
        desc = "Extremely easy to crack. The password does not offer standard security. Immediate rotation advised."
    elif entropy_rounded < 36:
        level = "Weak"
        desc = "Low entropy. Vulnerable to simple dictionary and offline brute-force attacks."
    elif entropy_rounded < 60:
        level = "Moderate"
        desc = "Fair complexity. Safe from casual guessing, but vulnerable to high-speed dedicated password rigs."
    elif entropy_rounded < 80:
        level = "Strong"
        desc = "High complexity. Secure against standard brute-force, meeting standard enterprise policies."
    else:
        level = "Very Strong"
        desc = "Outstanding mathematical strength. Exceptionally difficult to crack even with advanced supercomputer clusters."
        
    return entropy_rounded, level, desc
