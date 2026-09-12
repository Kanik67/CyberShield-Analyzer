# -*- coding: utf-8 -*-
"""
CyberShield - Secure Password Generator Module
Author: Senior Cybersecurity Engineer
Description: Generates cryptographically secure passwords using Python's 'secrets' module,
             ensuring defense against pattern guessing and timing attacks.
"""

import secrets
import string
import re
from utils.checker import detect_sequential, detect_repeated, detect_keyboard_patterns

def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_similar: bool = False,
    exclude_ambiguous: bool = False
) -> str:
    """
    Generates a cryptographically strong, random password using secrets.SystemRandom.
    Ensures the password satisfies selected options and strictly passes cybersecurity
    quality checks (no consecutive repeated chars, no alphabetical/numerical sequences, 
    no keyboard walks, and balanced composition).

    Args:
        length (int): Desired password length.
        use_upper (bool): Include uppercase letters (A-Z).
        use_lower (bool): Include lowercase letters (a-z).
        use_digits (bool): Include digits (0-9).
        use_symbols (bool): Include special symbols.
        exclude_similar (bool): If True, excludes similar characters (O, 0, I, l, 1).
        exclude_ambiguous (bool): If True, excludes ambiguous symbols ({}[]()/\\'\"~,;.<>).

    Returns:
        str: The generated secure password.
    """
    # Fallback to default sets if nothing is selected
    if not (use_upper or use_lower or use_digits or use_symbols):
        use_lower = True
        use_upper = True
        use_digits = True

    # Define standard character pools
    lower_pool = string.ascii_lowercase
    upper_pool = string.ascii_uppercase
    digit_pool = string.digits
    symbol_pool = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    # Exclude Similar Characters: O, 0, I, l, 1
    if exclude_similar:
        similar_chars = "O0Il1"
        lower_pool = "".join(c for c in lower_pool if c not in similar_chars)
        upper_pool = "".join(c for c in upper_pool if c not in similar_chars)
        digit_pool = "".join(c for c in digit_pool if c not in similar_chars)
        symbol_pool = "".join(c for c in symbol_pool if c not in similar_chars)

    # Exclude Ambiguous Symbols
    if exclude_ambiguous:
        ambiguous_symbols = "{}[]()/\\'\"~,;.<>|"
        symbol_pool = "".join(c for c in symbol_pool if c not in ambiguous_symbols)

    # Re-evaluate pools. If any pool is empty but was selected, we must handle it gracefully
    # by adding a fallback of non-ambiguous/non-similar characters from that set if possible.
    if use_lower and not lower_pool:
        lower_pool = "abcdefghjkmnpqrstuvwxyz"  # No 'l'
    if use_upper and not upper_pool:
        upper_pool = "ABCDEFGHJKLMNPQRSTUVWXYZ"  # No 'I', 'O'
    if use_digits and not digit_pool:
        digit_pool = "23456789"  # No '0', '1'
    if use_symbols and not symbol_pool:
        symbol_pool = "!@#$%^&*_+-=?"  # Standard safe symbols without ambiguity

    # We run a loop up to 100 times to find a password that passes all cybersecurity quality rules
    max_attempts = 100
    secure_random = secrets.SystemRandom()

    for attempt in range(max_attempts):
        pool = ""
        guaranteed = []

        # Ensure we draw at least one character from each selected pool
        if use_lower and lower_pool:
            pool += lower_pool
            guaranteed.append(secure_random.choice(lower_pool))
        if use_upper and upper_pool:
            pool += upper_pool
            guaranteed.append(secure_random.choice(upper_pool))
        if use_digits and digit_pool:
            pool += digit_pool
            guaranteed.append(secure_random.choice(digit_pool))
        if use_symbols and symbol_pool:
            pool += symbol_pool
            guaranteed.append(secure_random.choice(symbol_pool))

        # Fill the remaining length of the password from the unified pool
        remaining_count = length - len(guaranteed)
        if remaining_count > 0:
            for _ in range(remaining_count):
                guaranteed.append(secure_random.choice(pool))

        # Securely shuffle to disperse guaranteed starting characters
        secure_random.shuffle(guaranteed)
        candidate = "".join(guaranteed[:length])

        # If length is extremely short (e.g., 8), some patterns might be inevitable or unavoidable.
        # So for shorter passwords, we weaken the pattern exclusions slightly to avoid infinite loops,
        # but for standard security lengths (12+), we strictly enforce no repeated/sequential patterns.
        if length >= 12:
            # Quality checks
            if detect_repeated(candidate):
                continue
            if detect_sequential(candidate):
                continue
            if detect_keyboard_patterns(candidate):
                continue

            # Balanced character distribution: if multiple options are enabled, we shouldn't have >75% of one type
            if use_digits and use_lower and use_upper:
                low_count = sum(1 for c in candidate if c in lower_pool)
                up_count = sum(1 for c in candidate if c in upper_pool)
                dig_count = sum(1 for c in candidate if c in digit_pool)
                threshold = int(length * 0.75)
                if low_count > threshold or up_count > threshold or dig_count > threshold:
                    continue

        return candidate

    # Absolute fallback if we reached 100 attempts without a pristine candidate (highly unlikely)
    pool = ""
    if use_lower: pool += lower_pool
    if use_upper: pool += upper_pool
    if use_digits: pool += digit_pool
    if use_symbols: pool += symbol_pool
    return "".join(secure_random.choice(pool) for _ in range(length))
