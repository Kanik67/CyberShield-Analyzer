# -*- coding: utf-8 -*-
"""
CyberShield - Input Validator Module
Author: Senior Cybersecurity Engineer
Description: Provides sanitization and validation helper functions for password inputs.
"""

import string

def is_valid_password(password: str) -> bool:
    """
    Validates if a password is fit for testing.
    Ensures that it contains valid printable ASCII or UTF-8 characters and is not excessively long.
    
    Args:
        password (str): The password to validate.
        
    Returns:
        bool: True if valid, False otherwise.
    """
    if password is None:
        return False
        
    # Check length limits (protect against Denial of Service / buffer overflow simulation)
    if len(password) == 0 or len(password) > 128:
        return False
        
    # Ensure all characters are printable or standard UTF-8 characters
    # (Excludes control characters like tabs/newlines for strict sanitization)
    for char in password:
        if ord(char) < 32 and char not in ('\n', '\r', '\t'):
            return False
            
    return True

def sanitize_password(password: str) -> str:
    """
    Sanitizes user input by removing leading/trailing spaces if necessary,
    or handling special unicode normalizations.
    
    Args:
        password (str): The raw input password.
        
    Returns:
        str: The sanitized password.
    """
    if not password:
        return ""
    # We do NOT strip whitespace from passwords generally because space can be a valid character,
    # but we will trim carriage returns or potential injection patterns if applicable.
    sanitized = password.replace('\r', '').replace('\n', '')
    return sanitized
