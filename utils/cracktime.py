# -*- coding: utf-8 -*-
"""
CyberShield - Estimated Crack Time Module
Author: Senior Cybersecurity Engineer
Description: Estimates the time required to brute-force a password using modern cracking speeds.
It explains attacker capabilities and highlights the importance of slow hashing algorithms.
"""

import math

def format_crack_time(seconds: float) -> str:
    """
    Converts crack time in seconds to an educational human-readable string.
    """
    if seconds <= 0 or not math.isfinite(seconds):
        return "Instant" if seconds <= 0 else "> 1 Trillion Years"
        
    MINUTE = 60
    HOUR = 3600
    DAY = 86400
    MONTH = 2592000       # 30 days
    YEAR = 31536000       # 365 days
    CENTURY = 3153600000  # 100 years

    if seconds < 1:
        return "Instant"
    elif seconds < MINUTE:
        return f"{math.ceil(seconds)} Seconds"
    elif seconds < HOUR:
        return f"{math.ceil(seconds / MINUTE)} Minutes"
    elif seconds < DAY:
        return f"{math.ceil(seconds / HOUR)} Hours"
    elif seconds < MONTH:
        return f"{math.ceil(seconds / DAY)} Days"
    elif seconds < YEAR:
        return f"{math.ceil(seconds / MONTH)} Months"
    elif seconds < CENTURY:
        return f"{math.ceil(seconds / YEAR)} Years"
    elif seconds < (CENTURY * 100):
        return f"{math.ceil(seconds / CENTURY)} Centuries"
    elif seconds < (YEAR * 1e9):
        return f"{round(seconds / (YEAR * 1e6), 1)} Million Years"
    elif seconds < (YEAR * 1e12):
        return f"{round(seconds / (YEAR * 1e9), 1)} Billion Years"
    else:
        return "> 1 Trillion Years"

def calculate_scenarios(entropy: float) -> dict[str, str]:
    """
    Calculates crack times across 5 realistic attack scenarios.
    """
    if entropy <= 0:
        return {
            "online_throttled": "Instant",
            "online_fast": "Instant",
            "offline_gpu": "Instant",
            "offline_cluster": "Instant",
            "slow_hash": "Instant"
        }
    combinations = math.pow(2, entropy)
    return {
        "online_throttled": format_crack_time(combinations / 100),
        "online_fast": format_crack_time(combinations / 10000),
        "offline_gpu": format_crack_time(combinations / 1e11),
        "offline_cluster": format_crack_time(combinations / 1e13),
        "slow_hash": format_crack_time(combinations / 5000)
    }

def estimate_crack_time(entropy: float) -> tuple[str, str]:
    """
    Estimates the cracking time based on entropy.
    
    Using the Shannon entropy (H), the total possible combinations are 2^H.
    We assume a state-of-the-art consumer/enterprise cracking rig (e.g., multiple modern GPUs)
    running at 100,000,000,000 (10^11 or 100 Billion) guesses per second (such as Hashcat on fast hashes like MD5).
    
    Args:
        entropy (float): The calculated Shannon entropy value.
        
    Returns:
        tuple: (readable_time, explanation)
    """
    if entropy <= 0:
        return "Instant", "No password provided to analyze."
        
    # Total combinations
    combinations = math.pow(2, entropy)
    
    # Speed: 100 Billion guesses/second (1e11)
    guesses_per_second = 1e11
    
    # Total seconds required
    seconds = combinations / guesses_per_second
    
    # Define time constants in seconds
    MINUTE = 60
    HOUR = 3600
    DAY = 86400
    MONTH = 2592000       # 30 days
    YEAR = 31536000       # 365 days
    CENTURY = 3153600000  # 100 years
    
    # Generate human readable description
    if seconds < 1:
        readable = "Instant"
        explanation = (
            "An attacker with standard modern GPU cracking equipment (100 Billion guesses/sec) "
            "would crack this password instantaneously. This password is highly vulnerable."
        )
    elif seconds < MINUTE:
        readable = f"{math.ceil(seconds)} Seconds"
        explanation = (
            f"Would take roughly {math.ceil(seconds)} seconds to crack. "
            "Extremely vulnerable to online brute-forcing and automated dictionary tools."
        )
    elif seconds < HOUR:
        minutes = math.ceil(seconds / MINUTE)
        readable = f"{minutes} Minutes"
        explanation = (
            f"Would take approximately {minutes} minutes to crack. "
            "Easily cracked within a lunch break by a script-kiddie using standard tools."
        )
    elif seconds < DAY:
        hours = math.ceil(seconds / HOUR)
        readable = f"{hours} Hours"
        explanation = (
            f"Would take approximately {hours} hours to crack. "
            "Easily cracked overnight using a budget-friendly cloud compute instance."
        )
    elif seconds < MONTH:
        days = math.ceil(seconds / DAY)
        readable = f"{days} Days"
        explanation = (
            f"Would take approximately {days} days to crack. "
            "Vulnerable to moderate, targeted offline brute-forcing."
        )
    elif seconds < YEAR:
        months = math.ceil(seconds / MONTH)
        readable = f"{months} Months"
        explanation = (
            f"Would take approximately {months} months to crack. "
            "Provides basic short-term safety, but fails against dedicated, persistent adversaries."
        )
    elif seconds < CENTURY:
        years = math.ceil(seconds / YEAR)
        readable = f"{years} Years"
        explanation = (
            f"Would take approximately {years} years to crack. "
            "Reasonably safe from fast dictionary attacks, but still theoretically vulnerable within a lifetime."
        )
    elif seconds < (CENTURY * 1000):
        centuries = math.ceil(seconds / CENTURY)
        readable = f"{centuries} Centuries"
        explanation = (
            f"Would take approximately {centuries} centuries to crack. "
            "Highly secure against standard hardware setups. Meet top-tier academic complexity suggestions."
        )
    else:
        # Millions/Billions of Years
        millions = seconds / (YEAR * 1e6)
        if millions < 1000:
            readable = f"{round(millions, 1)} Million Years"
            explanation = (
                f"Would take around {round(millions, 1)} million years to crack. "
                "Mathematically impregnable against standard brute-force. Only side-channel attacks or leakages could expose it."
            )
        else:
            billions = millions / 1000
            readable = f"{round(billions, 1)} Billion Years"
            explanation = (
                f"Would take around {round(billions, 1)} billion years to crack. "
                "This password will outlive our Sun. The ultimate standard in cryptographic protection."
            )
            
    return readable, explanation
