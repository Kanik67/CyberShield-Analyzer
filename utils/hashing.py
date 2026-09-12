# -*- coding: utf-8 -*-
"""
CyberShield - Cryptographic Hashing Module
Author: Senior Cybersecurity Engineer
Description: Generates MD5, SHA-1, SHA-256, and SHA-512 hashes of passwords,
explaining key concepts of collision resistance and cryptographic security.
"""

import hashlib

def generate_hashes(password: str) -> dict:
    """
    Generates standard cryptographic digests of the given password.
    
    Args:
        password (str): The password to hash.
        
    Returns:
        dict: A dictionary containing the hash hex digests and educational summaries.
    """
    if not password:
        return {}
        
    password_bytes = password.encode('utf-8')
    
    # Generate Hex Digests
    md5_hash = hashlib.md5(password_bytes).hexdigest()
    sha1_hash = hashlib.sha1(password_bytes).hexdigest()
    sha256_hash = hashlib.sha256(password_bytes).hexdigest()
    sha512_hash = hashlib.sha512(password_bytes).hexdigest()
    
    return {
        "md5": {
            "digest": md5_hash,
            "name": "MD5 (Message Digest 5)",
            "length": 128,  # bits
            "status": "LEGACY / BROKEN",
            "status_class": "text-rose-500",
            "desc": (
                "MD5 produces a 128-bit digest. It is highly vulnerable to collision attacks, "
                "where two different inputs produce the exact same hash. It was cryptographically "
                "broken in 2004 and should NEVER be used to store passwords."
            )
        },
        "sha1": {
            "digest": sha1_hash,
            "name": "SHA-1 (Secure Hash Algorithm 1)",
            "length": 160,  # bits
            "status": "DEPRECATED",
            "status_class": "text-amber-500",
            "desc": (
                "SHA-1 produces a 160-bit digest. It was designed by the NSA. Theoretical and "
                "practical collision attacks have been executed since 2017. Major browsers "
                "and security standards (like PCI-DSS) have deprecated SHA-1 for certificates and storage."
            )
        },
        "sha256": {
            "digest": sha256_hash,
            "name": "SHA-256 (Secure Hash Algorithm 2 - 256 bits)",
            "length": 256,  # bits
            "status": "SECURE",
            "status_class": "text-emerald-500",
            "desc": (
                "SHA-256 is part of the SHA-2 family. It outputs a 256-bit digest and remains "
                "highly secure and widely used in blockchains, SSL certificates, and digital signatures. "
                "Note: For secure server password storage, SHA-256 should be salted and stretched "
                "(e.g., using PBKDF2) or replaced by memory-hard algorithms like Argon2."
            )
        },
        "sha512": {
            "digest": sha512_hash,
            "name": "SHA-512 (Secure Hash Algorithm 2 - 512 bits)",
            "length": 512,  # bits
            "status": "SECURE",
            "status_class": "text-emerald-500",
            "desc": (
                "SHA-512 outputs a 512-bit digest. It is extremely robust and performs faster "
                "than SHA-256 on 64-bit architectures because it uses 64-bit arithmetic. It provides "
                "supreme security against standard brute-force, collision, and length-extension attacks."
            )
        }
    }
