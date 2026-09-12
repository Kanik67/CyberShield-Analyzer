# CyberShield – Password Security Intelligence Engine

An advanced, production-quality offline password complexity analyzer, Shannon entropy evaluator, high-speed brute-force estimator, and secure key generator designed to assess and educate users on the mechanics of credential defense.

This repository is optimized as a **Professional Cybersecurity Portfolio Project** (ideal for college submissions, GitHub showcases, and academic reviews).

---

## 🛡️ Project Overview

In contemporary digital infrastructure, credential theft remains the leading initial access vector for security breaches. **CyberShield** is an architectural solution built from scratch to analyze, grade, and remediate password vulnerabilities. Unlike basic checkers that rely solely on simple length checks or regex matching, **CyberShield** conducts dynamic sequence mining, keyboard pattern identification, dictionary audits against a database of known leaked keys, and calculates Shannon information entropy.

By breaking down passwords into concrete mathematical metrics, CyberShield offers an educational platform that explains *why* a password is weak and *how* to transform it into enterprise-grade cryptographic protection.

---

## 🚀 Key Features

### 1. Password Strength Diagnostics
* **Advanced Scoring Algorithm:** Custom-weighted scoring mechanism (scaled 0-100) assessing length, case variation, numbers, and symbols.
* **Dictionary Matching:** Real-time lookup against common leaked credentials (`common_passwords.txt`).
* **Heuristic Pattern Miners:** Detects repeated strings (e.g., `aaaa`), consecutive sequences (e.g., `123456`, `abcdef`), and physical QWERTY keyboard walks (e.g., `qwer`, `asdf`).
* **Real-time Evaluation:** Reactive typing feed that updates metrics, circular progress ring, and alerts without requiring full page reloads.

### 2. Shannon Entropy Calculator
* Evaluates unpredictability using standard information theory formulas:
  $$H = L \times \log_2(R)$$
  Where $L$ is length and $R$ is character set pool size.
* Categorizes complexity (Very Weak, Weak, Moderate, Strong, Very Strong) based on NIST standards.

### 3. Brute-Force Crack Estimator
* Simulates attacker capabilities based on an enterprise GPU rig running Hashcat on fast hashes (e.g., MD5) at **100 Billion guesses/second ($10^{11}$ H/s)**.
* Converts combinations to descriptive time periods ranging from **Instantaneous** to **Billion Years (outliving our Sun)**.
* Educates students on why slow hashing parameters (such as Argon2id or bcrypt) are used to stall brute-force operations.

### 4. Cryptographic Hash Generator
* Produces hex digests in four cryptographic standards: **MD5, SHA-1, SHA-256, and SHA-512**.
* Compares algorithms, providing definitions of **collision resistance,deprecation timelines, and blockchain application standards**.

### 5. Cryptographically Secure Key Generator
* Uses the **Python `secrets` module** (backed by OS cryptographically strong pseudorandom number generators) to compile random keys.
* Enables adjustable lengths (8 to 64 chars) with selective charsets.
* Includes single-click copy-to-clipboard clipboard indicators.

---

## 🛠️ Technology Stack

### Dual-Platform Support
To ensure seamless deployment in cloud containers and local student environments, the repository features a dual-run capability. It runs on **Python/Flask** natively, and is configured to run on **Node.js/Express** inside serverless containers:

#### Backend Option A (Python/Flask - Academic Submission)
* **Python 3.10+ / 3.13+**
* **Flask 3.1.0** (Routing & Jinja2 Template Injection)
* Built-in modules: `re`, `math`, `hashlib`, `secrets`, `string`, `os`, `pathlib`

#### Backend Option B (Node.js/Express - Production Cloud Containers)
* **Express & TypeScript** (Fast server-side routing & AJAX endpoints)
* Custom Jinja2 template translation parsing compiler
* Cryptographic entropy and hashing powered by Node `crypto` module

#### Frontend & UI
* **HTML5 & Custom CSS3 Variables** (Zero external CSS dependencies like Bootstrap or Tailwind)
* **Glassmorphic Cyber-Minimalist Theme** (Neon green/blue status glow, active grid system)
* **Vanilla JavaScript ES6** (Debounced fetch telemetry, dynamic circular SVG gauges, clipboard controllers)

---

## 📁 Repository Folder Structure

```text
CyberShield/
├── app.py                      # Core Python Flask server entry point
├── server.ts                   # Core Express/Node server (for container hosting)
├── requirements.txt            # Python dependencies (Flask)
├── package.json                # Node/Vite development configuration scripts
├── README.md                   # Technical project portfolio documentation
├── LICENSE                     # MIT open-source licensing agreement
├── .gitignore                  # Exclusion file for compiled caches and logs
├── common_passwords.txt        # Local database database of leaked passwords
│
├── templates/                  # Shared HTML5 templates (Jinja & Express compatible)
│   ├── index.html              # Security central dashboard (Real-time and controls)
│   └── result.html             # Detailed cryptographic audit report sheet
│
├── static/                     # Global static assets served by Flask/Express
│   ├── css/
│   │   └── style.css           # Premium cyber-inspired glassmorphic style
│   └── js/
│       └── script.js           # Real-time event listeners, AJAX, and animations
│
└── utils/                      # Modular Python standard library functions
    ├── __init__.py             # Defines directory as Python package
    ├── checker.py              # Primary complexity & QWERTY walk score rules
    ├── entropy.py              # Shannon log2 character set math
    ├── cracktime.py            # Combinatorics attack speed converter
    ├── hashing.py              # Cryptographic hex digests creator
    ├── generator.py            # secrets-based secure string builder
    └── validator.py            # Defensive safe-length safe-character check
```

---

## ⚙️ Installation & Launch Guide

### Method A: Local Python Flask (Recommended for Cybersecurity Students)

1. **Clone and Navigate into the Project:**
   ```bash
   git clone https://github.com/yourusername/CyberShield.git
   cd CyberShield
   ```

2. **Establish a Virtual Environment:**
   * **On Windows:**
     ```bash
     python -m venv venv
     venv\Scripts\activate
     ```
   * **On macOS/Linux:**
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Install Core Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Boot the Defensive Core:**
   ```bash
   python app.py
   ```

5. **Interact:**
   Open your browser of choice and go to: `http://127.0.0.1:5000`

---

### Method B: Production Node.js/Express (For Cloud Container Hosting)

1. **Install JavaScript packages:**
   ```bash
   npm install
   ```

2. **Run in Development mode:**
   ```bash
   npm run dev
   ```

3. **Interact:**
   Open your browser and navigate to: `http://localhost:3000`

---

## 🎯 Educational Value & Learning Outcomes

This project has been deliberately built to demonstrate core concepts of cybersecurity engineering:
1. **Information Theory:** Practical application of Shannon's Entropy, explaining search space metrics.
2. **Defensive Programming:** Strict sanitization, bounding input limits (128-char limit to prevent memory-hard CPU exhaustion), and sanitizing control characters.
3. **Cryptographic Standards:** Illustrates the life cycle of hash functions, highlighting collision weaknesses of MD5 and SHA-1 and the modern relevance of SHA-2.
4. **Brute-Force Mechanics:** Outlines how attackers speed up attempts by precomputing dictionaries and running parallelized GPU attacks.
5. **Architectural Separation:** Shows clean separation of data (common passwords), business calculations (utils), and visualization layers (HTML/CSS).

---

## 🔮 Future Enhancements
* **Have I Been Pwned API:** Live integration with HaveIBeenPwned REST endpoints (using k-Anonymity sha-1 hashing ranges) to check database status online.
* **Slow Hashing Simulator:** Interactive Argon2id / bcrypt sliders allowing users to change memory cost, time cost, and threads to see how computing overhead delays attackers.
* **Graphical Logs:** Integrated SVG chart displaying entropy curves compared to password length.

---

## 📝 License

Distributed under the **MIT License**. See `LICENSE` for details. This codebase is free for academic citation, fork customization, and college showcase.
#   C y b e r S h i e l d - A n a l y z e r  
 