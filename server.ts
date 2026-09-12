import express from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static assets out of the static/ directory
app.use('/static', express.static(path.join(process.cwd(), 'static')));

// --- Static Common Passwords Loader ---
const commonPasswords = new Set<string>();
try {
  const filePath = path.join(process.cwd(), 'common_passwords.txt');
  if (fs.existsSync(filePath)) {
    const content = fs.readFileSync(filePath, 'utf-8');
    content.split(/\r?\n/).forEach(line => {
      const cleaned = line.trim().toLowerCase();
      if (cleaned) {
        commonPasswords.add(cleaned);
      }
    });
    console.log(`[CyberShield System] Loaded ${commonPasswords.size} common passwords.`);
  }
} catch (error) {
  console.warn("Failed to load common_passwords.txt, applying default fallback lists:", error);
  ['123456', '123456789', 'password', 'qwerty', 'admin', 'welcome', 'letmein'].forEach(p => commonPasswords.add(p));
}

// --- Micro Jinja Template Renderer in Node.js ---
function renderTemplate(filePath: string, context: Record<string, any>): string {
  let html = fs.readFileSync(filePath, 'utf-8');
  
  // 1. Standard substitutions: {{ variable }} or {{ metrics.property }}
  html = html.replace(/\{\{\s*([a-zA-Z0-9_\.]+)\s*\}\}/g, (_, expression) => {
    const parts = expression.split('.');
    let val = context;
    for (const part of parts) {
      val = val ? val[part] : undefined;
    }
    return val !== undefined ? String(val) : '';
  });

  // 2. Conditionally process block elements: {% if error %} ... {% endif %}
  html = html.replace(/\{%\s*if\s+([a-zA-Z0-9_]+)\s*%\}([\s\S]*?)\{%\s*endif\s*%\}/g, (_, condition, block) => {
    const hasCondition = !!context[condition];
    return hasCondition ? block : '';
  });

  // 3. Process {% if warnings %} ... {% else %} ... {% endif %}
  html = html.replace(/\{%\s*if\s+([a-zA-Z0-9_]+)\s*%\}([\s\S]*?)\{%\s*else\s*%\}([\s\S]*?)\{%\s*endif\s*%\}/g, (_, condition, trueBlock, falseBlock) => {
    const value = context[condition];
    const isTrue = Array.isArray(value) ? value.length > 0 : !!value;
    return isTrue ? trueBlock : falseBlock;
  });

  // 4. Loop lists: {% for warning in warnings %} ... {% endfor %}
  html = html.replace(/\{%\s*for\s+([a-zA-Z0-9_]+)\s+in\s+([a-zA-Z0-9_]+)\s*%\}([\s\S]*?)\{%\s*endfor\s*%\}/g, (_, itemVar, listVar, block) => {
    const list = context[listVar];
    if (!Array.isArray(list)) return '';
    return list.map(item => {
      return block.replace(new RegExp(`\\{\\{\\s*${itemVar}\\s*\\}\\}`, 'g'), String(item));
    }).join('\n');
  });

  // 5. Dynamic looping for hashes: {% for key, hash in hashes.items() %} ... {% endfor %}
  html = html.replace(/\{%\s*for\s+([a-zA-Z0-9_]+)\s*,\s*([a-zA-Z0-9_]+)\s+in\s+hashes\.items\(\)\s*%\}([\s\S]*?)\{%\s*endfor\s*%\}/g, (_, keyVar, valueVar, block) => {
    const hashes = context.hashes || {};
    return Object.entries(hashes).map(([key, hashVal]: [string, any]) => {
      let substituted = block;
      substituted = substituted.replace(new RegExp(`\\{\\{\\s*${keyVar}\\s*\\}\\}`, 'g'), String(key));
      substituted = substituted.replace(new RegExp(`\\{\\{\\s*${keyVar}\\|upper\\s*\\}\\}`, 'g'), String(key).toUpperCase());
      substituted = substituted.replace(new RegExp(`\\{\\{\\s*${valueVar}\\.name\\s*\\}\\}`, 'g'), String(hashVal.name));
      substituted = substituted.replace(new RegExp(`\\{\\{\\s*${valueVar}\\.status\\s*\\}\\}`, 'g'), String(hashVal.status));
      substituted = substituted.replace(new RegExp(`\\{\\{\\s*${valueVar}\\.status_class\\s*\\}\\}`, 'g'), String(hashVal.status_class));
      substituted = substituted.replace(new RegExp(`\\{\\{\\s*${valueVar}\\.digest\\s*\\}\\}`, 'g'), String(hashVal.digest));
      substituted = substituted.replace(new RegExp(`\\{\\{\\s*${valueVar}\\.desc\\s*\\}\\}`, 'g'), String(hashVal.desc));
      return substituted;
    }).join('\n');
  });

  // 6. Inline calculations: {{ warnings|length }}
  html = html.replace(/\{\{\s*warnings\|length\s*\}\}/g, () => {
    const list = context.warnings;
    return Array.isArray(list) ? String(list.length) : '0';
  });

  return html;
}

// --- Pattern Matching & Evaluation Logic (Shared with Python) ---

function isPrintableAscii(password: string): boolean {
  for (let i = 0; i < password.length; i++) {
    const code = password.charCodeAt(i);
    // Allow standard space (32) up to tilde (126) or tabs/newlines
    if (code < 32 && code !== 10 && code !== 13 && code !== 9) {
      return false;
    }
  }
  return true;
}

function detectSequential(p: string): boolean {
  p = p.toLowerCase();
  for (let i = 0; i < p.length - 2; i++) {
    const char1 = p[i];
    const char2 = p[i+1];
    const char3 = p[i+2];
    
    // Digit sequence
    if (/\d/.test(char1) && /\d/.test(char2) && /\d/.test(char3)) {
      const v1 = parseInt(char1, 10);
      const v2 = parseInt(char2, 10);
      const v3 = parseInt(char3, 10);
      if ((v2 === v1 + 1 && v3 === v2 + 1) || (v2 === v1 - 1 && v3 === v2 - 1)) {
        return true;
      }
    }
    
    // Alpha sequence
    if (/[a-z]/.test(char1) && /[a-z]/.test(char2) && /[a-z]/.test(char3)) {
      const o1 = char1.charCodeAt(0);
      const o2 = char2.charCodeAt(0);
      const o3 = char3.charCodeAt(0);
      if ((o2 === o1 + 1 && o3 === o2 + 1) || (o2 === o1 - 1 && o3 === o2 - 1)) {
        return true;
      }
    }
  }
  return false;
}

function detectRepeated(p: string): boolean {
  return /(.)\1\1/.test(p) || /(.{2,4})\1/.test(p);
}

function detectKeyboardPatterns(p: string): boolean {
  p = p.toLowerCase();
  const qwertyRows = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890"
  ];
  for (const row of qwertyRows) {
    for (let i = 0; i < row.length - 3; i++) {
      const sub = row.slice(i, i + 4);
      const revSub = sub.split('').reverse().join('');
      if (p.includes(sub) || p.includes(revSub)) {
        return true;
      }
    }
  }
  return false;
}

function detectDatesAndPatterns(p: string): boolean {
  // Calendar years: 1950 - 2039
  if (/(?:19[5-9]\d|20[0-3]\d)/.test(p)) return true;
  // Date patterns: MMDD or DDMM like 0112, 1225
  if (/(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])/.test(p)) return true;
  return detectKeyboardPatterns(p);
}

function formatCrackTime(seconds: number): string {
  if (seconds <= 0 || !isFinite(seconds)) {
    return seconds <= 0 ? "Instant" : "> 1 Trillion Years";
  }
  const MINUTE = 60;
  const HOUR = 3600;
  const DAY = 86400;
  const MONTH = 2592000;
  const YEAR = 31536000;
  const CENTURY = 3153600000;

  if (seconds < 1) return "Instant";
  if (seconds < MINUTE) return `${Math.ceil(seconds)} Seconds`;
  if (seconds < HOUR) return `${Math.ceil(seconds / MINUTE)} Minutes`;
  if (seconds < DAY) return `${Math.ceil(seconds / HOUR)} Hours`;
  if (seconds < MONTH) return `${Math.ceil(seconds / DAY)} Days`;
  if (seconds < YEAR) return `${Math.ceil(seconds / MONTH)} Months`;
  if (seconds < CENTURY) return `${Math.ceil(seconds / YEAR)} Years`;
  if (seconds < CENTURY * 100) return `${Math.ceil(seconds / CENTURY)} Centuries`;
  if (seconds < YEAR * 1e9) return `${(seconds / (YEAR * 1e6)).toFixed(1)} Million Years`;
  if (seconds < YEAR * 1e12) return `${(seconds / (YEAR * 1e9)).toFixed(1)} Billion Years`;
  return "> 1 Trillion Years";
}

function calculateScenarios(entropy: number): Record<string, string> {
  if (entropy <= 0) {
    return {
      online_throttled: "Instant",
      online_fast: "Instant",
      offline_gpu: "Instant",
      offline_cluster: "Instant",
      slow_hash: "Instant"
    };
  }
  const combinations = Math.pow(2, entropy);
  return {
    online_throttled: formatCrackTime(combinations / 100),
    online_fast: formatCrackTime(combinations / 10000),
    offline_gpu: formatCrackTime(combinations / 1e11),
    offline_cluster: formatCrackTime(combinations / 1e13),
    slow_hash: formatCrackTime(combinations / 5000)
  };
}

function calculateEntropy(password: string): { entropy: number; level: string; desc: string } {
  if (!password) {
    return { entropy: 0.0, level: 'None', desc: 'No password provided.' };
  }
  const length = password.length;
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigits = /\d/.test(password);
  const hasSymbols = /[^a-zA-Z0-9]/.test(password);
  const hasUnicode = [...password].some(c => c.charCodeAt(0) >= 128);

  let poolSize = 0;
  if (hasLower) poolSize += 26;
  if (hasUpper) poolSize += 26;
  if (hasDigits) poolSize += 10;
  if (hasSymbols) poolSize += 33;
  if (hasUnicode) poolSize += 128;

  if (poolSize === 0) poolSize = 1;

  const entropy = Number((length * Math.log2(poolSize)).toFixed(2));
  
  let level = "Very Weak";
  let desc = "Extremely easy to crack. The password does not offer standard security. Immediate rotation advised.";

  if (entropy >= 80) {
    level = "Very Strong";
    desc = "Outstanding mathematical strength. Exceptionally difficult to crack even with advanced supercomputer clusters.";
  } else if (entropy >= 60) {
    level = "Strong";
    desc = "High complexity. Secure against standard brute-force, meeting standard enterprise policies.";
  } else if (entropy >= 40) {
    level = "Fair";
    desc = "Moderate complexity. Safe from casual guessing, but vulnerable to high-speed dedicated password rigs.";
  } else if (entropy >= 25) {
    level = "Weak";
    desc = "Low entropy. Vulnerable to simple dictionary and offline brute-force attacks.";
  }

  return { entropy, level, desc };
}

function estimateCrackTime(entropy: number): { readable: string; explanation: string } {
  if (entropy <= 0) {
    return { readable: 'Instant', explanation: 'No password provided to analyze.' };
  }
  
  const combinations = Math.pow(2, entropy);
  const guessesPerSecond = 1e11; // 100 Billion
  const seconds = combinations / guessesPerSecond;

  const readable = formatCrackTime(seconds);
  let explanation = `An attacker with high-speed GPU equipment (100 Billion guesses/sec) would take approximately ${readable} to crack this password.`;
  if (seconds < 1) {
    explanation = "An attacker with standard modern GPU cracking equipment (100 Billion guesses/sec) would crack this password instantaneously. This password is critically vulnerable.";
  } else if (seconds >= 3153600000) {
    explanation = `Would take around ${readable} to crack under 100 Billion guesses/sec. Exceptionally robust mathematical defense.`;
  }

  return { readable, explanation };
}

function generateHashes(password: string): Record<string, any> {
  const md5 = crypto.createHash('md5').update(password).digest('hex');
  const sha1 = crypto.createHash('sha1').update(password).digest('hex');
  const sha256 = crypto.createHash('sha256').update(password).digest('hex');
  const sha512 = crypto.createHash('sha512').update(password).digest('hex');

  return {
    md5: {
      digest: md5,
      name: "MD5 (Message Digest 5)",
      length: 128,
      status: "LEGACY / BROKEN",
      status_class: "text-rose-500",
      desc: "MD5 produces a 128-bit digest. It is highly vulnerable to collision attacks, where two different inputs produce the exact same hash. It was cryptographically broken in 2004 and should NEVER be used to store passwords."
    },
    sha1: {
      digest: sha1,
      name: "SHA-1 (Secure Hash Algorithm 1)",
      length: 160,
      status: "DEPRECATED",
      status_class: "text-amber-500",
      desc: "SHA-1 produces a 160-bit digest. It was designed by the NSA. Theoretical and practical collision attacks have been executed since 2017. Major browsers and security standards (like PCI-DSS) have deprecated SHA-1 for certificates and storage."
    },
    sha256: {
      digest: sha256,
      name: "SHA-256 (Secure Hash Algorithm 2 - 256 bits)",
      length: 256,
      status: "SECURE",
      status_class: "text-emerald-500",
      desc: "SHA-256 is part of the SHA-2 family. It outputs a 256-bit digest and remains highly secure and widely used in blockchains, SSL certificates, and digital signatures. Note: For secure server password storage, SHA-256 should be salted and stretched (e.g., using PBKDF2) or replaced by memory-hard algorithms like Argon2."
    },
    sha512: {
      digest: sha512,
      name: "SHA-512 (Secure Hash Algorithm 2 - 512 bits)",
      length: 512,
      status: "SECURE",
      status_class: "text-emerald-500",
      desc: "SHA-512 outputs a 512-bit digest. It is extremely robust and performs faster than SHA-256 on 64-bit architectures because it uses 64-bit arithmetic. It provides supreme security against standard brute-force, collision, and length-extension attacks."
    }
  };
}

function checkPasswordStrength(password: string): Record<string, any> {
  const length = password.length;
  const upper_count = (password.match(/[A-Z]/g) || []).length;
  const lower_count = (password.match(/[a-z]/g) || []).length;
  const digits_count = (password.match(/\d/g) || []).length;
  const symbols_count = (password.match(/[^a-zA-Z0-9]/g) || []).length;
  const unique_count = new Set(password).size;
  const unique_ratio = length > 0 ? unique_count / length : 0;

  const hasLower = lower_count > 0;
  const hasUpper = upper_count > 0;
  const hasDigits = digits_count > 0;
  const hasSymbols = symbols_count > 0;

  const isCommon = commonPasswords.has(password.toLowerCase());
  const isSequential = detectSequential(password);
  const isRepeated = detectRepeated(password);
  const isDates = detectDatesAndPatterns(password);
  const isKeyboard = detectKeyboardPatterns(password);

  let score = 0;

  // Length points
  if (length <= 4) score += 5;
  else if (length <= 7) score += 15;
  else if (length <= 11) score += 30;
  else if (length <= 15) score += 45;
  else score += 55;

  // Composition points
  if (hasLower) score += 10;
  if (hasUpper) score += 10;
  if (hasDigits) score += 10;
  if (hasSymbols) score += 15;

  // Extra length & diversity bonus
  if (length >= 16) score += 10;
  if (unique_ratio >= 0.8 && length >= 8) score += 5;

  // Penalties
  let characterSetCount = 0;
  if (hasLower) characterSetCount++;
  if (hasUpper) characterSetCount++;
  if (hasDigits) characterSetCount++;
  if (hasSymbols) characterSetCount++;

  if (characterSetCount <= 1) score -= 20;
  if (isSequential) score -= 15;
  if (isRepeated) score -= 15;
  if (isDates) score -= 15;

  if (isCommon) score = 0;

  score = Math.max(0, Math.min(100, score));

  // 5 exact tiers: Very Weak, Weak, Fair, Strong, Very Strong
  let strength = "Very Weak";
  let badge_class = "bg-rose-500/10 text-rose-400 border border-rose-500/20";
  let color_class = "text-rose-400";
  let progress_class = "bg-rose-500";
  let gauge_color = "#f43f5e";

  if (score >= 80) {
    strength = "Very Strong";
    badge_class = "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
    color_class = "text-emerald-400";
    progress_class = "bg-emerald-400";
    gauge_color = "#10b981";
  } else if (score >= 60) {
    strength = "Strong";
    badge_class = "bg-sky-500/10 text-sky-400 border border-sky-500/20";
    color_class = "text-sky-400";
    progress_class = "bg-sky-400";
    gauge_color = "#0ea5e9";
  } else if (score >= 40) {
    strength = "Fair";
    badge_class = "bg-amber-500/10 text-amber-400 border border-amber-500/20";
    color_class = "text-amber-400";
    progress_class = "bg-amber-400";
    gauge_color = "#f59e0b";
  } else if (score >= 20) {
    strength = "Weak";
    badge_class = "bg-orange-500/10 text-orange-400 border border-orange-500/20";
    color_class = "text-orange-400";
    progress_class = "bg-orange-400";
    gauge_color = "#f97316";
  }

  const warnings: string[] = [];
  const suggestions: string[] = [];

  // Security Analysis Checks
  const checks = {
    length: {
      status: length >= 12 ? 'PASS' : (length >= 8 ? 'WARNING' : 'CRITICAL'),
      badge_class: length >= 12 ? 'badge-pass' : (length >= 8 ? 'badge-warning' : 'badge-danger'),
      card_class: length >= 12 ? 'pass' : (length >= 8 ? 'warning' : 'danger'),
      message: length >= 12 
        ? `${length} characters meets standard enterprise 12+ length policy.` 
        : (length >= 8 
            ? `Sub-optimal length (${length} characters). 12–16+ characters strongly recommended.`
            : `Critically short (${length} characters). Under 8 characters can be brute-forced in seconds.`)
    },
    repeated: {
      status: isRepeated ? 'WARNING' : 'PASS',
      badge_class: isRepeated ? 'badge-warning' : 'badge-pass',
      card_class: isRepeated ? 'warning' : 'pass',
      message: isRepeated 
        ? "Repeating characters or patterns detected. Repetition dramatically narrows search entropy."
        : "No excessive repeating characters or predictable identical runs detected."
    },
    sequential: {
      status: isSequential ? 'WARNING' : 'PASS',
      badge_class: isSequential ? 'badge-warning' : 'badge-pass',
      card_class: isSequential ? 'warning' : 'pass',
      message: isSequential
        ? "Sequential pattern detected (e.g., '123', 'abc'). Attackers optimize dictionary masks for sequences."
        : "No sequential alphabetical or numeric progressions found."
    },
    common: {
      status: isCommon ? 'DANGER' : 'PASS',
      badge_class: isCommon ? 'badge-danger' : 'badge-pass',
      card_class: isCommon ? 'danger' : 'pass',
      message: isCommon
        ? "Known common password! Found in leaked credential breach databases."
        : "Not present in common password dictionaries or known leaked wordlists."
    },
    dates: {
      status: isDates ? 'WARNING' : 'PASS',
      badge_class: isDates ? 'badge-warning' : 'badge-pass',
      card_class: isDates ? 'warning' : 'pass',
      message: isDates
        ? "Contains calendar year (1950–2039), date pattern, or keyboard walk ('qwerty', 'asdf')."
        : "No obvious calendar dates, birth years, or linear keyboard walks identified."
    },
    diversity: {
      status: (unique_count < 6 || (length > 6 && unique_ratio < 0.55)) ? 'WARNING' : 'PASS',
      badge_class: (unique_count < 6 || (length > 6 && unique_ratio < 0.55)) ? 'badge-warning' : 'badge-pass',
      card_class: (unique_count < 6 || (length > 6 && unique_ratio < 0.55)) ? 'warning' : 'pass',
      message: (unique_count < 6 || (length > 6 && unique_ratio < 0.55))
        ? `Low character diversity (${unique_count} unique chars). Higher variety improves resilience.`
        : `High character diversity: ${unique_count} unique symbols (${(unique_ratio * 100).toFixed(0)}% diversity).`
    }
  };

  if (isCommon) {
    warnings.push("CRITICAL: This password is on the list of most common insecure passwords!");
    suggestions.push("Change this password immediately. Avoid words that appear in dictionary files or common lists.");
  }

  if (length < 8) {
    warnings.push("Dangerous Length: Passwords under 8 characters are extremely easy to brute-force.");
    suggestions.push("Increase password length to at least 12-16 characters. Every single added character increases strength exponentially.");
  } else if (length < 12) {
    warnings.push("Sub-optimal Length: Standard security policies require 12+ characters for reliable security.");
    suggestions.push("Aim for a length of 12 or 16+ characters to survive modern distributed GPU attacks.");
  }

  if (!hasUpper) {
    suggestions.push("Add uppercase letters (A-Z) to mix character casing and expand the entropy search pool.");
  }
  if (!hasLower) {
    suggestions.push("Add lowercase letters (a-z) to include standard lower alphabets.");
  }
  if (!hasDigits) {
    suggestions.push("Integrate numerical digits (0-9) to secure your password against pure alphabetical search rigs.");
  }
  if (!hasSymbols) {
    suggestions.push("Add special characters or symbols (e.g., @, #, $, %, !, *) to disrupt automated dictionary matches.");
  }

  if (isRepeated) {
    warnings.push("Pattern Detected: Repeated characters or repeating sequence groups found.");
    suggestions.push("Remove repeating groups which reduce pattern unpredictability.");
  }
  if (isSequential) {
    warnings.push("Pattern Detected: Sequential numbers/letters found (e.g., '123', 'abc').");
    suggestions.push("Avoid standard keyboard sequences or sequential progressions as attackers prioritize these.");
  }
  if (isDates) {
    warnings.push("Pattern Detected: Obvious date format, birth year, or keyboard walk found.");
    suggestions.push("Do not use calendar years or keyboard walks ('qwerty'). Use high-entropy random characters.");
  }

  if (score >= 80 && warnings.length === 0) {
    suggestions.push("Excellent key! Your password meets enterprise-grade cybersecurity standards.");
  }

  return {
    score,
    strength,
    badge_class,
    color_class,
    progress_class,
    gauge_color,
    warnings,
    suggestions,
    checks,
    metrics: {
      length,
      upper_count,
      lower_count,
      digits_count,
      symbols_count,
      unique_count,
      unique_ratio,
      has_lower: hasLower,
      has_upper: hasUpper,
      has_digits: hasDigits,
      has_symbols: hasSymbols,
      is_common: isCommon,
      is_sequential: isSequential,
      is_repeated: isRepeated,
      is_dates: isDates,
      is_keyboard: isKeyboard
    }
  };
}

function generateSecurePassword(
  length = 16,
  useUpper = true,
  useLower = true,
  useDigits = true,
  useSymbols = true,
  excludeSimilar = false,
  excludeAmbiguous = false
): string {
  if (!useUpper && !useLower && !useDigits && !useSymbols) {
    useLower = true;
    useUpper = true;
    useDigits = true;
  }

  let lowerChars = "abcdefghijklmnopqrstuvwxyz";
  let upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  let digitChars = "0123456789";
  let symbolChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";

  if (excludeSimilar) {
    const similarChars = "O0Il1";
    lowerChars = lowerChars.split('').filter(c => !similarChars.includes(c)).join('');
    upperChars = upperChars.split('').filter(c => !similarChars.includes(c)).join('');
    digitChars = digitChars.split('').filter(c => !similarChars.includes(c)).join('');
    symbolChars = symbolChars.split('').filter(c => !similarChars.includes(c)).join('');
  }

  if (excludeAmbiguous) {
    const ambiguousSymbols = "{}[]()/\\'\"~,;.<>|";
    symbolChars = symbolChars.split('').filter(c => !ambiguousSymbols.includes(c)).join('');
  }

  // Graceful empty set fallback
  if (useLower && !lowerChars) lowerChars = "abcdefghjkmnpqrstuvwxyz";
  if (useUpper && !upperChars) upperChars = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  if (useDigits && !digitChars) digitChars = "23456789";
  if (useSymbols && !symbolChars) symbolChars = "!@#$%^&*_+-=?";

  const maxAttempts = 100;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    let pool = "";
    const guaranteed: string[] = [];

    if (useLower && lowerChars) {
      pool += lowerChars;
      guaranteed.push(lowerChars[crypto.randomInt(lowerChars.length)]);
    }
    if (useUpper && upperChars) {
      pool += upperChars;
      guaranteed.push(upperChars[crypto.randomInt(upperChars.length)]);
    }
    if (useDigits && digitChars) {
      pool += digitChars;
      guaranteed.push(digitChars[crypto.randomInt(digitChars.length)]);
    }
    if (useSymbols && symbolChars) {
      pool += symbolChars;
      guaranteed.push(symbolChars[crypto.randomInt(symbolChars.length)]);
    }

    const remainingCount = length - guaranteed.length;
    for (let i = 0; i < remainingCount; i++) {
      guaranteed.push(pool[crypto.randomInt(pool.length)]);
    }

    // Shuffle the guaranteed array
    for (let i = guaranteed.length - 1; i > 0; i--) {
      const j = crypto.randomInt(i + 1);
      const temp = guaranteed[i];
      guaranteed[i] = guaranteed[j];
      guaranteed[j] = temp;
    }

    const candidate = guaranteed.slice(0, length).join('');

    if (length >= 12) {
      if (detectRepeated(candidate)) continue;
      if (detectSequential(candidate)) continue;
      if (detectKeyboardPatterns(candidate)) continue;

      if (useDigits && useLower && useUpper) {
        const lowCount = [...candidate].filter(c => lowerChars.includes(c)).length;
        const upCount = [...candidate].filter(c => upperChars.includes(c)).length;
        const digCount = [...candidate].filter(c => digitChars.includes(c)).length;
        const threshold = Math.floor(length * 0.75);
        if (lowCount > threshold || upCount > threshold || digCount > threshold) {
          continue;
        }
      }
    }

    return candidate;
  }

  // Absolute fallback
  let fallbackPool = "";
  if (useLower) fallbackPool += lowerChars;
  if (useUpper) fallbackPool += upperChars;
  if (useDigits) fallbackPool += digitChars;
  if (useSymbols) fallbackPool += symbolChars;
  const fallbackArr: string[] = [];
  for (let i = 0; i < length; i++) {
    fallbackArr.push(fallbackPool[crypto.randomInt(fallbackPool.length)]);
  }
  return fallbackArr.join('');
}

// --- Express Endpoint Routes ---

// GET / -> Serves index.html compiled with default context
app.get('/', (req, res) => {
  const filePath = path.join(process.cwd(), 'templates', 'index.html');
  const rendered = renderTemplate(filePath, { error: null });
  res.send(rendered);
});

// POST /analyze -> Forms multi-page redirection audit sheet
app.post('/analyze', (req, res) => {
  const rawPassword = String(req.body.password || '');
  const password = rawPassword.replace(/\r?\n/g, ''); // Basic sanitization

  if (!password) {
    const indexPath = path.join(process.cwd(), 'templates', 'index.html');
    return res.send(renderTemplate(indexPath, { error: 'Please enter a password to analyze.' }));
  }

  if (password.length > 128 || !isPrintableAscii(password)) {
    const indexPath = path.join(process.cwd(), 'templates', 'index.html');
    return res.send(renderTemplate(indexPath, { error: 'Invalid character input or password exceeds safe limits (128 characters).' }));
  }

  // Run full evaluation sequence
  const strengthResult = checkPasswordStrength(password);
  const entropyResult = calculateEntropy(password);
  const crackTimeResult = estimateCrackTime(entropyResult.entropy);
  const scenarios = calculateScenarios(entropyResult.entropy);
  const hashes = generateHashes(password);

  const context = {
    password: password,
    report_id: strengthResult.score * 7 + 1042,
    score: strengthResult.score,
    strength: strengthResult.strength,
    badge_class: strengthResult.badge_class,
    color_class: strengthResult.color_class,
    progress_class: strengthResult.progress_class,
    gauge_color: strengthResult.gauge_color,
    warnings: strengthResult.warnings,
    suggestions: strengthResult.suggestions,
    checks: strengthResult.checks,
    scenarios: scenarios,
    metrics: strengthResult.metrics,
    entropy: entropyResult.entropy,
    entropy_level: entropyResult.level,
    entropy_desc: entropyResult.desc,
    crack_time: crackTimeResult.readable,
    crack_desc: crackTimeResult.explanation,
    hashes: hashes,
    error: null
  };

  const resultPath = path.join(process.cwd(), 'templates', 'result.html');
  const rendered = renderTemplate(resultPath, context);
  res.send(rendered);
});

// POST /api/analyze -> Real-time typing analysis JSON feed
app.post('/api/analyze', (req, res) => {
  const rawPassword = String(req.body.password || '');
  const password = rawPassword.replace(/\r?\n/g, '');

  if (!password) {
    return res.status(400).json({ error: 'Password field is empty.' });
  }

  if (password.length > 128 || !isPrintableAscii(password)) {
    return res.status(400).json({ error: 'Invalid character format or password exceeds maximum length limits.' });
  }

  const strengthResult = checkPasswordStrength(password);
  const entropyResult = calculateEntropy(password);
  const crackTimeResult = estimateCrackTime(entropyResult.entropy);
  const scenarios = calculateScenarios(entropyResult.entropy);
  const hashes = generateHashes(password);

  res.json({
    password: password,
    score: strengthResult.score,
    strength: strengthResult.strength,
    badge_class: strengthResult.badge_class,
    color_class: strengthResult.color_class,
    progress_class: strengthResult.progress_class,
    gauge_color: strengthResult.gauge_color,
    warnings: strengthResult.warnings,
    suggestions: strengthResult.suggestions,
    checks: strengthResult.checks,
    scenarios: scenarios,
    metrics: strengthResult.metrics,
    entropy: entropyResult.entropy,
    entropy_level: entropyResult.level,
    entropy_desc: entropyResult.desc,
    crack_time: crackTimeResult.readable,
    crack_desc: crackTimeResult.explanation,
    hashes: hashes
  });
});

// POST /api/generate -> Secure Key Generator AJAX JSON feed
app.post('/api/generate', (req, res) => {
  let length = parseInt(req.body.length, 10);
  if (isNaN(length) || length < 8 || length > 64) {
    length = 16;
  }

  const upper = req.body.upper !== false;
  const lower = req.body.lower !== false;
  const digits = req.body.digits !== false;
  const symbols = req.body.symbols !== false;
  const excludeSimilar = req.body.excludeSimilar === true || req.body.exclude_similar === true;
  const excludeAmbiguous = req.body.excludeAmbiguous === true || req.body.exclude_ambiguous === true;

  const pwd = generateSecurePassword(length, upper, lower, digits, symbols, excludeSimilar, excludeAmbiguous);
  const strengthResult = checkPasswordStrength(pwd);
  const entropyResult = calculateEntropy(pwd);
  const crackTimeResult = estimateCrackTime(entropyResult.entropy);

  res.json({
    password: pwd,
    length: pwd.length,
    strength: strengthResult.strength,
    score: strengthResult.score,
    crack_time: crackTimeResult.readable,
    crack_desc: crackTimeResult.explanation,
    entropy: entropyResult.entropy,
    entropy_level: entropyResult.level,
    entropy_desc: entropyResult.desc,
    gauge_color: strengthResult.gauge_color,
    badge_class: strengthResult.badge_class,
    warnings: strengthResult.warnings,
    suggestions: strengthResult.suggestions,
    metrics: strengthResult.metrics
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[CyberShield Core] Express server running on port ${PORT}`);
});
