/**
 * CyberShield – Interactive Frontend Scripts
 * Author: Senior Cybersecurity Engineer & Full-Stack Web Developer
 * Description: Client-side logic for password strength evaluation, cryptography,
 *              interactive animations, secure API integrations, and event listening.
 *              Includes full client-side cryptographic engine fallbacks for offline usage.
 */

document.addEventListener('DOMContentLoaded', () => {
    
    // --- DOM Reference Selectors ---
    const passwordInput = document.getElementById('passwordInput');
    const toggleVisibility = document.getElementById('toggleVisibility');
    const eyeIcon = document.getElementById('eyeIcon');
    const eyeOffIcon = document.getElementById('eyeOffIcon');
    
    // Live Security Feed Selectors
    const liveDiagnostics = document.getElementById('liveDiagnostics');
    const liveGauge = document.getElementById('liveGauge');
    const liveScoreValue = document.getElementById('liveScoreValue');
    const liveStrengthLabel = document.getElementById('liveStrengthLabel');
    const liveEntropyValue = document.getElementById('liveEntropyValue');
    const liveCrackTimeValue = document.getElementById('liveCrackTimeValue');
    const liveLenCheck = document.getElementById('liveLenCheck');
    const liveAlerts = document.getElementById('liveAlerts');
    
    // Charset badge selectors
    const setLower = document.getElementById('setLower');
    const setUpper = document.getElementById('setUpper');
    const setDigits = document.getElementById('setDigits');
    const setSymbols = document.getElementById('setSymbols');
    
    // Live hashing card selectors
    const hashMD5 = document.getElementById('hashMD5');
    const hashSHA1 = document.getElementById('hashSHA1');
    const hashSHA256 = document.getElementById('hashSHA256');
    const hashSHA512 = document.getElementById('hashSHA512');
    
    // Generator Selectors
    const lengthSlider = document.getElementById('lengthSlider');
    const lengthDisplay = document.getElementById('lengthDisplay');
    const genUpper = document.getElementById('genUpper');
    const genLower = document.getElementById('genLower');
    const genDigits = document.getElementById('genDigits');
    const genSymbols = document.getElementById('genSymbols');
    const generateBtn = document.getElementById('generateBtn');
    const generatorOutput = document.getElementById('generatorOutput');
    const copyPasswordBtn = document.getElementById('copyPasswordBtn');
    const copyTooltip = document.getElementById('copyTooltip');
    
    // Loader Overlay Selector
    const loadingOverlay = document.getElementById('loadingOverlay');
    const analyzeSubmit = document.getElementById('analyzeSubmit');
    const analyzerForm = document.querySelector('.analyzer-form');

    // --- Hero Action Smooth Scroll ---
    const startAnalysisBtn = document.getElementById('startAnalysisBtn');
    if (startAnalysisBtn && passwordInput) {
        startAnalysisBtn.addEventListener('click', () => {
            const anchor = document.getElementById('analysisAnchor');
            if (anchor) {
                anchor.scrollIntoView({ behavior: 'smooth', block: 'start' });
            } else {
                passwordInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
            passwordInput.focus();
        });
    }

    // --- Mobile Nav Drawer Control ---
    const mobileMenuToggle = document.getElementById('mobileMenuToggle');
    const closeDrawerBtn = document.getElementById('closeDrawerBtn');
    const mobileNavDrawer = document.getElementById('mobileNavDrawer');

    function openDrawer() {
        if (mobileNavDrawer) mobileNavDrawer.classList.add('open');
    }
    function closeDrawer() {
        if (mobileNavDrawer) mobileNavDrawer.classList.remove('open');
    }

    if (mobileMenuToggle) mobileMenuToggle.addEventListener('click', openDrawer);
    if (closeDrawerBtn) closeDrawerBtn.addEventListener('click', closeDrawer);

    // --- About Modal Dialog Control ---
    const aboutBtn = document.getElementById('aboutBtn');
    const aboutBtnMobile = document.getElementById('aboutBtnMobile');
    const aboutModal = document.getElementById('aboutModal');
    const closeModalBtn = document.getElementById('closeModalBtn');
    const closeModalOk = document.getElementById('closeModalOk');

    function openModal() {
        if (aboutModal) aboutModal.classList.add('open');
    }
    function closeModal() {
        if (aboutModal) aboutModal.classList.remove('open');
    }

    if (aboutBtn) aboutBtn.addEventListener('click', openModal);
    if (aboutBtnMobile) aboutBtnMobile.addEventListener('click', () => {
        closeDrawer();
        openModal();
    });
    if (closeModalBtn) closeModalBtn.addEventListener('click', closeModal);
    if (closeModalOk) closeModalOk.addEventListener('click', closeModal);
    if (aboutModal) {
        aboutModal.addEventListener('click', (e) => {
            if (e.target === aboutModal) closeModal();
        });
    }

    // --- Password Visibility Toggle Handler ---
    if (toggleVisibility && passwordInput) {
        let isVisible = false;
        toggleVisibility.addEventListener('click', () => {
            isVisible = !isVisible;
            if (isVisible) {
                passwordInput.type = 'text';
                eyeIcon.classList.add('hidden');
                eyeOffIcon.classList.remove('hidden');
            } else {
                passwordInput.type = 'password';
                eyeIcon.className = 'fa-solid fa-eye';
                eyeOffIcon.className = 'fa-solid fa-eye-slash hidden';
            }
        });
    }

    // --- Quick Strong Password Generation Handler ---
    const quickGenerateBtn = document.getElementById('quickGenerateBtn');
    if (quickGenerateBtn && passwordInput) {
        quickGenerateBtn.addEventListener('click', () => {
            const strongPass = localGenerateSecurePassword(16, true, true, true, true, false, false);
            passwordInput.value = strongPass;
            passwordInput.type = 'text';
            if (eyeIcon && eyeOffIcon) {
                eyeIcon.classList.add('hidden');
                eyeOffIcon.classList.remove('hidden');
            }
            evaluatePasswordLive(strongPass);
        });
    }

    // --- Live Real-Time Password Analysis Engine ---
    let debounceTimer;
    if (passwordInput) {
        passwordInput.addEventListener('input', () => {
            const val = passwordInput.value;
            
            // Clear pending debounces
            clearTimeout(debounceTimer);
            
            if (!val) {
                // If input is empty, hide diagnostics feed
                if (liveDiagnostics) liveDiagnostics.classList.add('hidden');
                resetHashingCards();
                resetStrengthMeter();
                return;
            }
            
            // Set debounce (delay of 150ms to protect performance and avoid excessive API requests)
            debounceTimer = setTimeout(() => {
                evaluatePasswordLive(val);
            }, 150);
        });
    }

    // --- Smooth Score Number Animation Helper ---
    function animateScoreText(element, targetValue) {
        if (!element) return;
        const startValue = parseInt(element.innerText, 10) || 0;
        if (startValue === targetValue) {
            element.innerText = targetValue;
            return;
        }

        const duration = 400; // ms
        const startTime = performance.now();

        if (element.dataset.animationId) {
            cancelAnimationFrame(parseInt(element.dataset.animationId, 10));
        }

        function updateCount(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            // Easing function (easeOutQuad)
            const easeProgress = progress * (2 - progress);
            
            const currentValue = Math.floor(startValue + (targetValue - startValue) * easeProgress);
            element.innerText = currentValue;

            if (progress < 1) {
                const animId = requestAnimationFrame(updateCount);
                element.dataset.animationId = animId;
            } else {
                element.innerText = targetValue;
                delete element.dataset.animationId;
            }
        }
        const animId = requestAnimationFrame(updateCount);
        element.dataset.animationId = animId;
    }

    async function evaluatePasswordLive(password) {
        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password: password })
            });

            if (response.ok) {
                const data = await response.json();
                renderLiveDiagnostics(data);
                return;
            }
        } catch (error) {
            console.warn('Telemetry server offline. Initializing local client-side diagnostics sandbox fallback...');
        }

        // Offline Client-Side Diagnostic Fallback Engine
        const localData = await runLocalAnalysis(password);
        renderLiveDiagnostics(localData);
    }

    function renderLiveDiagnostics(data) {
        // Unhide Feed Panel
        if (liveDiagnostics) liveDiagnostics.classList.remove('hidden');
        
        // 1. Update Score and Circular Gauge Meter
        const score = data.score;
        if (liveScoreValue) {
            animateScoreText(liveScoreValue, score);
        }
        
        // Gauge perimeter logic: radius is 50, so perimeter is 2 * Math.PI * 50 = 314.16
        const circlePerimeter = 314.16;
        const strokeOffset = circlePerimeter - (circlePerimeter * score / 100);
        
        if (liveGauge) {
            liveGauge.style.strokeDashoffset = strokeOffset;
            liveGauge.style.stroke = data.gauge_color;
        }
        
        // Adjust score text color dynamically to matching scale
        if (liveScoreValue) {
            liveScoreValue.className = 'score-number'; // Reset
            if (score < 20) liveScoreValue.style.color = '#f43f5e';
            else if (score < 40) liveScoreValue.style.color = '#f97316';
            else if (score < 60) liveScoreValue.style.color = '#f59e0b';
            else if (score < 80) liveScoreValue.style.color = '#0ea5e9';
            else liveScoreValue.style.color = '#10b981';
        }

        // 2. Update Strength Badge
        if (liveStrengthLabel) {
            liveStrengthLabel.innerText = data.strength;
            liveStrengthLabel.className = 'live-badge'; // Reset classes
            const strengthLower = data.strength.toLowerCase().replace(/\s+/g, '-');
            liveStrengthLabel.classList.add(`strength-${strengthLower}`);
        }

        // 3. Update Text Metrics
        if (liveEntropyValue) liveEntropyValue.innerText = `${data.entropy.toFixed(2)} bits`;
        if (liveCrackTimeValue) liveCrackTimeValue.innerText = data.crack_time;
        
        // Length check indicator update
        const length = data.metrics ? data.metrics.length : 0;
        if (liveLenCheck) {
            liveLenCheck.innerHTML = '';
            const lengthDot = document.createElement('span');
            lengthDot.className = 'dot';
            
            if (length < 8) {
                lengthDot.classList.add('bg-rose-500');
                liveLenCheck.appendChild(lengthDot);
                liveLenCheck.innerHTML += ` <span class="text-rose-400 font-mono">${length} chars (Critical)</span>`;
            } else if (length < 12) {
                lengthDot.classList.add('bg-amber-500');
                liveLenCheck.appendChild(lengthDot);
                liveLenCheck.innerHTML += ` <span class="text-amber-400 font-mono">${length} chars (Sub-optimal)</span>`;
            } else {
                lengthDot.classList.add('bg-emerald-500');
                liveLenCheck.appendChild(lengthDot);
                liveLenCheck.innerHTML += ` <span class="text-emerald-400 font-mono">${length} chars (Enterprise)</span>`;
            }
        }

        // 4. Update Character Set Badges
        if (setLower) setLower.className = (data.metrics && data.metrics.has_lower) ? 'mini-badge active' : 'mini-badge';
        if (setUpper) setUpper.className = (data.metrics && data.metrics.has_upper) ? 'mini-badge active' : 'mini-badge';
        if (setDigits) setDigits.className = (data.metrics && data.metrics.has_digits) ? 'mini-badge active' : 'mini-badge';
        if (setSymbols) setSymbols.className = (data.metrics && data.metrics.has_symbols) ? 'mini-badge active' : 'mini-badge';

        // 5. Update Alerts List (Warnings)
        if (liveAlerts) {
            liveAlerts.innerHTML = '';
            if (data.warnings && data.warnings.length > 0) {
                data.warnings.forEach(warn => {
                    const item = document.createElement('div');
                    item.className = 'alert-item error animate-fade-in';
                    item.innerHTML = `
                        <i class="fa-solid fa-triangle-exclamation alert-icon"></i>
                        <span>${warn}</span>
                    `;
                    liveAlerts.appendChild(item);
                });
            } else {
                const item = document.createElement('div');
                item.className = 'alert-item success animate-fade-in';
                item.innerHTML = `
                    <i class="fa-solid fa-circle-check alert-icon"></i>
                    <span>No critical vulnerabilities detected. Password meets standard security threshold.</span>
                `;
                liveAlerts.appendChild(item);
            }
        }

        // 6. Update Suggestions List (Actionable Guidance)
        const liveSuggestions = document.getElementById('liveSuggestions');
        if (liveSuggestions) {
            liveSuggestions.innerHTML = '';
            if (data.suggestions && data.suggestions.length > 0) {
                data.suggestions.forEach(sug => {
                    const item = document.createElement('div');
                    item.className = 'checklist-item active';
                    item.innerHTML = `
                        <span class="chk-box-visual checked"><i class="fa-solid fa-circle-check"></i></span>
                        <span class="chk-text">${sug}</span>
                    `;
                    liveSuggestions.appendChild(item);
                });
            } else {
                const item = document.createElement('div');
                item.className = 'checklist-item active';
                item.innerHTML = `
                    <span class="chk-box-visual checked"><i class="fa-solid fa-shield-halved"></i></span>
                    <span class="chk-text">Key satisfies all standard defensive complexity rules.</span>
                `;
                liveSuggestions.appendChild(item);
            }
        }

        // 7. Update Real-Time Cryptographic Hashes
        if (hashMD5 && data.hashes && data.hashes.md5) hashMD5.innerText = data.hashes.md5.digest;
        if (hashSHA1 && data.hashes && data.hashes.sha1) hashSHA1.innerText = data.hashes.sha1.digest;
        if (hashSHA256 && data.hashes && data.hashes.sha256) hashSHA256.innerText = data.hashes.sha256.digest;
        if (hashSHA512 && data.hashes && data.hashes.sha512) hashSHA512.innerText = data.hashes.sha512.digest;

        // 8. Update Horizontal Live 5-Tier Strength Meter
        const meterBarFill = document.getElementById('meterBarFill');
        const meterRatingLabel = document.getElementById('meterRatingLabel');
        const stepVeryWeak = document.getElementById('stepVeryWeak');
        const stepWeak = document.getElementById('stepWeak');
        const stepFair = document.getElementById('stepFair');
        const stepStrong = document.getElementById('stepStrong');
        const stepVeryStrong = document.getElementById('stepVeryStrong');
        const inputStatusText = document.getElementById('inputStatusText');
        const telemetryDataText = document.getElementById('telemetryDataText');

        if (inputStatusText) {
            inputStatusText.innerText = 'ANALYZER_ACTIVE';
            inputStatusText.style.color = 'var(--accent-blue)';
        }

        if (telemetryDataText) {
            telemetryDataText.innerText = `ENTROPY: ${data.entropy.toFixed(1)} BITS`;
        }

        if (meterBarFill) {
            meterBarFill.style.width = `${score}%`;
            meterBarFill.style.backgroundColor = data.gauge_color;
        }

        if (meterRatingLabel) {
            meterRatingLabel.innerText = data.strength.toUpperCase();
            meterRatingLabel.style.color = data.gauge_color;
        }

        // Reset step colors on all 5 tiers
        [stepVeryWeak, stepWeak, stepFair, stepStrong, stepVeryStrong].forEach(el => {
            if (el) el.className = '';
        });

        // Set active step color
        if (score < 20) {
            if (stepVeryWeak) stepVeryWeak.className = 'meter-text-veryweak font-bold';
        } else if (score < 40) {
            if (stepWeak) stepWeak.className = 'meter-text-weak font-bold';
        } else if (score < 60) {
            if (stepFair) stepFair.className = 'meter-text-fair font-bold';
        } else if (score < 80) {
            if (stepStrong) stepStrong.className = 'meter-text-strong font-bold';
        } else {
            if (stepVeryStrong) stepVeryStrong.className = 'meter-text-verystrong font-bold';
        }

        // 9. Update Password Details Cards
        const m = data.metrics || {};
        const detailTotalChars = document.getElementById('detailTotalChars');
        const detailTotalCharsSub = document.getElementById('detailTotalCharsSub');
        const detailUpperChars = document.getElementById('detailUpperChars');
        const detailLowerChars = document.getElementById('detailLowerChars');
        const detailDigitChars = document.getElementById('detailDigitChars');
        const detailSymbolChars = document.getElementById('detailSymbolChars');
        const detailUniqueChars = document.getElementById('detailUniqueChars');
        const detailUniqueRatio = document.getElementById('detailUniqueRatio');
        const detailEntropy = document.getElementById('detailEntropy');
        const detailEntropyLevel = document.getElementById('detailEntropyLevel');

        if (detailTotalChars) detailTotalChars.innerText = m.length !== undefined ? m.length : length;
        if (detailTotalCharsSub) {
            detailTotalCharsSub.innerText = length >= 16 
                ? 'Optimal (16+ chars)' 
                : (length >= 12 ? 'Standard (12+ chars)' : 'Short (< 12 chars)');
        }
        if (detailUpperChars) detailUpperChars.innerText = m.upper_count !== undefined ? m.upper_count : 0;
        if (detailLowerChars) detailLowerChars.innerText = m.lower_count !== undefined ? m.lower_count : 0;
        if (detailDigitChars) detailDigitChars.innerText = m.digits_count !== undefined ? m.digits_count : 0;
        if (detailSymbolChars) detailSymbolChars.innerText = m.symbols_count !== undefined ? m.symbols_count : 0;
        if (detailUniqueChars) detailUniqueChars.innerText = m.unique_count !== undefined ? m.unique_count : 0;
        if (detailUniqueRatio) {
            const ratioPercent = m.unique_ratio ? Math.round(m.unique_ratio * 100) : 0;
            detailUniqueRatio.innerText = `${ratioPercent}% Diversity`;
        }
        if (detailEntropy) detailEntropy.innerText = data.entropy.toFixed(1);
        if (detailEntropyLevel) detailEntropyLevel.innerText = `${data.entropy.toFixed(2)} bits (${data.entropy_level || 'Normal'})`;

        // 10. Update Security Analysis Cards (6-Check Matrix)
        if (data.checks) {
            renderCheckCard('checkCardLength', 'checkBadgeLength', 'checkDescLength', data.checks.length);
            renderCheckCard('checkCardRepeated', 'checkBadgeRepeated', 'checkDescRepeated', data.checks.repeated);
            renderCheckCard('checkCardSequential', 'checkBadgeSequential', 'checkDescSequential', data.checks.sequential);
            renderCheckCard('checkCardCommon', 'checkBadgeCommon', 'checkDescCommon', data.checks.common);
            renderCheckCard('checkCardDates', 'checkBadgeDates', 'checkDescDates', data.checks.dates);
            renderCheckCard('checkCardDiversity', 'checkBadgeDiversity', 'checkDescDiversity', data.checks.diversity);
        }

        // 11. Update Multi-Scenario Crack-Time Estimates
        if (data.scenarios) {
            const timeOnlineThrottled = document.getElementById('timeOnlineThrottled');
            const timeOnlineFast = document.getElementById('timeOnlineFast');
            const timeOfflineGpu = document.getElementById('timeOfflineGpu');
            const timeOfflineCluster = document.getElementById('timeOfflineCluster');
            const timeSlowHash = document.getElementById('timeSlowHash');

            if (timeOnlineThrottled) timeOnlineThrottled.innerText = data.scenarios.online_throttled || 'Instant';
            if (timeOnlineFast) timeOnlineFast.innerText = data.scenarios.online_fast || 'Instant';
            if (timeOfflineGpu) timeOfflineGpu.innerText = data.scenarios.offline_gpu || 'Instant';
            if (timeOfflineCluster) timeOfflineCluster.innerText = data.scenarios.offline_cluster || 'Instant';
            if (timeSlowHash) timeSlowHash.innerText = data.scenarios.slow_hash || 'Instant';
        }
    }

    function renderCheckCard(cardId, badgeId, descId, checkInfo) {
        if (!checkInfo) return;
        const card = document.getElementById(cardId);
        const badge = document.getElementById(badgeId);
        const desc = document.getElementById(descId);

        if (card) {
            card.classList.remove('pass', 'warning', 'danger');
            card.classList.add(checkInfo.card_class || 'pass');
        }
        if (badge) {
            badge.className = `check-status-badge ${checkInfo.badge_class || 'badge-pass'}`;
            badge.innerText = checkInfo.status;
        }
        if (desc) {
            desc.innerText = checkInfo.message;
        }
    }

    function resetHashingCards() {
        if (hashMD5) hashMD5.innerText = '[Enter password above to calculate MD5]';
        if (hashSHA1) hashSHA1.innerText = '[Enter password above to calculate SHA-1]';
        if (hashSHA256) hashSHA256.innerText = '[Enter password above to calculate SHA-256]';
        if (hashSHA512) hashSHA512.innerText = '[Enter password above to calculate SHA-512]';
    }

    function resetStrengthMeter() {
        const meterBarFill = document.getElementById('meterBarFill');
        const meterRatingLabel = document.getElementById('meterRatingLabel');
        const stepVeryWeak = document.getElementById('stepVeryWeak');
        const stepWeak = document.getElementById('stepWeak');
        const stepFair = document.getElementById('stepFair');
        const stepStrong = document.getElementById('stepStrong');
        const stepVeryStrong = document.getElementById('stepVeryStrong');
        const inputStatusText = document.getElementById('inputStatusText');
        const telemetryDataText = document.getElementById('telemetryDataText');

        if (inputStatusText) {
            inputStatusText.innerText = 'AWAITING_INPUT';
            inputStatusText.style.color = 'var(--text-muted)';
        }

        if (telemetryDataText) {
            telemetryDataText.innerText = 'HASH_RATE: 100G/S';
        }

        if (meterBarFill) {
            meterBarFill.style.width = '0%';
            meterBarFill.style.backgroundColor = 'var(--text-muted)';
        }

        if (meterRatingLabel) {
            meterRatingLabel.innerText = 'STANDBY';
            meterRatingLabel.style.color = 'var(--text-muted)';
        }

        [stepVeryWeak, stepWeak, stepFair, stepStrong, stepVeryStrong].forEach(el => {
            if (el) el.className = '';
        });

        // Reset details cards to zero
        const detailTotalChars = document.getElementById('detailTotalChars');
        const detailUpperChars = document.getElementById('detailUpperChars');
        const detailLowerChars = document.getElementById('detailLowerChars');
        const detailDigitChars = document.getElementById('detailDigitChars');
        const detailSymbolChars = document.getElementById('detailSymbolChars');
        const detailUniqueChars = document.getElementById('detailUniqueChars');
        const detailEntropy = document.getElementById('detailEntropy');

        if (detailTotalChars) detailTotalChars.innerText = '0';
        if (detailUpperChars) detailUpperChars.innerText = '0';
        if (detailLowerChars) detailLowerChars.innerText = '0';
        if (detailDigitChars) detailDigitChars.innerText = '0';
        if (detailSymbolChars) detailSymbolChars.innerText = '0';
        if (detailUniqueChars) detailUniqueChars.innerText = '0';
        if (detailEntropy) detailEntropy.innerText = '0.0';
    }

    // --- Cryptographic Password Generator Controls ---
    const lengthsArray = [8, 12, 16, 20, 24, 32, 48, 64];

    if (lengthSlider && lengthDisplay) {
        lengthSlider.addEventListener('input', () => {
            const index = parseInt(lengthSlider.value, 10);
            lengthDisplay.innerText = lengthsArray[index];
        });
    }

    // New premium control selectors
    const toggleGenVisibility = document.getElementById('toggleGenVisibility');
    const genEyeIcon = document.getElementById('genEyeIcon');
    const genEyeOffIcon = document.getElementById('genEyeOffIcon');
    const clearPasswordBtn = document.getElementById('clearPasswordBtn');
    const regenerateBtn = document.getElementById('regenerateBtn');
    const regenerateIcon = document.getElementById('regenerateIcon');
    const genExcludeSimilar = document.getElementById('genExcludeSimilar');
    const genExcludeAmbiguous = document.getElementById('genExcludeAmbiguous');

    // Live diagnostics selectors
    const genLiveDiagnostics = document.getElementById('genLiveDiagnostics');
    const genLiveGauge = document.getElementById('genLiveGauge');
    const genLiveScoreValue = document.getElementById('genLiveScoreValue');
    const genLiveStrengthLabel = document.getElementById('genLiveStrengthLabel');
    const genLiveEntropyValue = document.getElementById('genLiveEntropyValue');
    const genLiveCrackTimeValue = document.getElementById('genLiveCrackTimeValue');
    const genLiveQualityValue = document.getElementById('genLiveQualityValue');
    const genLiveRecommendations = document.getElementById('genLiveRecommendations');

    // Toggle visibility logic (Eye/Eye-slash)
    if (toggleGenVisibility && generatorOutput) {
        let genVisible = false;
        toggleGenVisibility.addEventListener('click', () => {
            genVisible = !genVisible;
            if (genVisible) {
                generatorOutput.type = 'text';
                genEyeIcon.classList.add('hidden');
                genEyeOffIcon.classList.remove('hidden');
            } else {
                generatorOutput.type = 'password';
                genEyeIcon.classList.remove('hidden');
                genEyeOffIcon.classList.add('hidden');
            }
        });
    }

    // Clear Generator Handler
    if (clearPasswordBtn && generatorOutput) {
        clearPasswordBtn.addEventListener('click', () => {
            generatorOutput.value = '';
            copyPasswordBtn.disabled = true;
            clearPasswordBtn.disabled = true;
            if (genLiveDiagnostics) genLiveDiagnostics.classList.add('hidden');
        });
    }

    // Regenerate Button Animation and click trigger
    if (regenerateBtn && generateBtn) {
        regenerateBtn.addEventListener('click', () => {
            if (regenerateIcon) {
                regenerateIcon.classList.add('fa-spin');
                setTimeout(() => { regenerateIcon.classList.remove('fa-spin'); }, 600);
            }
            generateBtn.click();
        });
    }

    if (generateBtn) {
        generateBtn.addEventListener('click', async () => {
            const lengthIndex = parseInt(lengthSlider.value, 10);
            const length = lengthsArray[lengthIndex];
            const upper = genUpper.checked;
            const lower = genLower.checked;
            const digits = genDigits.checked;
            const symbols = genSymbols.checked;
            const excludeSimilar = genExcludeSimilar ? genExcludeSimilar.checked : false;
            const excludeAmbiguous = genExcludeAmbiguous ? genExcludeAmbiguous.checked : false;

            // Simple validation: at least one character set must be chosen
            if (!upper && !lower && !digits && !symbols) {
                if (generatorOutput) {
                    generatorOutput.type = 'text';
                    generatorOutput.value = "Error: Select at least one character set!";
                }
                copyPasswordBtn.disabled = true;
                if (clearPasswordBtn) clearPasswordBtn.disabled = true;
                if (genLiveDiagnostics) genLiveDiagnostics.classList.add('hidden');
                return;
            }

            try {
                const response = await fetch('/api/generate', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        length: length,
                        upper: upper,
                        lower: lower,
                        digits: digits,
                        symbols: symbols,
                        excludeSimilar: excludeSimilar,
                        excludeAmbiguous: excludeAmbiguous
                    })
                });

                if (response.ok) {
                    const data = await response.json();
                    renderGeneratorResults(data);
                    return;
                }
            } catch (err) {
                console.warn("Telemetry generator offline, compiling key via secure browser CSPRNG fallback...");
            }

            // Local fallback generator using browser cryptographic secure randomness
            const localGen = await runLocalGeneration(length, upper, lower, digits, symbols, excludeSimilar, excludeAmbiguous);
            renderGeneratorResults(localGen);
        });
    }

    function renderGeneratorResults(data) {
        if (generatorOutput) {
            generatorOutput.value = data.password;
        }
        
        // Enable Copy and Clear
        copyPasswordBtn.disabled = false;
        if (clearPasswordBtn) clearPasswordBtn.disabled = false;

        // Populate Real-Time Assessment Diagnostic Panel
        if (genLiveDiagnostics) {
            genLiveDiagnostics.classList.remove('hidden');
            
            // Update score value & circle offset (circumference ~ 263.89)
            if (genLiveScoreValue) {
                animateScoreText(genLiveScoreValue, data.score);
                // Match text color to strength gauge color
                if (data.gauge_color === '#a3e635' || data.gauge_color === '#00FF88' || data.gauge_color === '#10b981') {
                    genLiveScoreValue.className = "score-number sm text-green";
                } else if (data.gauge_color === '#0ea5e9' || data.gauge_color === '#00C8FF') {
                    genLiveScoreValue.className = "score-number sm text-blue";
                } else if (data.gauge_color === '#f59e0b' || data.gauge_color === '#FFA500') {
                    genLiveScoreValue.className = "score-number sm text-warning";
                } else {
                    genLiveScoreValue.className = "score-number sm text-rose-400";
                }
            }
            
            if (genLiveGauge) {
                const circumference = 263.89;
                const offset = circumference - (data.score / 100) * circumference;
                genLiveGauge.style.strokeDashoffset = offset;
                genLiveGauge.style.stroke = data.gauge_color;
            }

            // Update labels and badges
            if (genLiveStrengthLabel) {
                genLiveStrengthLabel.innerText = data.strength;
                const strengthClass = data.strength.toLowerCase().replace(' ', '');
                genLiveStrengthLabel.className = `live-badge strength-${strengthClass}`;
            }
            if (genLiveEntropyValue) {
                genLiveEntropyValue.innerText = `${data.entropy.toFixed(2)} bits`;
            }
            if (genLiveCrackTimeValue) {
                genLiveCrackTimeValue.innerText = data.crack_time;
            }
            if (genLiveQualityValue) {
                genLiveQualityValue.innerText = data.entropy_desc || 'Optimal';
            }

            // Populate recommendations list
            if (genLiveRecommendations) {
                genLiveRecommendations.innerHTML = '';
                const combinedAdvices = [];
                if (data.warnings && data.warnings.length > 0) {
                    data.warnings.forEach(w => combinedAdvices.push(w));
                }
                if (data.suggestions && data.suggestions.length > 0) {
                    data.suggestions.forEach(s => combinedAdvices.push(s));
                }

                if (combinedAdvices.length === 0) {
                    combinedAdvices.push("No vulnerabilities detected. Key meets absolute military-grade defense standards.");
                }

                combinedAdvices.forEach(adv => {
                    const li = document.createElement('li');
                    li.innerText = adv;
                    genLiveRecommendations.appendChild(li);
                });
            }
        }

        // Automatically copy to main password input for instant live analysis
        if (passwordInput) {
            passwordInput.value = data.password;
            evaluatePasswordLive(data.password);
        }
    }

    // Copy to Clipboard Action
    if (copyPasswordBtn) {
        copyPasswordBtn.addEventListener('click', () => {
            const passwordToCopy = generatorOutput.value;
            if (!passwordToCopy) return;

            navigator.clipboard.writeText(passwordToCopy)
                .then(() => {
                    copyTooltip.innerText = "Copied!";
                    setTimeout(() => {
                        copyTooltip.innerText = "Copy Password";
                    }, 2000);
                })
                .catch(err => {
                    console.error('Could not copy credential to clipboard: ', err);
                });
        });
    }

    // --- Interactive Cybersecurity Security & Intel Tabs Event Handler ---
    const intelTabs = document.querySelectorAll('.intel-tab-btn');
    intelTabs.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active status from all tab buttons and panels
            intelTabs.forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.intel-tab-panel').forEach(p => p.classList.remove('active'));

            // Set active clicked tab and matching panel
            btn.classList.add('active');
            const tabId = btn.getAttribute('data-tab');
            const panel = document.getElementById(tabId);
            if (panel) panel.classList.add('active');
        });
    });

    // --- Intercept Form Submits to generate dynamic client side audit reports ---
    if (analyzerForm) {
        analyzerForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            if (!analyzerForm.checkValidity()) return;

            // Flash loader screen briefly for visual feedback
            if (loadingOverlay) loadingOverlay.classList.remove('hidden');

            const password = passwordInput.value;
            const localData = await runLocalAnalysis(password);

            setTimeout(() => {
                if (loadingOverlay) loadingOverlay.classList.add('hidden');
                renderLocalAuditSection(password, localData);
            }, 600);
        });
    }

    // Results Page Obscure toggler
    const toggleLocalResultVisibility = document.getElementById('toggleLocalResultVisibility');
    const localAnalyzedPassword = document.getElementById('localAnalyzedPassword');
    const localEyeIcon = document.getElementById('localEyeIcon');
    const localEyeOffIcon = document.getElementById('localEyeOffIcon');

    if (toggleLocalResultVisibility && localAnalyzedPassword) {
        let isResultObscured = true;
        toggleLocalResultVisibility.addEventListener('click', () => {
            isResultObscured = !isResultObscured;
            if (isResultObscured) {
                localAnalyzedPassword.className = 'obscured-password font-mono';
                if (localEyeIcon) localEyeIcon.classList.remove('hidden');
                if (localEyeOffIcon) localEyeOffIcon.classList.add('hidden');
            } else {
                localAnalyzedPassword.className = 'revealed-password font-mono';
                if (localEyeIcon) localEyeIcon.classList.add('hidden');
                if (localEyeOffIcon) localEyeOffIcon.classList.remove('hidden');
            }
        });
    }

    // ==========================================
    // --- Cryptographic & Pattern Walk Fallback Logic ---
    // ==========================================

    const defaultCommonPasswords = ['123456', '123456789', 'password', 'qwerty', 'admin', 'welcome', 'letmein', '12345', '1234567', '12345678', '1234567890', 'iloveyou', 'p@ssword'];

    function detectSequential(p) {
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

    function detectRepeated(p) {
        return /(.)\1\1/.test(p) || /(.{2,4})\1/.test(p);
    }

    function detectKeyboardPatterns(p) {
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

    function detectDatesAndPatterns(p) {
        // Calendar years (1950 - 2039)
        if (/(?:19[5-9]\d|20[0-3]\d)/.test(p)) return true;
        // Date patterns MMDD or DDMM like 0112, 1225
        if (/(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])/.test(p)) return true;
        return detectKeyboardPatterns(p);
    }

    function formatCrackTime(seconds) {
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

    function calculateScenarios(entropy) {
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

    function calculateEntropy(password) {
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

    function estimateCrackTime(entropy) {
        if (entropy <= 0) {
            return { readable: 'Instant', explanation: 'No password provided to analyze.' };
        }
        
        const combinations = Math.pow(2, entropy);
        const guessesPerSecond = 1e11; // 100 Billion
        const seconds = combinations / guessesPerSecond;

        const readable = formatCrackTime(seconds);
        let explanation = `An attacker with standard modern GPU cracking equipment (100 Billion guesses/sec) would take approximately ${readable} to crack this password.`;
        if (seconds < 1) {
            explanation = "An attacker with standard modern GPU cracking equipment (100 Billion guesses/sec) would crack this password instantaneously. This password is critically vulnerable.";
        } else if (seconds >= 3153600000) {
            explanation = `Would take around ${readable} to crack under 100 Billion guesses/sec. Exceptionally robust mathematical defense.`;
        }

        return { readable, explanation };
    }

    function checkPasswordStrength(password) {
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

        const isCommon = defaultCommonPasswords.includes(password.toLowerCase());
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

        const warnings = [];
        const suggestions = [];

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

    async function runLocalAnalysis(password) {
        const strengthData = checkPasswordStrength(password);
        const entropyData = calculateEntropy(password);
        const crackTimeData = estimateCrackTime(entropyData.entropy);
        const scenarios = calculateScenarios(entropyData.entropy);
        
        // Dynamic client-side secure hashes (MD5 in JS, others native)
        const md5Digest = md5(password);
        const sha1Digest = await calcSubtleHash(password, 'SHA-1');
        const sha256Digest = await calcSubtleHash(password, 'SHA-256');
        const sha512Digest = await calcSubtleHash(password, 'SHA-512');

        return {
            score: strengthData.score,
            strength: strengthData.strength,
            badge_class: strengthData.badge_class,
            color_class: strengthData.color_class,
            progress_class: strengthData.progress_class,
            gauge_color: strengthData.gauge_color,
            warnings: strengthData.warnings,
            suggestions: strengthData.suggestions,
            checks: strengthData.checks,
            scenarios: scenarios,
            entropy: entropyData.entropy,
            entropy_level: entropyData.level,
            entropy_desc: entropyData.desc,
            crack_time: crackTimeData.readable,
            crack_desc: crackTimeData.explanation,
            metrics: strengthData.metrics,
            hashes: {
                md5: { digest: md5Digest },
                sha1: { digest: sha1Digest },
                sha256: { digest: sha256Digest },
                sha512: { digest: sha512Digest }
            }
        };
    }

    async function runLocalGeneration(length, upper, lower, digits, symbols, excludeSimilar, excludeAmbiguous) {
        const password = localGenerateSecurePassword(length, upper, lower, digits, symbols, excludeSimilar, excludeAmbiguous);
        const analysis = await runLocalAnalysis(password);
        return {
            password,
            score: analysis.score,
            strength: analysis.strength,
            gauge_color: analysis.gauge_color,
            entropy: analysis.entropy,
            entropy_desc: analysis.entropy_level,
            crack_time: analysis.crack_time,
            warnings: analysis.warnings,
            suggestions: analysis.suggestions
        };
    }

    async function calcSubtleHash(message, algo) {
        if (!message) return '';
        try {
            const msgBuffer = new TextEncoder().encode(message);
            const hashBuffer = await crypto.subtle.digest(algo, msgBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (e) {
            console.error(`Subtle crypto failed for ${algo}:`, e);
            return '[Not supported in this browser context]';
        }
    }

    function browserRandomInt(max) {
        if (max <= 0) return 0;
        const array = new Uint32Array(1);
        window.crypto.getRandomValues(array);
        return array[0] % max;
    }

    function localGenerateSecurePassword(
        length = 16,
        useUpper = true,
        useLower = true,
        useDigits = true,
        useSymbols = true,
        excludeSimilar = false,
        excludeAmbiguous = false
    ) {
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
            const guaranteed = [];

            if (useLower && lowerChars) {
                pool += lowerChars;
                guaranteed.push(lowerChars[browserRandomInt(lowerChars.length)]);
            }
            if (useUpper && upperChars) {
                pool += upperChars;
                guaranteed.push(upperChars[browserRandomInt(upperChars.length)]);
            }
            if (useDigits && digitChars) {
                pool += digitChars;
                guaranteed.push(digitChars[browserRandomInt(digitChars.length)]);
            }
            if (useSymbols && symbolChars) {
                pool += symbolChars;
                guaranteed.push(symbolChars[browserRandomInt(symbolChars.length)]);
            }

            const remainingCount = length - guaranteed.length;
            for (let i = 0; i < remainingCount; i++) {
                guaranteed.push(pool[browserRandomInt(pool.length)]);
            }

            // Shuffle the guaranteed array
            for (let i = guaranteed.length - 1; i > 0; i--) {
                const j = browserRandomInt(i + 1);
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
        const fallbackArr = [];
        for (let i = 0; i < length; i++) {
            fallbackArr.push(fallbackPool[browserRandomInt(fallbackPool.length)]);
        }
        return fallbackArr.join('');
    }

    function renderLocalAuditSection(password, data) {
        const detailedAuditSection = document.getElementById('detailedAuditSection');
        if (!detailedAuditSection) return;

        // Unhide
        detailedAuditSection.classList.remove('hidden');

        // Scroll to the detailed audit section smoothly
        detailedAuditSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

        // Update target password field
        const localAnalyzedPassword = document.getElementById('localAnalyzedPassword');
        if (localAnalyzedPassword) {
            localAnalyzedPassword.innerText = password;
            // Force obscured by default
            localAnalyzedPassword.className = 'obscured-password font-mono';
        }

        // Reset Result eye icons
        const localEyeIcon = document.getElementById('localEyeIcon');
        const localEyeOffIcon = document.getElementById('localEyeOffIcon');
        if (localEyeIcon) localEyeIcon.classList.remove('hidden');
        if (localEyeOffIcon) localEyeOffIcon.classList.add('hidden');

        // Update Verdict Badge
        const localVerdictBadge = document.getElementById('localVerdictBadge');
        if (localVerdictBadge) {
            localVerdictBadge.innerText = data.strength;
            localVerdictBadge.className = `badge ${data.badge_class}`;
        }

        // Overall Score Meter
        const localScoreNumber = document.getElementById('localScoreNumber');
        if (localScoreNumber) {
            animateScoreText(localScoreNumber, data.score);
            localScoreNumber.className = `score-number large ${data.color_class}`;
        }

        const localResultGauge = document.getElementById('localResultGauge');
        if (localResultGauge) {
            const circumference = 471.24; // 2 * Math.PI * 75
            const offset = circumference - (data.score / 100) * circumference;
            localResultGauge.style.strokeDashoffset = offset;
            localResultGauge.style.stroke = data.gauge_color;
        }

        // Score Grade & Explanation
        const localScoreGrade = document.getElementById('localScoreGrade');
        if (localScoreGrade) {
            localScoreGrade.innerText = `Security Grade: ${data.strength}`;
            localScoreGrade.className = data.color_class;
        }

        const localScoreExplanation = document.getElementById('localScoreExplanation');
        if (localScoreExplanation) {
            if (data.score < 25) {
                localScoreExplanation.innerText = "This key is extremely vulnerable. It is highly advised to immediately replace it with a strong alternative.";
            } else if (data.score < 45) {
                localScoreExplanation.innerText = "A basic credential. Safe from automated internet scans but vulnerable to directed GPU brute-force pipelines.";
            } else if (data.score < 60) {
                localScoreExplanation.innerText = "A moderately secure key. Meets minor complexity checks but fails under intensive hardware walks.";
            } else if (data.score < 80) {
                localScoreExplanation.innerText = "Solid defensive key. Standard algorithms require a long theoretical search window to brute force.";
            } else if (data.score < 95) {
                localScoreExplanation.innerText = "Strong standard password. Meets corporate guidelines and high-entropy resilience thresholds.";
            } else {
                localScoreExplanation.innerText = "Enterprise-grade key variables. Safe against distributed GPU rigs and parallelized search algorithms.";
            }
        }

        // Shannon Entropy Analysis
        const localEntropyVal = document.getElementById('localEntropyVal');
        if (localEntropyVal) {
            localEntropyVal.innerText = `${data.entropy.toFixed(2)}`;
            const unitSpan = document.createElement('span');
            unitSpan.className = 'unit';
            unitSpan.innerText = ' bits';
            localEntropyVal.appendChild(unitSpan);
        }

        const localEntropyLevel = document.getElementById('localEntropyLevel');
        if (localEntropyLevel) {
            localEntropyLevel.innerHTML = `<i class="fa-solid fa-brain"></i> ${data.entropy_level}`;
        }

        const localEntropyDesc = document.getElementById('localEntropyDesc');
        if (localEntropyDesc) {
            localEntropyDesc.innerText = data.entropy_desc;
        }

        // Formula values
        const localFormulaVars = document.getElementById('localFormulaVars');
        if (localFormulaVars) {
            let poolSize = 0;
            if (data.metrics.has_lower) poolSize += 26;
            if (data.metrics.has_upper) poolSize += 26;
            if (data.metrics.has_digits) poolSize += 10;
            if (data.metrics.has_symbols) poolSize += 33;
            if (poolSize === 0) poolSize = 1;

            localFormulaVars.innerHTML = `
                <span>L = Length (${data.metrics.length})</span>
                <span>R = Charset Pool (${poolSize})</span>
            `;
        }

        // Attacker Brute-Force Time
        const localCrackTime = document.getElementById('localCrackTime');
        if (localCrackTime) {
            localCrackTime.innerText = data.crack_time;
        }

        const localCrackDesc = document.getElementById('localCrackDesc');
        if (localCrackDesc) {
            localCrackDesc.innerText = data.crack_desc;
        }

        // Alerts & Checklist
        const localFindingsGroupTitle = document.getElementById('localFindingsGroupTitle');
        if (localFindingsGroupTitle) {
            localFindingsGroupTitle.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> Security Threats Detected (${data.warnings.length})`;
            if (data.warnings.length === 0) {
                localFindingsGroupTitle.className = 'findings-group-title text-emerald-400';
            } else {
                localFindingsGroupTitle.className = 'findings-group-title text-rose-500';
            }
        }

        const localAlertsList = document.getElementById('localAlertsList');
        if (localAlertsList) {
            localAlertsList.innerHTML = '';
            if (data.warnings.length === 0) {
                localAlertsList.innerHTML = `
                    <div class="alert-item success">
                        <i class="fa-solid fa-circle-check alert-icon"></i>
                        <span>No severe architectural pattern warnings detected. Excellent structure.</span>
                    </div>
                `;
            } else {
                data.warnings.forEach(warn => {
                    const item = document.createElement('div');
                    item.className = 'alert-item error animate-fade-in';
                    item.innerHTML = `
                        <i class="fa-solid fa-triangle-exclamation alert-icon"></i>
                        <span>${warn}</span>
                    `;
                    localAlertsList.appendChild(item);
                });
            }
        }

        const localSuggestionsList = document.getElementById('localSuggestionsList');
        if (localSuggestionsList) {
            localSuggestionsList.innerHTML = '';
            data.suggestions.forEach(sug => {
                const item = document.createElement('div');
                item.className = 'checklist-item active';
                item.innerHTML = `
                    <span class="chk-box-visual checked"><i class="fa-solid fa-circle-check"></i></span>
                    <span class="chk-text">${sug}</span>
                `;
                localSuggestionsList.appendChild(item);
            });
        }

        // Composition Matrix Checklists
        updateBadge('localBadgeLength', data.metrics.length >= 12, `${data.metrics.length} Chars`);
        updateBadge('localBadgeLower', data.metrics.has_lower, data.metrics.has_lower ? 'YES' : 'NO');
        updateBadge('localBadgeUpper', data.metrics.has_upper, data.metrics.has_upper ? 'YES' : 'NO');
        updateBadge('localBadgeDigits', data.metrics.has_digits, data.metrics.has_digits ? 'YES' : 'NO');
        updateBadge('localBadgeSymbols', data.metrics.has_symbols, data.metrics.has_symbols ? 'YES' : 'NO');

        const localMatrixLength = document.getElementById('localMatrixLength');
        if (localMatrixLength) localMatrixLength.innerText = data.metrics.length;

        // Hashes Output
        const localResultHashMD5 = document.getElementById('localResultHashMD5');
        const localResultHashSHA1 = document.getElementById('localResultHashSHA1');
        const localResultHashSHA256 = document.getElementById('localResultHashSHA256');
        const localResultHashSHA512 = document.getElementById('localResultHashSHA512');

        if (localResultHashMD5) localResultHashMD5.innerText = data.hashes.md5.digest;
        if (localResultHashSHA1) localResultHashSHA1.innerText = data.hashes.sha1.digest;
        if (localResultHashSHA256) localResultHashSHA256.innerText = data.hashes.sha256.digest;
        if (localResultHashSHA512) localResultHashSHA512.innerText = data.hashes.sha512.digest;
    }

    function updateBadge(id, isPass, passText) {
        const el = document.getElementById(id);
        if (!el) return;
        if (isPass) {
            el.className = 'badge bg-emerald-500/10 text-emerald-400 border border-emerald-500/20';
            el.innerHTML = `<i class="fa-solid fa-circle-check"></i> ${passText}`;
        } else {
            el.className = 'badge bg-rose-500/10 text-rose-400 border border-rose-500/20';
            el.innerHTML = `<i class="fa-solid fa-circle-xmark"></i> ${passText === 'NO' ? 'NO' : 'FAIL'}`;
        }
    }

    // Pure JS MD5 Implementation (Self-Contained)
    function md5(string) {
        function RotateLeft(lValue, iShiftBits) {
            return (lValue<<iShiftBits) | (lValue>>>(32-iShiftBits));
        }
        function AddUnsigned(lX,lY) {
            var lX4,lY4,lX8,lY8,lResult;
            lX8 = (lX & 0x80000000);
            lY8 = (lY & 0x80000000);
            lX4 = (lX & 0x40000000);
            lY4 = (lY & 0x40000000);
            lResult = (lX & 0x3FFFFFFF)+(lY & 0x3FFFFFFF);
            if (lX4 & lY4) {
                return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
            }
            if (lX4 | lY4) {
                if (lResult & 0x40000000) {
                    return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
                } else {
                    return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
                }
            } else {
                return (lResult ^ lX8 ^ lY8);
            }
        }
        function F(x,y,z) { return (x & y) | ((~x) & z); }
        function G(x,y,z) { return (x & z) | (y & (~z)); }
        function H(x,y,z) { return (x ^ y ^ z); }
        function I(x,y,z) { return (y ^ (x | (~z))); }
        function FF(a,b,c,d,x,s,ac) {
            a = AddUnsigned(a, AddUnsigned(AddUnsigned(F(b,c,d), x), ac));
            return AddUnsigned(RotateLeft(a, s), b);
        }
        function GG(a,b,c,d,x,s,ac) {
            a = AddUnsigned(a, AddUnsigned(AddUnsigned(G(b,c,d), x), ac));
            return AddUnsigned(RotateLeft(a, s), b);
        }
        function HH(a,b,c,d,x,s,ac) {
            a = AddUnsigned(a, AddUnsigned(AddUnsigned(H(b,c,d), x), ac));
            return AddUnsigned(RotateLeft(a, s), b);
        }
        function II(a,b,c,d,x,s,ac) {
            a = AddUnsigned(a, AddUnsigned(AddUnsigned(I(b,c,d), x), ac));
            return AddUnsigned(RotateLeft(a, s), b);
        }
        function ConvertToWordArray(string) {
            var lWordCount;
            var lMessageLength = string.length;
            var lNumberOfWords_temp1=lMessageLength + 8;
            var lNumberOfWords_temp2=(lNumberOfWords_temp1-(lNumberOfWords_temp1 % 64))/64;
            var lNumberOfWords = (lNumberOfWords_temp2+1)*16;
            var lWordArray=Array(lNumberOfWords);
            var lBytePosition = 0;
            var lByteCount = 0;
            while ( lByteCount < lMessageLength ) {
                lWordCount = (lByteCount-(lByteCount % 4))/4;
                lBytePosition = (lByteCount % 4)*8;
                lWordArray[lWordCount] = (lWordArray[lWordCount] | (string.charCodeAt(lByteCount)<<lBytePosition));
                lByteCount++;
            }
            lWordCount = (lByteCount-(lByteCount % 4))/4;
            lBytePosition = (lByteCount % 4)*8;
            lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80<<lBytePosition);
            lWordArray[lNumberOfWords-2] = lMessageLength<<3;
            lWordArray[lNumberOfWords-1] = lMessageLength>>>29;
            return lWordArray;
        }
        function WordToHex(lValue) {
            var WordToHexValue="",WordToHexValue_temp="",lByte,lCount;
            for (lCount = 0;lCount<=3;lCount++) {
                lByte = (lValue>>>(lCount*8)) & 255;
                WordToHexValue_temp = "0" + lByte.toString(16);
                WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length-2,2);
            }
            return WordToHexValue;
        }
        function Utf8Encode(string) {
            string = string.replace(/\r\n/g,"\n");
            var utftext = "";
            for (var n = 0; n < string.length; n++) {
                var c = string.charCodeAt(n);
                if (c < 128) {
                    utftext += String.fromCharCode(c);
                } else if((c > 127) && (c < 2048)) {
                    utftext += String.fromCharCode((c >> 6) | 192);
                    utftext += String.fromCharCode((c & 63) | 128);
                } else {
                    utftext += String.fromCharCode((c >> 12) | 224);
                    utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                    utftext += String.fromCharCode((c & 63) | 128);
                }
            }
            return utftext;
        }
        var x=Array();
        var k,AA,BB,CC,DD,a,b,c,d;
        var S11=7, S12=12, S13=17, S14=22;
        var S21=5, S22=9 , S23=14, S24=20;
        var S31=4, S32=11, S33=16, S34=23;
        var S41=6, S42=10, S43=15, S44=21;
        string = Utf8Encode(string);
        x = ConvertToWordArray(string);
        a = 0x67452301; b = 0xEFCDAB89; c = 0x98BADCFE; d = 0x10325476;
        for (k=0;k<x.length;k+=16) {
            AA=a; BB=b; CC=c; DD=d;
            a=FF(a,b,c,d,x[k+0], S11,0xD76AA478); d=FF(d,a,b,c,x[k+1], S12,0xE8C7B756); c=FF(c,d,a,b,x[k+2], S13,0x242070DB); b=FF(b,c,d,a,x[k+3], S14,0xC1BDCEEE);
            a=FF(a,b,c,d,x[k+4], S11,0xF57C0FAF); d=FF(d,a,b,c,x[k+5], S12,0x4787C62A); c=FF(c,d,a,b,x[k+6], S13,0xA8304613); b=FF(b,c,d,a,x[k+7], S14,0xFD469501);
            a=FF(a,b,c,d,x[k+8], S11,0x698098D8); d=FF(d,a,b,c,x[k+9], S12,0x8B44F7AF); c=FF(c,d,a,b,x[k+10],S13,0xFFFF5BB1); b=FF(b,c,d,a,x[k+11],S14,0x895CD7BE);
            a=FF(a,b,c,d,x[k+12],S11,0x6B901122); d=FF(d,a,b,c,x[k+13],S12,0xFD987193); c=FF(c,d,a,b,x[k+14],S13,0xA679438E); b=FF(b,c,d,a,x[k+15],S14,0x49B40821);
            a=GG(a,b,c,d,x[k+1], S21,0xF61E2562); d=GG(d,a,b,c,x[k+6], S22,0xC040B340); c=GG(c,d,a,b,x[k+11],S23,0x265E5A51); b=GG(b,c,d,a,x[k+0], S24,0xE9B6C7AA);
            a=GG(a,b,c,d,x[k+5], S21,0xD62F105D); d=GG(d,a,b,c,x[k+10],S22,0x2441453);  c=GG(c,d,a,b,x[k+15],S23,0xD8A1E681); b=GG(b,c,d,a,x[k+4], S24,0xE7D3FBC8);
            a=GG(a,b,c,d,x[k+9], S21,0x21E1CDE6); d=GG(d,a,b,c,x[k+14],S22,0xC33707D6); c=GG(c,d,a,b,x[k+3], S23,0xF4D50D87); b=GG(b,c,d,a,x[k+8], S24,0x455A14ED);
            a=GG(a,b,c,d,x[k+13],S21,0xA9E3E905); d=GG(d,a,b,c,x[k+2], S22,0xFCEFA3F8); c=GG(c,d,a,b,x[k+7], S23,0x676F02D9); b=GG(b,c,d,a,x[k+12],S24,0x8D2A4C8A);
            a=HH(a,b,c,d,x[k+5], S31,0xFFFA3942); d=HH(d,a,b,c,x[k+8], S32,0x8771F681); c=HH(c,d,a,b,x[k+11],S33,0x6D9D6122); b=HH(b,c,d,a,x[k+14],S34,0xFDE5380C);
            a=HH(a,b,c,d,x[k+1], S31,0xA4BEEA44); d=HH(d,a,b,c,x[k+4], S32,0x4BDECFA9); c=HH(c,d,a,b,x[k+7], S33,0xF6BB4B60); b=HH(b,c,d,a,x[k+10],S34,0xBEBFBC70);
            a=HH(a,b,c,d,x[k+13],S31,0x289B7EC6); d=HH(d,a,b,c,x[k+0], S32,0xEAA127FA); c=HH(c,d,a,b,x[k+3], S33,0xD4EF3085); b=HH(b,c,d,a,x[k+6], S34,0x4881D05);
            a=HH(a,b,c,d,x[k+9], S31,0xD9D4D039); d=HH(d,a,b,c,x[k+12],S32,0xE6DB99E5); c=HH(c,d,a,b,x[k+15],S33,0x1FA27CF8); b=HH(b,c,d,a,x[k+2], S34,0xC4AC5665);
            a=II(a,b,c,d,x[k+0], S41,0xF4292244); d=II(d,a,b,c,x[k+7], S42,0x432AFF97);  c=II(c,d,a,b,x[k+14],S43,0xAB9423A7); b=II(b,c,d,a,x[k+5], S44,0xFC93A039);
            a=II(a,b,c,d,x[k+12],S41,0x655B59C3); d=II(d,a,b,c,x[k+3], S42,0x8F0CCC92);  c=II(c,d,a,b,x[k+10],S43,0xFFEFF47D); b=II(b,c,d,a,x[k+1], S44,0x85845DD1);
            a=II(a,b,c,d,x[k+8], S41,0x6FA87E4F); d=II(d,a,b,c,x[k+15],S42,0xFE2CE6E0); c=II(c,d,a,b,x[k+6], S43,0xA3014314); b=II(b,c,d,a,x[k+13],S44,0x4E0811A1);
            a=II(a,b,c,d,x[k+4], S41,0xF7537E82); d=II(d,a,b,c,x[k+11],S42,0xBD3AF235); c=II(c,d,a,b,x[k+2], S43,0x2AD7D2BB); b=II(b,c,d,a,x[k+9], S44,0xEB86D391);
            a=AddUnsigned(a,AA); b=AddUnsigned(b,BB); c=AddUnsigned(c,CC); d=AddUnsigned(d,DD);
        }
        var temp = WordToHex(a)+WordToHex(b)+WordToHex(c)+WordToHex(d);
        return temp.toLowerCase();
    }
});
