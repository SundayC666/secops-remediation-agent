/**
 * Main application logic
 * Handles tab switching and common UI functions
 */

// ============================================
// Welcome Overlay Controller
// ============================================
const WelcomeOverlay = {
    overlay: null,
    steps: {},
    progress: null,
    bubble: null,
    currentStep: 0,
    totalSteps: 3,
    floatingBubbles: [],
    bubbleInterval: null,

    init() {
        this.overlay = document.getElementById('welcome-overlay');
        this.steps = {
            detect: document.getElementById('step-detect'),
            fetch: document.getElementById('step-fetch'),
            analyze: document.getElementById('step-analyze')
        };
        this.bubble = document.getElementById('welcome-bubble');
        this.progress = document.getElementById('welcome-progress-fill');
        this.fullscreenParticles = document.getElementById('fullscreen-particles');
        this.bubbleContainer = this.overlay;

        // Start floating bubbles animation on welcome screen
        this.startBubbleSpawning();
    },

    // Create a floating bubble from bottom of screen
    createFloatingBubble() {
        if (!this.bubbleContainer) return;

        const bubble = document.createElement('div');
        bubble.className = 'floating-bubble';

        // Random size (varied sizes for natural look)
        const size = 8 + Math.random() * 40;
        bubble.style.width = `${size}px`;
        bubble.style.height = `${size}px`;

        // Random horizontal position across full screen width
        const x = Math.random() * window.innerWidth;
        bubble.style.left = `${x}px`;
        bubble.style.bottom = '-50px';

        // Random animation duration (slower for bigger bubbles)
        const duration = 3 + Math.random() * 4;
        bubble.style.animationDuration = `${duration}s`;

        // Random horizontal drift
        const drift = (Math.random() - 0.5) * 100;
        bubble.style.setProperty('--drift', `${drift}px`);

        this.bubbleContainer.appendChild(bubble);
        this.floatingBubbles.push(bubble);

        // Remove after animation
        setTimeout(() => {
            if (bubble.parentNode) bubble.remove();
            const idx = this.floatingBubbles.indexOf(bubble);
            if (idx > -1) this.floatingBubbles.splice(idx, 1);
        }, duration * 1000);
    },

    startBubbleSpawning() {
        const spawn = () => {
            this.createFloatingBubble();
            // Spawn faster as progress increases
            const progress = this.currentStep / this.totalSteps;
            const interval = 600 - (progress * 400); // 600ms -> 200ms
            this.bubbleInterval = setTimeout(spawn, interval);
        };
        spawn();
    },

    stopBubbleSpawning() {
        if (this.bubbleInterval) {
            clearTimeout(this.bubbleInterval);
            this.bubbleInterval = null;
        }
    },

    updateStep(stepName, status, detail = '') {
        const step = this.steps[stepName];
        if (!step) return;

        const statusIcon = step.querySelector('.step-status i');
        const detailSpan = document.getElementById(`${stepName}-detail`);

        // Update detail text
        if (detailSpan && detail) {
            detailSpan.textContent = detail;
        }

        // Update step status
        step.classList.remove('active', 'completed');

        if (status === 'active') {
            step.classList.add('active');
            statusIcon.className = 'fas fa-spinner fa-spin';
            statusIcon.style.opacity = '1';
        } else if (status === 'completed') {
            step.classList.add('completed');
            statusIcon.className = 'fas fa-check';
            statusIcon.style.opacity = '1';
            this.currentStep++;
            this.updateProgress();
            this.updateBubble();
        } else if (status === 'pending') {
            statusIcon.className = 'fas fa-circle';
            statusIcon.style.opacity = '0.3';
        }
    },

    updateProgress() {
        const percent = (this.currentStep / this.totalSteps) * 100;
        if (this.progress) {
            this.progress.style.width = `${percent}%`;
        }
    },

    updateBubble() {
        const percent = Math.round((this.currentStep / this.totalSteps) * 100);
        const bubbleContainer = document.getElementById('bubble-container');

        if (this.bubble && bubbleContainer) {
            // Move bubble container to follow progress
            bubbleContainer.style.left = `${percent}%`;

            // Calculate bubble size (24px at 0% to 40px at 100%)
            const minSize = 24;
            const maxSize = 40;
            const size = minSize + (maxSize - minSize) * (percent / 100);

            this.bubble.style.width = `${size}px`;
            this.bubble.style.height = `${size}px`;

            // Add wobble animation
            this.bubble.classList.add('growing');
            setTimeout(() => {
                this.bubble.classList.remove('growing');
            }, 400);
        }
    },

    popBubble() {
        const particleContainer = this.fullscreenParticles;
        const bubble = this.bubble;

        if (!particleContainer) return;

        // Stop spawning new bubbles
        this.stopBubbleSpawning();

        // Bubble-matching colors (iridescent soap bubble colors)
        const colors = [
            'rgba(245, 162, 110, 0.8)', // Papaya
            'rgba(200, 155, 93, 0.8)',  // Caramel
            'rgba(255, 220, 180, 0.8)', // Cream
            'rgba(255, 255, 255, 0.8)', // White
            'rgba(193, 122, 80, 0.8)',  // Iced coffee
        ];

        // Pop main bubble
        if (bubble) {
            const bubbleRect = bubble.getBoundingClientRect();
            const centerX = bubbleRect.left + bubbleRect.width / 2;
            const centerY = bubbleRect.top + bubbleRect.height / 2;

            bubble.classList.remove('growing');
            bubble.classList.add('popping');

            // Create particles from main bubble
            this.createBubbleParticles(centerX, centerY, 30, colors, particleContainer);
        }

        // Pop all floating bubbles with slight delays
        this.floatingBubbles.forEach((floatingBubble, index) => {
            setTimeout(() => {
                if (floatingBubble && floatingBubble.parentNode) {
                    const rect = floatingBubble.getBoundingClientRect();
                    const x = rect.left + rect.width / 2;
                    const y = rect.top + rect.height / 2;

                    // Create particles for each floating bubble
                    this.createBubbleParticles(x, y, 15, colors, particleContainer);

                    // Remove the bubble
                    floatingBubble.classList.add('popping');
                    setTimeout(() => floatingBubble.remove(), 300);
                }
            }, index * 50); // Stagger the pops
        });

        // Clear floating bubbles array
        this.floatingBubbles = [];

        // Clean up particles after animation
        setTimeout(() => {
            if (particleContainer) {
                particleContainer.innerHTML = '';
            }
        }, 1500);
    },

    createBubbleParticles(centerX, centerY, count, colors, container) {
        for (let i = 0; i < count; i++) {
            const particle = document.createElement('div');
            particle.className = 'explosion-particle';

            const angle = Math.random() * 360;
            const rad = angle * (Math.PI / 180);
            const distance = 50 + Math.random() * 150;
            const tx = Math.cos(rad) * distance;
            const ty = Math.sin(rad) * distance;

            const size = 4 + Math.random() * 10;
            const duration = 0.5 + Math.random() * 0.4;

            particle.style.left = `${centerX}px`;
            particle.style.top = `${centerY}px`;
            particle.style.width = `${size}px`;
            particle.style.height = `${size}px`;
            particle.style.setProperty('--tx', `${tx}px`);
            particle.style.setProperty('--ty', `${ty}px`);
            particle.style.setProperty('--duration', `${duration}s`);
            particle.style.background = colors[Math.floor(Math.random() * colors.length)];
            particle.style.borderRadius = '50%';

            container.appendChild(particle);

            setTimeout(() => {
                particle.classList.add('explode');
            }, Math.random() * 30);
        }
    },

    hide() {
        // Pop the bubble before hiding
        this.popBubble();

        // Wait for pop animation then hide
        setTimeout(() => {
            if (this.overlay) {
                this.overlay.classList.add('hidden');
                // Remove from DOM after animation
                setTimeout(() => {
                    if (this.overlay && this.overlay.parentNode) {
                        this.overlay.style.display = 'none';
                    }
                }, 500);
            }
        }, 350);
    },

    show() {
        if (this.overlay) {
            this.overlay.classList.remove('hidden');
            this.overlay.style.display = 'flex';
        }
    }
};

// Tab switching functionality
function switchTab(tabName) {
    // Remove active class from all tabs
    document.querySelectorAll('.tab-button').forEach(button => {
        button.classList.remove('active');
    });

    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });

    // Add active class to selected tab
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    document.getElementById(`${tabName}-tab`).classList.add('active');
}

// Global variable to store detected OS info for CVE filtering
let detectedOS = null;

// Browser icon mapping
const BROWSER_ICONS = {
    'Chrome': 'fab fa-chrome',
    'Firefox': 'fab fa-firefox-browser',
    'Safari': 'fab fa-safari',
    'Edge': 'fab fa-edge',
    'Opera': 'fab fa-opera',
    'Brave': 'fab fa-brave',
    'Vivaldi': 'fas fa-globe'
};

// Detect user's OS and browser via backend API (reads HTTP User-Agent header)
async function detectUserOS() {
    const osBadge = document.getElementById('os-text');
    const osDetails = document.getElementById('os-details');
    const browserBadge = document.getElementById('browser-badge');
    const browserIcon = document.getElementById('browser-icon');
    const browserText = document.getElementById('browser-text');

    // Update welcome overlay step
    WelcomeOverlay.updateStep('detect', 'active');

    try {
        // Call backend API which reads User-Agent from HTTP header
        const response = await fetch('/api/os/detect');
        if (!response.ok) {
            throw new Error('OS detection failed');
        }

        detectedOS = await response.json();
        osBadge.textContent = detectedOS.normalized;

        // Update welcome overlay with detected system
        const browserInfo = detectedOS.browser?.name ? ` + ${detectedOS.browser.name}` : '';
        WelcomeOverlay.updateStep('detect', 'completed', `${detectedOS.normalized}${browserInfo}`);

        // Update browser badge if browser was detected
        if (detectedOS.browser && detectedOS.browser.name) {
            const browser = detectedOS.browser;
            browserBadge.style.display = 'inline-flex';
            browserText.textContent = browser.version
                ? `${browser.name} ${browser.version}`
                : browser.name;

            // Set appropriate icon
            const iconClass = BROWSER_ICONS[browser.name] || 'fas fa-globe';
            browserIcon.className = iconClass;

            console.log('Browser detected:', browser);
        }

        // Update tooltip details
        if (osDetails) {
            let browserInfo = '';
            if (detectedOS.browser && detectedOS.browser.name) {
                browserInfo = `
                    <div style="margin-top: 0.5rem;"><strong>Browser:</strong> ${detectedOS.browser.name}${detectedOS.browser.version ? ' ' + detectedOS.browser.version : ''}</div>
                    <div><strong>Engine:</strong> ${detectedOS.browser.engine || 'Unknown'}</div>
                `;
            }

            osDetails.innerHTML = `
                <div><strong>Family:</strong> ${detectedOS.family}</div>
                <div><strong>Version:</strong> ${detectedOS.version || 'Not detected'}</div>
                ${browserInfo}
                <div style="margin-top: 0.5rem;"><strong>CVE Tags:</strong></div>
                <div><code>${detectedOS.tags.join('</code>, <code>') || 'none'}</code></div>
            `;
        }

        console.log('OS detected from HTTP header:', detectedOS);
    } catch (error) {
        console.error('OS detection error:', error);
        osBadge.textContent = 'Unknown';
        detectedOS = { family: 'Unknown', version: null, normalized: 'Unknown', tags: [] };

        // Still mark as completed even on error
        WelcomeOverlay.updateStep('detect', 'completed', 'Unknown system');

        if (osDetails) {
            osDetails.innerHTML = `
                <div style="color: var(--critical);">Unable to detect system.</div>
                <div>All vulnerabilities will be shown.</div>
            `;
        }
    }

    return detectedOS;
}

// Load quick search buttons dynamically from API
async function loadQuickButtons() {
    const container = document.getElementById('quick-buttons-container');
    if (!container) return;

    try {
        const response = await fetch('/api/versions/buttons');
        if (!response.ok) throw new Error('Failed to load versions');

        const data = await response.json();
        const buttons = data.buttons || [];

        if (buttons.length === 0) {
            container.innerHTML = '<span class="loading-text">No versions available</span>';
            return;
        }

        // Generate button HTML
        const buttonsHtml = buttons.map(btn => `
            <button class="os-quick-btn ${btn.css_class}" data-query="${btn.query}" onclick="quickOSSearch(this)">
                <i class="${btn.icon}"></i>
                <span>${btn.label}</span>
            </button>
        `).join('');

        container.innerHTML = buttonsHtml;
        console.log(`Loaded ${buttons.length} quick search buttons`);

        // Log cache status
        if (data.cache_status) {
            console.log('Version cache status:', data.cache_status);
        }

    } catch (error) {
        console.error('Failed to load quick buttons:', error);
        // Show fallback buttons
        container.innerHTML = `
            <button class="os-quick-btn macos" data-query="macOS" onclick="quickOSSearch(this)">
                <i class="fab fa-apple"></i>
                <span>macOS</span>
            </button>
            <button class="os-quick-btn windows" data-query="Windows" onclick="quickOSSearch(this)">
                <i class="fab fa-windows"></i>
                <span>Windows</span>
            </button>
            <button class="os-quick-btn linux" data-query="Ubuntu" onclick="quickOSSearch(this)">
                <i class="fab fa-ubuntu"></i>
                <span>Ubuntu</span>
            </button>
            <button class="os-quick-btn ios" data-query="iOS" onclick="quickOSSearch(this)">
                <i class="fab fa-apple"></i>
                <span>iOS</span>
            </button>
            <button class="os-quick-btn android" data-query="Android" onclick="quickOSSearch(this)">
                <i class="fab fa-android"></i>
                <span>Android</span>
            </button>
            <button class="os-quick-btn browser" data-query="Chrome" onclick="quickOSSearch(this)">
                <i class="fab fa-chrome"></i>
                <span>Chrome</span>
            </button>
            <button class="os-quick-btn browser" data-query="Firefox" onclick="quickOSSearch(this)">
                <i class="fab fa-firefox-browser"></i>
                <span>Firefox</span>
            </button>
            <button class="os-quick-btn browser" data-query="Safari" onclick="quickOSSearch(this)">
                <i class="fab fa-safari"></i>
                <span>Safari</span>
            </button>
        `;
    }
}

// Initialize on page load with welcome flow
document.addEventListener('DOMContentLoaded', async () => {
    // Initialize welcome overlay
    WelcomeOverlay.init();

    // Start welcome sequence
    await runWelcomeSequence();

    // Load quick buttons in background
    loadQuickButtons();
});

// Run welcome sequence with loading steps
async function runWelcomeSequence() {
    try {
        // Step 1: Detect OS
        await detectUserOS();

        // Small delay for visual feedback
        await sleep(300);

        // Step 2: Fetch CVE data
        WelcomeOverlay.updateStep('fetch', 'active');

        // Check system health first
        try {
            const healthResponse = await fetch('/api/health');
            if (healthResponse.ok) {
                const health = await healthResponse.json();
                console.log('System health:', health);
            }
        } catch (e) {
            console.warn('Health check failed:', e);
        }

        WelcomeOverlay.updateStep('fetch', 'completed', 'CIRCL CVE database');

        // Small delay
        await sleep(300);

        // Step 3: Analyze vulnerabilities
        WelcomeOverlay.updateStep('analyze', 'active');

        // Trigger CVE loading (skip ocean animation during welcome - no blue burst)
        if (typeof loadLatestCVEs === 'function') {
            await loadLatestCVEs(false, false);
        }

        WelcomeOverlay.updateStep('analyze', 'completed', 'Analysis complete');

        // Small delay before hiding overlay
        await sleep(500);

        // Hide welcome overlay
        WelcomeOverlay.hide();

    } catch (error) {
        console.error('Welcome sequence error:', error);
        // Hide overlay even on error
        WelcomeOverlay.hide();
    }
}

// Helper sleep function
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// File input handling for phishing analyzer
function handleFileSelect(event) {
    const file = event.target.files[0];
    const fileNameSpan = document.getElementById('file-name');
    const analyzeButton = document.getElementById('analyze-phishing-btn');

    if (file) {
        fileNameSpan.textContent = file.name;
        analyzeButton.disabled = false;
    } else {
        fileNameSpan.textContent = 'Choose .eml file or drag here';
        analyzeButton.disabled = true;
    }
}

// Show loading state with underwater bubble animation (borderless)
function showLoading(elementId) {
    const element = document.getElementById(elementId);
    const loadingId = `ocean-loading-${Date.now()}`;

    element.innerHTML = `
        <div class="ocean-loading" id="${loadingId}">
            <div class="ocean-bubbles-area" id="${loadingId}-bubbles"></div>
            <p class="ocean-text">Scanning for vulnerabilities...</p>
        </div>
    `;

    // Start ocean bubble animation
    startOceanAnimation(loadingId);
}

// Show fishing cat loading animation for phishing analyzer
// Loading: Show fishing_underwater.png (fish swimming). 100%: Switch to fishing.png (fish caught)
function showFishingCatLoading(elementId) {
    const element = document.getElementById(elementId);
    const loadingId = `fishing-cat-${Date.now()}`;

    // Design:
    // - Loading: fishing_underwater.png (fish swimming in water) + gentle water shimmer + bubbles
    // - The fish IN THE IMAGE appears to swim via subtle CSS animation
    // - Complete: soft water splash transition -> fishing.png (fish caught)
    element.innerHTML = `
        <div class="fishing-cat-loading" id="${loadingId}">
            <div class="fishing-scene-v2">
                <!-- Loading state: fish swimming underwater (with swimming animation) -->
                <img src="/static/images/fishing_underwater.png" alt="Fish swimming" class="fishing-img fishing-underwater fish-swimming">

                <!-- Underwater bubbles -->
                <div class="underwater-bubbles">
                    <div class="underwater-bubble ub1"></div>
                    <div class="underwater-bubble ub2"></div>
                    <div class="underwater-bubble ub3"></div>
                    <div class="underwater-bubble ub4"></div>
                    <div class="underwater-bubble ub5"></div>
                    <div class="underwater-bubble ub6"></div>
                    <div class="underwater-bubble ub7"></div>
                    <div class="underwater-bubble ub8"></div>
                </div>

                <!-- Gentle water shimmer for loading state -->
                <div class="water-waves-overlay">
                    <div class="water-wave w1"></div>
                    <div class="water-wave w2"></div>
                    <div class="water-wave w3"></div>
                </div>

                <!-- Water splash transition (soft, illustration style) -->
                <div class="water-splash-transition">
                    <div class="water-surge"></div>
                    <div class="water-droplet d1"></div>
                    <div class="water-droplet d2"></div>
                    <div class="water-droplet d3"></div>
                    <div class="water-droplet d4"></div>
                    <div class="water-droplet d5"></div>
                </div>

                <!-- Complete state: fish caught (hidden initially) -->
                <img src="/static/images/fishing.png" alt="Cat caught fish" class="fishing-img fishing-caught">
            </div>
        </div>
    `;

    // Start fishing animation progress (internal tracking)
    startFishingProgress(loadingId);
}

// Start fishing progress animation (internal tracking, no visible progress bar)
function startFishingProgress(loadingId) {
    const container = document.getElementById(loadingId);
    if (!container) return;

    // Just store the container for later completion
    container.dataset.started = 'true';
}

// Complete fishing animation (cat catches fish!)
function completeFishingAnimation(elementId) {
    const container = document.querySelector(`#${elementId} .fishing-cat-loading`);
    if (!container) return;

    // Trigger fish caught animation
    container.classList.add('fish-caught');
}

// Ocean bubble animation controller (borderless)
function startOceanAnimation(loadingId) {
    const bubblesArea = document.getElementById(`${loadingId}-bubbles`);
    if (!bubblesArea) {
        console.warn('Ocean animation: bubbles area not found');
        return;
    }

    const bubbles = [];

    // Create bubbles continuously
    const createBubble = () => {
        const bubble = document.createElement('div');
        bubble.className = 'ocean-bubble';

        // Random size (8-30px for better visibility)
        const size = 8 + Math.random() * 22;
        bubble.style.width = `${size}px`;
        bubble.style.height = `${size}px`;

        // Random horizontal position across the loading area
        const x = 5 + Math.random() * 90; // 5% to 95% width
        bubble.style.left = `${x}%`;

        // Animation duration based on size (smaller = faster, 2.5-5s range)
        const duration = 2.5 + (size / 30) * 2.5;
        bubble.style.animationDuration = `${duration}s`;

        // Random wobble for natural movement
        const wobble = (Math.random() - 0.5) * 50;
        bubble.style.setProperty('--wobble', `${wobble}px`);

        bubblesArea.appendChild(bubble);
        bubbles.push(bubble);

        // Remove after animation
        setTimeout(() => {
            if (bubble.parentNode) bubble.remove();
            const idx = bubbles.indexOf(bubble);
            if (idx > -1) bubbles.splice(idx, 1);
        }, duration * 1000);
    };

    // Create initial batch of bubbles immediately for instant visibility
    for (let i = 0; i < 8; i++) {
        setTimeout(() => createBubble(), i * 50);
    }

    // Spawn bubbles at intervals
    const spawnInterval = setInterval(() => {
        createBubble();
        // Occasionally create multiple bubbles at once
        if (Math.random() > 0.5) createBubble();
        if (Math.random() > 0.75) createBubble();
    }, 150);

    // Store for cleanup
    bubblesArea.dataset.intervalId = spawnInterval;
}

// Complete ocean animation - each bubble bursts individually
function completeBalloonAnimation(elementId) {
    const loadingContainer = document.querySelector(`#${elementId} .ocean-loading`);

    if (!loadingContainer) {
        return;
    }

    const bubblesArea = loadingContainer.querySelector('.ocean-bubbles-area');

    // Clear spawn interval first
    if (bubblesArea && bubblesArea.dataset.intervalId) {
        clearInterval(parseInt(bubblesArea.dataset.intervalId));
    }

    // Get all existing bubbles and make each one burst
    if (bubblesArea) {
        const bubbles = bubblesArea.querySelectorAll('.ocean-bubble');
        bubbles.forEach((bubble, index) => {
            // Stagger the bursts for a cascading effect
            setTimeout(() => {
                const rect = bubble.getBoundingClientRect();
                const centerX = rect.left + rect.width / 2;
                const centerY = rect.top + rect.height / 2;

                // Create small burst at each bubble's position
                createSingleBubbleBurst(centerX, centerY, rect.width);

                // Remove the original bubble
                bubble.remove();
            }, index * 30);
        });
    }
}

// Create burst effect for a single bubble
function createSingleBubbleBurst(centerX, centerY, originalSize) {
    const colors = [
        'rgba(135, 206, 235, 0.85)', // Sky blue
        'rgba(176, 224, 230, 0.8)',  // Powder blue
        'rgba(173, 216, 230, 0.75)', // Light blue
        'rgba(255, 255, 255, 0.9)',  // White highlight
        'rgba(64, 224, 208, 0.7)',   // Turquoise
    ];

    // Number of particles based on bubble size
    const particleCount = Math.max(5, Math.floor(originalSize / 3));

    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.className = 'burst-bubble';

        const angle = (i / particleCount) * 360 + Math.random() * 30;
        const rad = angle * (Math.PI / 180);
        const distance = 20 + Math.random() * 40;
        const tx = Math.cos(rad) * distance;
        const ty = Math.sin(rad) * distance;

        const size = 3 + Math.random() * 6;
        const duration = 0.3 + Math.random() * 0.3;

        particle.style.cssText = `
            position: fixed;
            left: ${centerX}px;
            top: ${centerY}px;
            width: ${size}px;
            height: ${size}px;
            background: ${colors[Math.floor(Math.random() * colors.length)]};
            border-radius: 50%;
            pointer-events: none;
            z-index: 10002;
            box-shadow: inset -1px -1px 3px rgba(255,255,255,0.5), 0 0 4px rgba(135,206,235,0.4);
        `;

        particle.style.setProperty('--tx', `${tx}px`);
        particle.style.setProperty('--ty', `${ty}px`);

        document.body.appendChild(particle);

        requestAnimationFrame(() => {
            particle.style.animation = `bubbleBurst ${duration}s ease-out forwards`;
        });

        setTimeout(() => particle.remove(), duration * 1000 + 50);
    }
}

// Create bubble burst effect (bubbles scatter outward)
function createBubbleBurst(centerX, centerY) {
    const colors = [
        'rgba(135, 206, 235, 0.8)', // Sky blue
        'rgba(176, 224, 230, 0.8)', // Powder blue
        'rgba(173, 216, 230, 0.7)', // Light blue
        'rgba(255, 255, 255, 0.9)', // White
        'rgba(64, 224, 208, 0.6)',  // Turquoise
        'rgba(127, 255, 212, 0.5)', // Aquamarine
    ];

    // Create burst bubbles
    for (let i = 0; i < 25; i++) {
        const bubble = document.createElement('div');
        bubble.className = 'burst-bubble';

        const angle = (i / 25) * 360 + Math.random() * 20;
        const rad = angle * (Math.PI / 180);
        const distance = 60 + Math.random() * 120;
        const tx = Math.cos(rad) * distance;
        const ty = Math.sin(rad) * distance;

        const size = 8 + Math.random() * 16;
        const duration = 0.6 + Math.random() * 0.4;

        bubble.style.cssText = `
            position: fixed;
            left: ${centerX}px;
            top: ${centerY}px;
            width: ${size}px;
            height: ${size}px;
            background: ${colors[Math.floor(Math.random() * colors.length)]};
            border-radius: 50%;
            pointer-events: none;
            z-index: 10002;
            box-shadow: inset -2px -2px 4px rgba(255,255,255,0.4), 0 0 8px rgba(255,255,255,0.3);
        `;

        bubble.style.setProperty('--tx', `${tx}px`);
        bubble.style.setProperty('--ty', `${ty}px`);

        document.body.appendChild(bubble);

        requestAnimationFrame(() => {
            bubble.style.animation = `bubbleBurst ${duration}s ease-out forwards`;
        });

        // Remove bubble after animation
        setTimeout(() => bubble.remove(), duration * 1000 + 100);
    }
}

// Legacy confetti function (kept for compatibility)
function createConfetti(centerX, centerY) {
    createBubbleBurst(centerX, centerY);
}

// Show error message
function showError(elementId, message) {
    const element = document.getElementById(elementId);

    // Convert technical errors to user-friendly messages
    let userMessage = message;
    let title = "Oops!";

    if (message.includes("HTTP error 500") || message.includes("Internal Server Error")) {
        userMessage = "Something went wrong on our end. Please try again in a moment.";
        title = "Server Error";
    } else if (message.includes("HTTP error 503") || message.includes("Service Unavailable")) {
        userMessage = "The service is temporarily unavailable. Please try again shortly.";
        title = "Service Unavailable";
    } else if (message.includes("HTTP error 404")) {
        userMessage = "The requested resource was not found.";
        title = "Not Found";
    } else if (message.includes("Failed to fetch") || message.includes("NetworkError")) {
        userMessage = "Unable to connect to the server. Please check your internet connection.";
        title = "Connection Error";
    } else if (message.includes("timeout") || message.includes("Timeout")) {
        userMessage = "The request took too long. Please try again.";
        title = "Request Timeout";
    }

    element.innerHTML = `
        <div class="card" style="border-left: 4px solid var(--medium);">
            <div class="card-body" style="text-align: center; padding: 2rem;">
                <div style="font-size: 2.5rem; margin-bottom: 1rem;">😕</div>
                <h3 style="color: var(--text-primary); margin-bottom: 0.5rem;">${title}</h3>
                <p style="color: var(--text-secondary); margin-bottom: 1rem;">${userMessage}</p>
                <button onclick="location.reload()" class="btn-secondary" style="padding: 0.5rem 1.5rem; border-radius: 20px; border: 1px solid var(--atmos-gray); background: var(--pure-white); cursor: pointer;">
                    <i class="fas fa-redo" style="margin-right: 0.5rem;"></i>Try Again
                </button>
            </div>
        </div>
    `;
}

// ============================================
// Interactive Click Animations
// ============================================

// Particle colors from our palette (for Quick Search buttons)
const PARTICLE_COLORS = [
    '#F5A26E', // Papaya
    '#E56B7A', // Pink Lemonade
    '#C89B5D', // Iced Coffee
    '#D19C4E', // Mango Mojito
    '#C17A50', // Caramel
    '#8B9075', // Tea
];

// Different colors for Analyze button (cooler tones - teal/blue/purple)
const ANALYZE_PARTICLE_COLORS = [
    '#5B8C85', // Teal
    '#7B68EE', // Medium Slate Blue
    '#9370DB', // Medium Purple
    '#6A5ACD', // Slate Blue
    '#48D1CC', // Medium Turquoise
    '#20B2AA', // Light Sea Green
];

/**
 * Create particle explosion effect at given position
 * @param {number} x - X coordinate
 * @param {number} y - Y coordinate
 * @param {number} particleCount - Number of particles (default 20)
 * @param {Array} colors - Color array to use (default PARTICLE_COLORS)
 */
function createParticleExplosion(x, y, particleCount = 20, colors = PARTICLE_COLORS) {
    const container = document.createElement('div');
    container.className = 'particle-container';
    document.body.appendChild(container);

    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';

        // Random shape (circle is default, so no class needed)
        const shapes = ['circle', 'square'];
        const shape = shapes[Math.floor(Math.random() * shapes.length)];
        if (shape !== 'circle') {
            particle.classList.add(shape);
        }

        // Random color from provided color array
        const color = colors[Math.floor(Math.random() * colors.length)];
        particle.style.backgroundColor = color;

        // Random direction and distance
        const angle = (Math.PI * 2 * i) / particleCount + (Math.random() - 0.5);
        const distance = 80 + Math.random() * 120;
        const tx = Math.cos(angle) * distance;
        const ty = Math.sin(angle) * distance;

        particle.style.setProperty('--tx', `${tx}px`);
        particle.style.setProperty('--ty', `${ty}px`);
        particle.style.left = `${x}px`;
        particle.style.top = `${y}px`;

        // Random size
        const size = 6 + Math.random() * 10;
        particle.style.width = `${size}px`;
        particle.style.height = `${size}px`;

        // Random delay
        particle.style.animationDelay = `${Math.random() * 0.1}s`;

        container.appendChild(particle);
    }

    // Remove container after animation
    setTimeout(() => container.remove(), 1000);
}

/**
 * Create flying text that moves to search input
 */
function createFlyingText(text, startX, startY) {
    const queryInput = document.getElementById('cve-query');
    const inputRect = queryInput.getBoundingClientRect();

    const flyingText = document.createElement('div');
    flyingText.className = 'flying-text';
    flyingText.textContent = text;
    flyingText.style.left = `${startX}px`;
    flyingText.style.top = `${startY}px`;

    // Calculate end position (center of input)
    const endX = inputRect.left + inputRect.width / 2;
    const endY = inputRect.top + inputRect.height / 2;

    document.body.appendChild(flyingText);

    // Animate to search box using Web Animations API
    const animation = flyingText.animate([
        {
            left: `${startX}px`,
            top: `${startY}px`,
            transform: 'scale(1)',
            opacity: 1
        },
        {
            left: `${endX}px`,
            top: `${endY}px`,
            transform: 'scale(0.3)',
            opacity: 0
        }
    ], {
        duration: 500,
        easing: 'cubic-bezier(0.25, 0.46, 0.45, 0.94)'
    });

    animation.onfinish = () => {
        flyingText.remove();
        // Highlight input when text arrives
        queryInput.classList.add('highlight');
        setTimeout(() => queryInput.classList.remove('highlight'), 600);
    };
}

/**
 * Add ripple effect to button
 */
function addRipple(button, event) {
    const rect = button.getBoundingClientRect();
    const ripple = document.createElement('span');
    ripple.className = 'ripple';

    const size = Math.max(rect.width, rect.height);
    ripple.style.width = ripple.style.height = `${size}px`;
    ripple.style.left = `${event.clientX - rect.left - size / 2}px`;
    ripple.style.top = `${event.clientY - rect.top - size / 2}px`;

    button.appendChild(ripple);
    setTimeout(() => ripple.remove(), 600);
}

/**
 * OS Quick Search with animation
 */
function quickOSSearch(button) {
    const query = button.dataset.query;
    const queryInput = document.getElementById('cve-query');

    if (!query || !queryInput) {
        console.error('quickOSSearch: Missing query or input element');
        return;
    }

    console.log('quickOSSearch triggered:', query);

    // Get button position for effects
    const rect = button.getBoundingClientRect();
    const centerX = rect.left + rect.width / 2;
    const centerY = rect.top + rect.height / 2;

    // Add click animation class
    button.classList.add('clicked');
    setTimeout(() => button.classList.remove('clicked'), 300);

    // Create particle explosion (more visible)
    createParticleExplosion(centerX, centerY, 25);

    // Set query value immediately
    queryInput.value = query;
    queryInput.focus();

    // Highlight input
    queryInput.classList.add('highlight');
    setTimeout(() => queryInput.classList.remove('highlight'), 600);

    // Trigger search immediately
    console.log('Calling analyzeCVEs with query:', queryInput.value);
    if (typeof analyzeCVEs === 'function') {
        analyzeCVEs();
    } else {
        console.error('analyzeCVEs function not found');
    }
}

/**
 * Enhanced analyze button click
 * Uses different particle colors than Quick Search buttons (cooler tones)
 */
function enhanceAnalyzeButton() {
    const analyzeBtn = document.getElementById('analyze-btn');
    if (!analyzeBtn) return;

    analyzeBtn.addEventListener('click', function(e) {
        // Add ripple
        addRipple(this, e);

        // Get button position
        const rect = this.getBoundingClientRect();
        const centerX = rect.left + rect.width / 2;
        const centerY = rect.top + rect.height / 2;

        // Particle burst with DIFFERENT colors (teal/blue/purple)
        createParticleExplosion(centerX, centerY, 12, ANALYZE_PARTICLE_COLORS);

        // Add burst animation class
        this.classList.add('burst');
        setTimeout(() => this.classList.remove('burst'), 600);
    });
}

/**
 * Add magnetic effect to OS buttons
 */
function addMagneticEffect() {
    const buttons = document.querySelectorAll('.os-quick-btn');

    buttons.forEach(button => {
        button.addEventListener('mousemove', (e) => {
            const rect = button.getBoundingClientRect();
            const x = e.clientX - rect.left - rect.width / 2;
            const y = e.clientY - rect.top - rect.height / 2;

            button.style.transform = `translate(${x * 0.1}px, ${y * 0.1}px)`;
        });

        button.addEventListener('mouseleave', () => {
            button.style.transform = '';
        });
    });
}

/**
 * Show success animation
 */
function showSuccessAnimation(x, y) {
    const check = document.createElement('div');
    check.className = 'success-check';
    check.innerHTML = '<i class="fas fa-check"></i>';
    check.style.left = `${x - 30}px`;
    check.style.top = `${y - 30}px`;

    document.body.appendChild(check);

    setTimeout(() => {
        check.style.opacity = '0';
        check.style.transform = 'scale(1.5)';
        check.style.transition = 'all 0.3s ease-out';
        setTimeout(() => check.remove(), 300);
    }, 800);
}

/**
 * Create confetti burst
 */
function createConfetti(x, y, count = 30) {
    const container = document.createElement('div');
    container.className = 'confetti';
    container.style.left = `${x}px`;
    container.style.top = `${y}px`;

    for (let i = 0; i < count; i++) {
        const piece = document.createElement('div');
        piece.className = 'confetti-piece';
        piece.style.backgroundColor = PARTICLE_COLORS[Math.floor(Math.random() * PARTICLE_COLORS.length)];
        piece.style.left = `${(Math.random() - 0.5) * 100}px`;
        piece.style.setProperty('--fall-distance', `${200 + Math.random() * 300}px`);
        piece.style.setProperty('--rotation', `${Math.random() * 1440}deg`);
        piece.style.setProperty('--fall-duration', `${1 + Math.random() * 2}s`);
        piece.style.animationDelay = `${Math.random() * 0.3}s`;

        container.appendChild(piece);
    }

    document.body.appendChild(container);
    setTimeout(() => container.remove(), 3500);
}

// Initialize animations on page load
document.addEventListener('DOMContentLoaded', () => {
    enhanceAnalyzeButton();
    addMagneticEffect();

    // Add hover sound effect simulation (visual feedback)
    document.querySelectorAll('.os-quick-btn').forEach(btn => {
        btn.addEventListener('mouseenter', () => {
            btn.style.transition = 'all 0.2s cubic-bezier(0.68, -0.55, 0.265, 1.55)';
        });
    });
});
