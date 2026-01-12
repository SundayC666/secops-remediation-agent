/**
 * CVE Analyzer
 * Handles vulnerability analysis queries and result rendering
 */

// ============================================
// Vendor Security Pages - Official update links
// ============================================
const VENDOR_SECURITY_LINKS = {
    // Browsers
    'chrome': { name: 'Google Chrome', url: 'https://chromereleases.googleblog.com/' },
    'chromium': { name: 'Chromium', url: 'https://chromereleases.googleblog.com/' },
    'firefox': { name: 'Mozilla Firefox', url: 'https://www.mozilla.org/en-US/security/advisories/' },
    'safari': { name: 'Apple Safari', url: 'https://support.apple.com/en-us/HT201222' },
    'edge': { name: 'Microsoft Edge', url: 'https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security' },

    // Operating Systems
    'windows': { name: 'Microsoft Windows', url: 'https://msrc.microsoft.com/update-guide/vulnerability' },
    'macos': { name: 'Apple macOS', url: 'https://support.apple.com/en-us/HT201222' },
    'ios': { name: 'Apple iOS', url: 'https://support.apple.com/en-us/HT201222' },
    'ipados': { name: 'Apple iPadOS', url: 'https://support.apple.com/en-us/HT201222' },
    'android': { name: 'Android', url: 'https://source.android.com/docs/security/bulletin' },
    'linux': { name: 'Linux Kernel', url: 'https://www.kernel.org/' },
    'ubuntu': { name: 'Ubuntu', url: 'https://ubuntu.com/security/notices' },

    // Software
    'adobe': { name: 'Adobe', url: 'https://helpx.adobe.com/security.html' },
    'acrobat': { name: 'Adobe Acrobat', url: 'https://helpx.adobe.com/security/products/acrobat.html' },
    'office': { name: 'Microsoft Office', url: 'https://msrc.microsoft.com/update-guide/vulnerability' },
    'exchange': { name: 'Microsoft Exchange', url: 'https://msrc.microsoft.com/update-guide/vulnerability' },

    // Default vendors
    'microsoft': { name: 'Microsoft', url: 'https://msrc.microsoft.com/update-guide/vulnerability' },
    'apple': { name: 'Apple', url: 'https://support.apple.com/en-us/HT201222' },
    'google': { name: 'Google', url: 'https://chromereleases.googleblog.com/' },
    'mozilla': { name: 'Mozilla', url: 'https://www.mozilla.org/en-US/security/advisories/' },
};

/**
 * Get vendor security link based on CVE tags or description
 */
function getVendorSecurityLink(finding) {
    // Check tags first
    if (finding.os_tags) {
        for (const tag of finding.os_tags) {
            const key = tag.toLowerCase();
            if (VENDOR_SECURITY_LINKS[key]) {
                return VENDOR_SECURITY_LINKS[key];
            }
        }
    }

    // Check title/description for keywords
    const text = ((finding.title || '') + ' ' + (finding.description || '')).toLowerCase();

    for (const [keyword, info] of Object.entries(VENDOR_SECURITY_LINKS)) {
        if (text.includes(keyword)) {
            return info;
        }
    }

    return null;
}

// ============================================
// Recent Searches - localStorage management
// ============================================
const RECENT_SEARCHES_KEY = 'secops_recent_searches';
const MAX_RECENT_SEARCHES = 5;

// Particle colors for recent search clicks (green/sage tones)
const RECENT_SEARCH_PARTICLE_COLORS = [
    '#8B9075', // Tea
    '#7AA885', // Sage green
    '#6B8E6B', // Medium green
    '#A08068', // Cocoa creme
    '#9CAF88', // Light sage
    '#7D8B6A', // Olive
];

/**
 * Load recent searches from localStorage
 */
function loadRecentSearches() {
    try {
        const data = localStorage.getItem(RECENT_SEARCHES_KEY);
        return data ? JSON.parse(data) : [];
    } catch (e) {
        console.error('Failed to load recent searches:', e);
        return [];
    }
}

/**
 * Save recent searches to localStorage
 */
function saveRecentSearches(searches) {
    try {
        localStorage.setItem(RECENT_SEARCHES_KEY, JSON.stringify(searches));
    } catch (e) {
        console.error('Failed to save recent searches:', e);
    }
}

/**
 * Add a search term to recent searches
 */
function addToRecentSearches(query) {
    if (!query || query.trim().length < 2) return;

    const searches = loadRecentSearches();
    const normalizedQuery = query.trim();

    // Remove if already exists (to move to front)
    const filtered = searches.filter(s => s.toLowerCase() !== normalizedQuery.toLowerCase());

    // Add to front
    filtered.unshift(normalizedQuery);

    // Keep only MAX_RECENT_SEARCHES
    const limited = filtered.slice(0, MAX_RECENT_SEARCHES);

    saveRecentSearches(limited);
    renderRecentSearches();
}

/**
 * Clear all recent searches
 */
function clearRecentSearches() {
    saveRecentSearches([]);
    renderRecentSearches();
}

/**
 * Render recent searches UI
 */
function renderRecentSearches() {
    const container = document.getElementById('recent-searches');
    const list = document.getElementById('recent-searches-list');

    if (!container || !list) return;

    const searches = loadRecentSearches();

    if (searches.length === 0) {
        container.style.display = 'none';
        return;
    }

    container.style.display = 'flex';

    list.innerHTML = searches.map(search => `
        <span class="recent-search-item" onclick="searchFromRecent('${search.replace(/'/g, "\\'")}', event)" title="${search}">
            ${search}
        </span>
    `).join('');
}

/**
 * Search from recent search item click
 */
function searchFromRecent(query, event) {
    // Create particle explosion with different colors
    if (event && typeof createParticleExplosion === 'function') {
        const rect = event.target.getBoundingClientRect();
        const centerX = rect.left + rect.width / 2;
        const centerY = rect.top + rect.height / 2;
        createParticleExplosion(centerX, centerY, 10, RECENT_SEARCH_PARTICLE_COLORS);
    }

    // Set query and search
    const queryInput = document.getElementById('cve-query');
    if (queryInput) {
        queryInput.value = query;
    }
    analyzeCVEs();
}

// Initialize recent searches on page load
document.addEventListener('DOMContentLoaded', () => {
    renderRecentSearches();
});

// Check system initialization status
async function checkSystemStatus() {
    try {
        const response = await fetch('/api/status');
        if (response.ok) {
            return await response.json();
        }
    } catch (e) {
        console.error('Status check failed:', e);
    }
    return { rag_ready: false, rag_initializing: false, cve_count: 0 };
}

// Show initializing message
function showInitializing(elementId) {
    const element = document.getElementById(elementId);
    element.innerHTML = `
        <div class="card">
            <div class="card-body text-center">
                <div class="loading" style="margin: 2rem auto;"></div>
                <p style="color: var(--text-primary); margin-top: 1rem; font-weight: 500;">
                    System Initializing
                </p>
                <p style="color: var(--text-secondary); font-size: 0.9rem;">
                    Loading CVE database and AI models...<br>
                    This may take 1-2 minutes on first startup.
                </p>
            </div>
        </div>
    `;
}

// Load latest CVEs automatically on page load
// Set to false to not auto-load CVEs on page load (show empty state instead)
async function loadLatestCVEs(showEmptyOnNoResults = true) {
    const resultsDiv = document.getElementById('cve-results');

    // Check if system is ready
    const status = await checkSystemStatus();
    if (!status.rag_ready) {
        if (status.rag_initializing) {
            showInitializing('cve-results');
            pollUntilReadyThenLoad();
            return;
        } else if (status.error) {
            showError('cve-results', `System error: ${status.error}`);
            return;
        }
    }

    // Show loading state
    showLoading('cve-results');

    try {
        const response = await fetch('/api/cve/latest?limit=5');

        if (response.status === 503) {
            showInitializing('cve-results');
            pollUntilReadyThenLoad();
            return;
        }

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.detail || `HTTP error ${response.status}`);
        }

        const data = await response.json();
        renderCVEResults(data, showEmptyOnNoResults);
    } catch (error) {
        console.error('Failed to load CVEs:', error);
        // On initial load, don't show error - just leave empty
        if (showEmptyOnNoResults) {
            showError('cve-results', `Failed to load vulnerabilities: ${error.message}`);
        } else {
            resultsDiv.innerHTML = '';
        }
    }
}

/**
 * Sanitize user input to prevent XSS and injection attacks
 * Client-side validation (server also validates)
 */
function sanitizeInput(input) {
    if (!input) return '';

    // Remove potential script tags and event handlers
    let sanitized = input
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/on\w+\s*=/gi, '')
        .replace(/<[^>]*>/g, '')  // Remove HTML tags
        .replace(/javascript:/gi, '')
        .replace(/vbscript:/gi, '')
        .replace(/data:/gi, '');

    // Limit length
    if (sanitized.length > 200) {
        sanitized = sanitized.substring(0, 200);
    }

    return sanitized.trim();
}

/**
 * Validate query input
 * Returns error message if invalid, null if valid
 */
function validateQuery(query) {
    if (!query || query.length < 2) {
        return null; // Empty is allowed (loads latest)
    }

    if (query.length > 200) {
        return 'Query is too long (max 200 characters)';
    }

    // Check for suspicious patterns
    const dangerousPatterns = [
        /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b)/i,
        /(--|\/\*|\*\/)/,
        /(<\s*script|javascript:|on\w+\s*=)/i,
        /(\||\$\(|`|;(?!\s*$))/
    ];

    for (const pattern of dangerousPatterns) {
        if (pattern.test(query)) {
            return 'Invalid characters in query';
        }
    }

    return null;
}

// Analyze CVEs based on user query
async function analyzeCVEs() {
    const queryInput = document.getElementById('cve-query');
    let query = queryInput.value.trim();
    const resultsDiv = document.getElementById('cve-results');

    // Sanitize input
    query = sanitizeInput(query);
    queryInput.value = query; // Update input with sanitized value

    // Validate input
    const validationError = validateQuery(query);
    if (validationError) {
        showError('cve-results', validationError);
        return;
    }

    if (!query) {
        // If no query, just load latest
        loadLatestCVEs();
        return;
    }

    // Check if system is ready
    const status = await checkSystemStatus();
    if (!status.rag_ready) {
        if (status.rag_initializing) {
            showInitializing('cve-results');
            pollUntilReady(query);
            return;
        } else if (status.error) {
            showError('cve-results', `System error: ${status.error}`);
            return;
        }
    }

    // Show loading state
    showLoading('cve-results');

    try {
        const response = await fetch('/api/cve/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ query: query, limit: 5 })
        });

        if (response.status === 503) {
            showInitializing('cve-results');
            pollUntilReady(query);
            return;
        }

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.detail || `HTTP error ${response.status}`);
        }

        const data = await response.json();
        renderCVEResults(data);

        // Save to recent searches on successful search
        addToRecentSearches(query);
    } catch (error) {
        console.error('CVE analysis failed:', error);
        showError('cve-results', `Analysis failed: ${error.message}`);
    }
}

// Poll until system is ready, then load latest CVEs
async function pollUntilReadyThenLoad() {
    const maxAttempts = 60;
    let attempts = 0;

    const poll = async () => {
        attempts++;
        const status = await checkSystemStatus();

        if (status.rag_ready) {
            loadLatestCVEs();
        } else if (status.error) {
            showError('cve-results', `Initialization failed: ${status.error}`);
        } else if (attempts < maxAttempts) {
            const element = document.getElementById('cve-results');
            if (element && status.cve_count > 0) {
                const progressP = element.querySelector('p:last-child');
                if (progressP) {
                    progressP.innerHTML = `
                        Loading CVE database and AI models...<br>
                        Progress: ${status.cve_count} CVEs indexed
                    `;
                }
            }
            setTimeout(poll, 2000);
        } else {
            showError('cve-results', 'Initialization timed out. Please refresh the page.');
        }
    };

    setTimeout(poll, 2000);
}

// Poll until system is ready, then run the query
async function pollUntilReady(query) {
    const maxAttempts = 60;
    let attempts = 0;

    const poll = async () => {
        attempts++;
        const status = await checkSystemStatus();

        if (status.rag_ready) {
            document.getElementById('cve-query').value = query;
            analyzeCVEs();
        } else if (status.error) {
            showError('cve-results', `Initialization failed: ${status.error}`);
        } else if (attempts < maxAttempts) {
            const element = document.getElementById('cve-results');
            if (element && status.cve_count > 0) {
                const progressP = element.querySelector('p:last-child');
                if (progressP) {
                    progressP.innerHTML = `
                        Loading CVE database and AI models...<br>
                        Progress: ${status.cve_count} CVEs indexed
                    `;
                }
            }
            setTimeout(poll, 2000);
        } else {
            showError('cve-results', 'Initialization timed out. Please refresh the page.');
        }
    };

    setTimeout(poll, 2000);
}

// Render CVE analysis results
// showEmptyMessage: if true, show "No vulnerabilities found" when empty; if false, show nothing
function renderCVEResults(data, showEmptyMessage = true) {
    const resultsDiv = document.getElementById('cve-results');

    let html = '';

    // Search description (instead of Detected System which is now in header)
    if (data.search_description) {
        html += `
            <div class="card" style="margin-bottom: 1.5rem; border-left: 4px solid var(--accent-indigo);">
                <div class="card-body" style="padding: 0.75rem 1rem;">
                    <p style="margin: 0; color: var(--text-secondary); font-size: 0.95rem;">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: middle; margin-right: 0.5rem;">
                            <circle cx="11" cy="11" r="8"></circle>
                            <path d="m21 21-4.3-4.3"></path>
                        </svg>
                        ${data.search_description}
                    </p>
                </div>
            </div>
        `;
    }

    // ACTION PLAN AT TOP - Shows specific remediation for ALL CVEs found
    if (data.your_system && data.your_system.action_plan && data.your_system.action_plan.length > 0) {
        html += `
            <div class="card" style="margin-bottom: 1.5rem; background: var(--powder-rose); border: 2px solid var(--accent-rose);">
                <div class="card-body">
                    <h3 style="color: var(--accent-rose); margin-bottom: 0.75rem; display: flex; align-items: center; gap: 0.5rem;">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M9 11l3 3L22 4"></path>
                            <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path>
                        </svg>
                        Remediation Action Plan
                    </h3>
                    <ul style="margin: 0; padding-left: 0; color: var(--text-primary); list-style: none;">
                        ${data.your_system.action_plan.map(step => renderActionPlanItem(step)).join('')}
                    </ul>
                </div>
            </div>
        `;
    }

    // Your System section
    if (data.your_system && data.your_system.findings && data.your_system.findings.length > 0) {
        html += `
            <div class="cve-section your-system" style="margin-bottom: 2rem; border: 2px solid var(--accent-rose); border-radius: 12px; padding: 1.5rem; background: var(--powder-rose);">
                <h2 style="color: var(--accent-rose); margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
                    Vulnerabilities Affecting Your System
                    <span style="font-size: 0.85rem; font-weight: normal; color: var(--text-secondary);">(${data.your_system.findings.length})</span>
                </h2>
        `;

        data.your_system.findings.forEach((finding, index) => {
            html += renderCVECard(finding, true, index);
        });

        html += `</div>`;
    }

    // Other Systems section (at the bottom)
    if (data.other_systems && data.other_systems.findings && data.other_systems.findings.length > 0) {
        html += `
            <div class="cve-section other-systems" style="border: 2px solid var(--atmos-gray); border-radius: 12px; padding: 1.5rem; background: var(--cloud-white); opacity: 0.8;">
                <h2 style="color: var(--text-secondary); margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
                    Other Vulnerabilities
                    <span style="font-size: 0.85rem; font-weight: normal;">(${data.other_systems.findings.length})</span>
                </h2>
        `;

        data.other_systems.findings.forEach((finding, index) => {
            html += renderCVECard(finding, false, index + 100);
        });

        html += `</div>`;
    }

    // No results - only show message if showEmptyMessage is true (i.e., user explicitly searched)
    if ((!data.your_system || !data.your_system.findings || data.your_system.findings.length === 0) &&
        (!data.other_systems || !data.other_systems.findings || data.other_systems.findings.length === 0)) {
        if (showEmptyMessage) {
            // Calculate the search date range (last 5 years)
            const currentYear = new Date().getFullYear();
            const startYear = currentYear - 5;
            html = `
                <div class="card">
                    <div class="card-body text-center">
                        <p style="color: var(--text-secondary); margin-bottom: 8px;">No vulnerabilities found. Your system appears to be up to date.</p>
                        <p style="color: var(--text-muted); font-size: 0.85em;">
                            <i class="fas fa-info-circle"></i>
                            Search range: ${startYear} - ${currentYear} (last 5 years)
                        </p>
                    </div>
                </div>
            `;
        } else {
            // On initial load, don't show anything
            html = '';
        }
    }

    resultsDiv.innerHTML = html;
}

/**
 * Render action plan item with clickable CVE link and colored indicator
 * Uses CSS-styled circles with colors matching the severity badges
 */
function renderActionPlanItem(step) {
    // Extract CVE ID from step (format: "🚨 CVE-XXXX-XXXX: description" or "🔴 CVE-XXXX-XXXX: description")
    const cveMatch = step.match(/CVE-\d{4}-\d+/);
    const cveId = cveMatch ? cveMatch[0] : null;

    // Determine severity color and icon based on emoji prefix
    // Colors match the CSS severity variables (--critical, --high, --medium, --low)
    let indicatorColor = 'var(--low)';  // Gray for low
    let indicatorTitle = 'Low';
    let indicatorIcon = '●';  // Default filled circle

    if (step.includes('🚨')) {
        indicatorColor = 'var(--critical)';  // Red #DC3545
        indicatorTitle = 'Actively Exploited';
        indicatorIcon = '⚠';  // Warning for exploited
    } else if (step.includes('🔴')) {
        indicatorColor = 'var(--critical)';  // Red #DC3545
        indicatorTitle = 'Critical';
    } else if (step.includes('🟠')) {
        indicatorColor = 'var(--high)';  // Orange #E85D04
        indicatorTitle = 'High';
    } else if (step.includes('🟡')) {
        indicatorColor = 'var(--medium)';  // Amber #F4A300
        indicatorTitle = 'Medium';
    } else if (step.includes('🔵')) {
        indicatorColor = 'var(--low)';  // Gray #6C757D
        indicatorTitle = 'Low';
    }

    // Remove emoji from text and clean up
    const cleanText = step.replace(/[🚨🔴🟠🟡🔵]\s*/g, '');

    // Create clickable item if CVE ID found
    const clickHandler = cveId ? `onclick="scrollToCVE('${cveId}')"` : '';
    const hoverClass = cveId ? 'action-plan-item' : '';

    return `
        <li class="${hoverClass}" ${clickHandler} style="margin-bottom: 0.25rem; line-height: 1.5; display: flex; align-items: flex-start; gap: 0.75rem; padding: 0.5rem 0.75rem; margin: 0 -0.75rem; border-radius: 6px; ${cveId ? 'cursor: pointer;' : ''}">
            <span style="font-size: 1rem; color: ${indicatorColor}; flex-shrink: 0; line-height: 1.4;" title="${indicatorTitle}">${indicatorIcon}</span>
            <span>${cleanText}${cveId ? ' <i class="fas fa-arrow-right" style="font-size: 0.7rem; opacity: 0.5; margin-left: 0.25rem;"></i>' : ''}</span>
        </li>
    `;
}

/**
 * Scroll to specific CVE card
 */
function scrollToCVE(cveId) {
    const element = document.getElementById(`cve-card-${cveId}`);
    if (element) {
        element.scrollIntoView({ behavior: 'smooth', block: 'center' });
        // Highlight the card briefly
        element.style.transition = 'box-shadow 0.3s, transform 0.3s';
        element.style.boxShadow = '0 0 0 3px var(--critical), 0 8px 30px rgba(220, 53, 69, 0.3)';
        element.style.transform = 'scale(1.01)';
        setTimeout(() => {
            element.style.boxShadow = '';
            element.style.transform = '';
        }, 1500);
    }
}

// Render individual CVE card with collapsible details
function renderCVECard(finding, isYourSystem, cardIndex) {
    const severityColors = {
        'CRITICAL': 'var(--critical)',
        'HIGH': 'var(--high)',
        'MEDIUM': 'var(--medium)',
        'LOW': 'var(--low)'
    };

    const severityColor = severityColors[finding.severity] || 'var(--text-secondary)';
    const borderColor = isYourSystem ? 'var(--accent-rose)' : 'var(--atmos-gray)';
    const detailsId = `cve-details-${cardIndex}`;
    const cardId = finding.cve ? `cve-card-${finding.cve}` : `cve-card-${cardIndex}`;

    // Source type badge (OS or Browser)
    let sourceTypeBadge = '';
    if (finding.source_type === 'os') {
        sourceTypeBadge = `
            <span style="display: inline-flex; align-items: center; gap: 0.25rem; background: var(--tea); color: white; padding: 0.25rem 0.5rem; border-radius: 6px; font-size: 0.7rem;">
                <i class="fas fa-desktop" style="font-size: 0.65rem;"></i> OS
            </span>
        `;
    } else if (finding.source_type === 'browser') {
        sourceTypeBadge = `
            <span style="display: inline-flex; align-items: center; gap: 0.25rem; background: var(--iced-coffee); color: white; padding: 0.25rem 0.5rem; border-radius: 6px; font-size: 0.7rem;">
                <i class="fas fa-globe" style="font-size: 0.65rem;"></i> Browser
            </span>
        `;
    }

    let cardHtml = `
        <div class="card" id="${cardId}" style="margin-bottom: 1rem; border-left: 4px solid ${borderColor}; background: white;">
            <div class="card-body">
                <!-- Header Row: CVE ID, Severity Badge, Expand Button -->
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <div style="display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;">
                        <h4 style="color: var(--text-primary); margin: 0;">
                            ${finding.cve || 'N/A'}
                        </h4>
                        ${sourceTypeBadge}
                        <span class="severity-badge" style="background: ${severityColor}; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600;">
                            ${finding.severity || 'UNKNOWN'}
                        </span>
                        ${finding.is_exploited ? `
                            <span style="display: inline-flex; align-items: center; gap: 0.25rem; background: var(--critical); color: white; padding: 0.25rem 0.5rem; border-radius: 6px; font-size: 0.75rem;">
                                Exploited
                            </span>
                        ` : ''}
                    </div>
    `;

    // NVD Link
    if (finding.nvd_link) {
        cardHtml += `
                    <a href="${finding.nvd_link}" target="_blank" style="color: var(--accent-teal); text-decoration: none; font-size: 0.85rem; display: inline-flex; align-items: center; gap: 0.25rem;">
                        NVD
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                            <polyline points="15 3 21 3 21 9"></polyline>
                            <line x1="10" y1="14" x2="21" y2="3"></line>
                        </svg>
                    </a>
        `;
    }

    cardHtml += `
                </div>
    `;

    // Title with date
    if (finding.title) {
        const dateDisplay = finding.published_date ? `<span style="font-size: 0.8rem; color: var(--text-secondary); font-weight: normal; margin-left: 0.5rem;">${finding.published_date}</span>` : '';
        cardHtml += `<p style="font-weight: 500; color: var(--text-primary); margin-bottom: 0.5rem;">${finding.title}${dateDisplay}</p>`;
    } else if (finding.published_date) {
        cardHtml += `<p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.5rem;">${finding.published_date}</p>`;
    }

    // Remediation Summary (always visible)
    if (finding.remediation_summary) {
        cardHtml += `
            <div style="display: flex; align-items: center; justify-content: space-between; background: var(--powder-sky); padding: 0.75rem; border-radius: 6px; margin-top: 0.5rem;">
                <p style="color: var(--accent-indigo); font-size: 0.9rem; margin: 0; font-weight: 500;">
                    ${finding.remediation_summary}
                </p>
                <button onclick="toggleDetails('${detailsId}')" style="background: var(--accent-indigo); color: white; border: none; padding: 0.35rem 0.75rem; border-radius: 6px; cursor: pointer; font-size: 0.8rem; display: flex; align-items: center; gap: 0.25rem;">
                    Details
                    <svg id="${detailsId}-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="transition: transform 0.2s;">
                        <polyline points="6 9 12 15 18 9"></polyline>
                    </svg>
                </button>
            </div>
        `;
    }

    // Collapsible Details Section
    cardHtml += `
        <div id="${detailsId}" style="display: none; margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--atmos-mist);">
    `;

    // Description
    if (finding.description) {
        cardHtml += `
            <div style="margin-bottom: 0.75rem;">
                <p style="font-weight: 600; color: var(--text-primary); margin-bottom: 0.25rem; font-size: 0.9rem;">Description</p>
                <p style="color: var(--text-secondary); font-size: 0.9rem; margin: 0;">${finding.description}</p>
            </div>
        `;
    }

    // Published Date
    if (finding.published_date) {
        cardHtml += `
            <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.5rem;">
                <span style="font-weight: 600;">Published:</span> ${finding.published_date}
            </p>
        `;
    }

    // CVSS Score
    if (finding.cvss_score) {
        cardHtml += `
            <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.5rem;">
                <span style="font-weight: 600;">CVSS Score:</span> ${finding.cvss_score}
            </p>
        `;
    }

    // Patch Link or Vendor Security Page
    if (finding.patch_link) {
        cardHtml += `
            <div style="margin-top: 0.75rem;">
                <a href="${finding.patch_link}" target="_blank" style="color: var(--safe); text-decoration: none; font-size: 0.9rem; display: inline-flex; align-items: center; gap: 0.25rem; font-weight: 500;">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                        <polyline points="9 12 11 14 15 10"></polyline>
                    </svg>
                    View Patch
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                        <polyline points="15 3 21 3 21 9"></polyline>
                        <line x1="10" y1="14" x2="21" y2="3"></line>
                    </svg>
                </a>
            </div>
        `;
    } else {
        // Try to find vendor security page
        const vendorLink = getVendorSecurityLink(finding);
        if (vendorLink) {
            cardHtml += `
                <div style="margin-top: 0.75rem;">
                    <a href="${vendorLink.url}" target="_blank" style="color: var(--accent-teal); text-decoration: none; font-size: 0.9rem; display: inline-flex; align-items: center; gap: 0.25rem;">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="12" y1="16" x2="12" y2="12"></line>
                            <line x1="12" y1="8" x2="12.01" y2="8"></line>
                        </svg>
                        Check ${vendorLink.name} Security Updates
                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                            <polyline points="15 3 21 3 21 9"></polyline>
                            <line x1="10" y1="14" x2="21" y2="3"></line>
                        </svg>
                    </a>
                </div>
            `;
        }
    }

    // OS Tags (for other systems)
    if (finding.os_tags && finding.os_tags.length > 0 && !isYourSystem) {
        cardHtml += `
            <div style="margin-top: 0.75rem;">
                <p style="font-size: 0.85rem; color: var(--text-secondary);">
                    <span style="font-weight: 600;">Affected Systems:</span> ${finding.os_tags.join(', ')}
                </p>
            </div>
        `;
    }

    // Note
    if (finding.note) {
        cardHtml += `
            <div style="margin-top: 0.75rem; padding: 0.5rem; background: var(--atmos-mist); border-radius: 6px;">
                <p style="font-size: 0.85rem; color: var(--text-secondary); margin: 0;">${finding.note}</p>
            </div>
        `;
    }

    cardHtml += `
        </div>
            </div>
        </div>
    `;

    return cardHtml;
}

// Toggle details visibility
function toggleDetails(detailsId) {
    const details = document.getElementById(detailsId);
    const icon = document.getElementById(detailsId + '-icon');

    if (details.style.display === 'none') {
        details.style.display = 'block';
        if (icon) icon.style.transform = 'rotate(180deg)';
    } else {
        details.style.display = 'none';
        if (icon) icon.style.transform = 'rotate(0deg)';
    }
}

// Allow Enter key to submit
document.addEventListener('DOMContentLoaded', () => {
    const queryInput = document.getElementById('cve-query');
    if (queryInput) {
        queryInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                analyzeCVEs();
            }
        });
    }

    // Note: Auto-load CVEs is now handled by WelcomeOverlay in app.js
    // This ensures proper sequencing with the welcome animation
});
