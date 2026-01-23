/**
 * Phishing Analyzer
 * Handles email file upload and phishing analysis with detailed breakdown
 */

// Analyze uploaded phishing email
async function analyzePhishing() {
    const fileInput = document.getElementById('phishing-file');
    const resultsDiv = document.getElementById('phishing-results');
    const analyzeButton = document.getElementById('analyze-phishing-btn');

    const file = fileInput.files[0];
    if (!file) {
        showError('phishing-results', 'Please select an .eml file');
        return;
    }

    // Validate file extension
    if (!file.name.endsWith('.eml')) {
        showError('phishing-results', 'Please upload a valid .eml file');
        return;
    }

    // Show fishing cat loading animation
    showFishingCatLoading('phishing-results');
    analyzeButton.disabled = true;

    try {
        const formData = new FormData();
        formData.append('file', file);

        const response = await fetch('/api/phishing/analyze', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.detail || `HTTP error ${response.status}`);
        }

        const data = await response.json();
        renderPhishingResults(data);
    } catch (error) {
        console.error('Phishing analysis failed:', error);
        showError('phishing-results', `Analysis failed: ${error.message}`);
    } finally {
        analyzeButton.disabled = false;
    }
}

// Render phishing analysis results
function renderPhishingResults(data) {
    const resultsDiv = document.getElementById('phishing-results');

    // Complete fishing animation first
    if (typeof completeFishingAnimation === 'function') {
        completeFishingAnimation('phishing-results');
    }

    // Delay to show the fish caught animation
    setTimeout(() => {
        renderPhishingResultsContent(data, resultsDiv);
    }, 800);
}

function renderPhishingResultsContent(data, resultsDiv) {

    // Risk level colors
    const riskColors = {
        'critical': 'var(--critical)',
        'high': 'var(--high)',
        'medium': 'var(--medium)',
        'low': 'var(--low)',
        'safe': 'var(--safe)'
    };

    const statusColors = {
        'critical': 'var(--critical)',
        'danger': 'var(--high)',
        'warning': 'var(--medium)',
        'safe': 'var(--safe)'
    };

    const riskColor = riskColors[data.risk_level] || 'var(--text-secondary)';

    // Determine verdict based on risk level for clearer messaging
    let verdict, verdictColor, verdictBg;
    const riskLevel = (data.risk_level || '').toLowerCase();

    if (data.is_phishing || riskLevel === 'critical' || riskLevel === 'high') {
        verdict = 'PHISHING DETECTED';
        verdictColor = 'var(--critical)';
        verdictBg = 'var(--powder-rose)';
    } else if (riskLevel === 'medium') {
        verdict = 'SUSPICIOUS';
        verdictColor = 'var(--high)';
        verdictBg = 'var(--powder-peach)';
    } else if (riskLevel === 'low') {
        // Low risk (15-29) - not dangerous but some indicators found
        verdict = 'LOW RISK';
        verdictColor = 'var(--low)';
        verdictBg = 'var(--powder-sky)';
    } else {
        // Safe (0-14) - no significant risk indicators
        verdict = 'SAFE';
        verdictColor = 'var(--safe)';
        verdictBg = 'var(--powder-sage)';
    }

    // Data source indicator
    let dataSourceHtml = '';
    if (data.data_source) {
        const sourceIcon = data.data_source.status === 'online' ?
            '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>' :
            '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path></svg>';
        const statusColor = data.data_source.status === 'online' ? 'var(--safe)' : 'var(--medium)';
        dataSourceHtml = `
            <div style="display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0.75rem; background: var(--cloud-white); border-radius: 6px; font-size: 0.75rem; color: var(--text-secondary);">
                <span style="color: ${statusColor};">${sourceIcon}</span>
                <span>Domain DB: <strong style="color: var(--text-primary);">${data.data_source.source}</strong></span>
                <span class="info-tooltip" style="cursor: help;">
                    <svg class="info-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"></circle>
                        <path d="M12 16v-4"></path>
                        <path d="M12 8h.01"></path>
                    </svg>
                    <span class="tooltip-content" style="width: 260px; left: auto; right: 0;">
                        <strong>${data.data_source.source}</strong>
                        <p style="margin: 0.5rem 0 0 0; font-weight: normal;">${data.data_source.description}</p>
                        ${data.data_source.status === 'online' ? '<p style="margin: 0.5rem 0 0 0; color: var(--safe); font-size: 0.8rem;">Updated from tranco-list.eu</p>' : '<p style="margin: 0.5rem 0 0 0; color: var(--medium); font-size: 0.8rem;">Using cached local data</p>'}
                    </span>
                </span>
            </div>
        `;
    }

    let html = `
        <!-- Overall Verdict Card -->
        <div class="card" style="margin-bottom: 1.5rem; border-left: 4px solid ${verdictColor}; background: ${verdictBg};">
            <div class="card-body">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; flex-wrap: wrap; gap: 0.75rem;">
                    <h3 style="color: var(--text-primary); margin: 0;">Analysis Result</h3>
                    <div style="display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;">
                        ${dataSourceHtml}
                        <span style="background: ${verdictColor}; color: white; padding: 0.5rem 1rem; border-radius: 12px; font-size: 1rem; font-weight: 600;">
                            ${verdict}
                        </span>
                    </div>
                </div>

                <!-- Risk Score -->
                <div style="margin-bottom: 1.5rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                        <span style="color: var(--text-secondary); font-size: 0.9rem; display: flex; align-items: center; gap: 0.4rem;">
                            Risk Score
                            <span class="info-tooltip risk-score-tooltip">
                                <svg class="info-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <circle cx="12" cy="12" r="10"></circle>
                                    <path d="M12 16v-4"></path>
                                    <path d="M12 8h.01"></path>
                                </svg>
                                <span class="tooltip-content risk-tooltip-content">
                                    <strong>Risk Score Levels</strong>
                                    <div class="risk-levels">
                                        <p style="margin: 0.25rem 0;"><span style="color: var(--safe); font-size: 1.1rem;">●</span> <strong>0-14:</strong> SAFE</p>
                                        <p style="margin: 0.25rem 0;"><span style="color: var(--low); font-size: 1.1rem;">●</span> <strong>15-29:</strong> LOW</p>
                                        <p style="margin: 0.25rem 0;"><span style="color: var(--medium); font-size: 1.1rem;">●</span> <strong>30-49:</strong> MEDIUM</p>
                                        <p style="margin: 0.25rem 0;"><span style="color: var(--high); font-size: 1.1rem;">●</span> <strong>50-69:</strong> HIGH</p>
                                        <p style="margin: 0.25rem 0;"><span style="color: var(--critical); font-size: 1.1rem;">●</span> <strong>70-100:</strong> CRITICAL</p>
                                    </div>
                                </span>
                            </span>
                        </span>
                        <span style="color: ${riskColor}; font-size: 1.5rem; font-weight: 700;">${data.risk_score}/${data.max_score}</span>
                    </div>
                    <div style="width: 100%; height: 12px; background: var(--atmos-gray); border-radius: 6px; overflow: hidden;">
                        <div style="width: ${data.risk_score}%; height: 100%; background: ${riskColor}; transition: width 0.5s ease;"></div>
                    </div>
                </div>

                <!-- Confidence & Risk Level -->
                <div style="display: flex; gap: 2rem; margin-bottom: 1rem;">
                    <div>
                        <p style="color: var(--text-secondary); font-size: 0.75rem; margin: 0; text-transform: uppercase;">Confidence</p>
                        <p style="color: var(--text-primary); font-size: 1.1rem; font-weight: 600; margin: 0; text-transform: capitalize;">${data.confidence}</p>
                    </div>
                    <div>
                        <p style="color: var(--text-secondary); font-size: 0.75rem; margin: 0; text-transform: uppercase;">Risk Level</p>
                        <p style="color: ${riskColor}; font-size: 1.1rem; font-weight: 600; margin: 0; text-transform: uppercase;">${data.risk_level}</p>
                    </div>
                </div>

                <!-- Explanation -->
                <div style="background: white; padding: 1rem; border-radius: 8px;">
                    <p style="color: var(--text-primary); font-size: 0.95rem; line-height: 1.6; margin: 0;">${data.explanation}</p>
                </div>
            </div>
        </div>
    `;

    // Recommendation Card
    html += `
        <div class="card" style="margin-bottom: 1.5rem; border-left: 4px solid var(--accent-indigo);">
            <div class="card-body">
                <h3 style="color: var(--accent-indigo); margin-bottom: 0.75rem; display: flex; align-items: center; gap: 0.5rem;">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"></circle>
                        <path d="M12 16v-4"></path>
                        <path d="M12 8h.01"></path>
                    </svg>
                    Recommendation
                </h3>
                <p style="color: var(--text-primary); font-size: 0.95rem; line-height: 1.6; margin: 0;">${data.recommendation}</p>
            </div>
        </div>
    `;

    // Detailed Checks Section
    if (data.checks && data.checks.length > 0) {
        // Group checks by category
        const checksByCategory = {};
        data.checks.forEach(check => {
            if (!checksByCategory[check.category]) {
                checksByCategory[check.category] = [];
            }
            checksByCategory[check.category].push(check);
        });

        html += `
            <div class="card collapsible-card" style="margin-bottom: 1.5rem;">
                <div class="card-header-collapsible" onclick="toggleCardCollapse('security-checks-section')" style="cursor: pointer; padding: 1rem 1.5rem; display: flex; justify-content: space-between; align-items: center; background: var(--soft-white); border-radius: 12px 12px 0 0;">
                    <h3 style="color: var(--text-primary); margin: 0; display: flex; align-items: center; gap: 0.5rem;">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M9 11l3 3L22 4"></path>
                            <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path>
                        </svg>
                        Security Checks (${data.checks.length} findings)
                    </h3>
                    <svg id="security-checks-section-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--text-secondary)" stroke-width="2" style="transition: transform 0.3s;">
                        <polyline points="6 9 12 15 18 9"></polyline>
                    </svg>
                </div>
                <div id="security-checks-section" class="card-body" style="padding: 1.5rem;">
        `;

        for (const [category, checks] of Object.entries(checksByCategory)) {
            const categoryTitle = category.charAt(0).toUpperCase() + category.slice(1);
            html += `
                <div style="margin-bottom: 1.5rem;">
                    <h4 style="color: var(--text-secondary); font-size: 0.85rem; text-transform: uppercase; margin-bottom: 0.75rem; letter-spacing: 0.05em;">${categoryTitle}</h4>
            `;

            checks.forEach(check => {
                const statusColor = statusColors[check.status] || 'var(--text-secondary)';
                const statusIcon = check.status === 'safe' ? '✓' : check.status === 'warning' ? '⚠' : '✗';

                html += `
                    <div style="padding: 0.75rem; border-left: 3px solid ${statusColor}; background: var(--cloud-white); margin-bottom: 0.5rem; border-radius: 4px;">
                        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 0.25rem;">
                            <div style="display: flex; align-items: center; gap: 0.5rem;">
                                <span style="color: ${statusColor}; font-weight: bold;">${statusIcon}</span>
                                <span style="font-weight: 600; color: var(--text-primary); font-size: 0.9rem;">${check.name}</span>
                            </div>
                            <span style="background: ${statusColor}; color: white; padding: 0.15rem 0.5rem; border-radius: 8px; font-size: 0.7rem; font-weight: 600;">
                                +${check.score} pts
                            </span>
                        </div>
                        <p style="color: var(--text-secondary); font-size: 0.85rem; margin: 0.25rem 0 0 1.5rem;">${check.description}</p>
                        ${check.details ? `<p style="color: var(--text-muted); font-size: 0.8rem; margin: 0.25rem 0 0 1.5rem; font-family: monospace;">${check.details}</p>` : ''}
                        ${check.reference_url ? `
                            <a href="${check.reference_url}" target="_blank" style="font-size: 0.75rem; color: var(--accent-teal); margin-left: 1.5rem; display: inline-flex; align-items: center; gap: 0.25rem; margin-top: 0.25rem;">
                                Learn more
                                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                                    <polyline points="15 3 21 3 21 9"></polyline>
                                    <line x1="10" y1="14" x2="21" y2="3"></line>
                                </svg>
                            </a>
                        ` : ''}
                    </div>
                `;
            });

            html += `</div>`;
        }

        html += `
                </div>
            </div>
        `;
    }

    // Domain Analysis Section
    if (data.domain_analyses && data.domain_analyses.length > 0) {
        html += `
            <div class="card collapsible-card" style="margin-bottom: 1.5rem;">
                <div class="card-header-collapsible" onclick="toggleCardCollapse('domain-analysis-section')" style="cursor: pointer; padding: 1rem 1.5rem; display: flex; justify-content: space-between; align-items: center; background: var(--soft-white); border-radius: 12px 12px 0 0;">
                    <h3 style="color: var(--text-primary); margin: 0; display: flex; align-items: center; gap: 0.5rem;">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="2" y1="12" x2="22" y2="12"></line>
                            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                        </svg>
                        Domain Analysis (${data.domain_analyses.length} URLs)
                    </h3>
                    <svg id="domain-analysis-section-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--text-secondary)" stroke-width="2" style="transition: transform 0.3s;">
                        <polyline points="6 9 12 15 18 9"></polyline>
                    </svg>
                </div>
                <div id="domain-analysis-section" class="card-body" style="padding: 1.5rem;">
        `;

        data.domain_analyses.forEach(domain => {
            const domainRiskColor = riskColors[domain.risk_level] || 'var(--text-secondary)';
            const statusIcon = domain.is_suspicious ? '⚠' : '✓';
            const trustColor = domain.is_known_trusted ? 'var(--safe)' : (domain.trust_level === 'high' ? 'var(--safe)' : (domain.trust_level === 'low' ? 'var(--high)' : 'var(--medium)'));

            html += `
                <div style="padding: 1rem; border: 1px solid ${domain.is_suspicious ? domainRiskColor : 'var(--atmos-gray)'}; background: ${domain.is_suspicious ? 'var(--powder-rose)' : 'var(--cloud-white)'}; margin-bottom: 0.75rem; border-radius: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                        <div style="display: flex; align-items: center; gap: 0.5rem;">
                            <span style="color: ${domainRiskColor}; font-size: 1.2rem;">${statusIcon}</span>
                            <span style="font-family: monospace; font-size: 0.9rem; color: var(--text-primary); word-break: break-all;">${domain.domain}</span>
                        </div>
                        <div style="display: flex; gap: 0.5rem; align-items: center;">
                            ${domain.trust_level ? `
                                <span style="background: ${trustColor}; color: white; padding: 0.25rem 0.6rem; border-radius: 12px; font-size: 0.7rem; font-weight: 500;">
                                    ${domain.is_known_trusted ? 'Verified' : (domain.trust_level === 'high' ? 'Trusted' : (domain.trust_level === 'low' ? 'Low Trust' : 'Unverified'))}
                                </span>
                            ` : ''}
                            <span style="background: ${domainRiskColor}; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase;">
                                ${domain.risk_level}
                            </span>
                        </div>
                    </div>
                    ${domain.checks && domain.checks.length > 0 ? `
                        <div style="margin-left: 1.75rem;">
                            ${domain.checks.map(c => `
                                <p style="color: ${c.is_trust ? 'var(--safe)' : (c.is_risk ? 'var(--high)' : 'var(--text-secondary)')}; font-size: 0.85rem; margin: 0.25rem 0;">
                                    ${c.is_trust ? '✓' : (c.is_risk ? '⚠' : '•')} ${c.description}
                                    ${c.reference_url ? `<a href="${c.reference_url}" target="_blank" style="color: var(--accent-teal); font-size: 0.75rem; margin-left: 0.5rem;">Learn more</a>` : ''}
                                </p>
                            `).join('')}
                        </div>
                    ` : ''}
                </div>
            `;
        });

        html += `
                </div>
            </div>
        `;
    }

    // Attachment Analysis Section (with collapse)
    if (data.attachment_analyses && data.attachment_analyses.length > 0) {
        html += `
            <div class="card" style="margin-bottom: 1.5rem;">
                <div class="card-body">
                    <h3 style="color: var(--text-primary); margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"></path>
                        </svg>
                        Attachment Analysis (${data.attachment_analyses.length} files)
                    </h3>
        `;

        data.attachment_analyses.forEach(att => {
            const attRiskColor = riskColors[att.risk_level] || 'var(--text-secondary)';
            const statusIcon = att.risk_level === 'low' ? '✓' : att.risk_level === 'medium' ? '⚠' : '✗';

            html += `
                <div style="padding: 0.75rem; border-left: 3px solid ${attRiskColor}; background: var(--cloud-white); margin-bottom: 0.5rem; border-radius: 4px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div style="display: flex; align-items: center; gap: 0.5rem;">
                            <span style="color: ${attRiskColor}; font-weight: bold;">${statusIcon}</span>
                            <span style="font-family: monospace; font-size: 0.9rem; color: var(--text-primary);">${att.filename}</span>
                        </div>
                        <span style="background: ${attRiskColor}; color: white; padding: 0.15rem 0.5rem; border-radius: 8px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase;">
                            ${att.risk_level}
                        </span>
                    </div>
                    <p style="color: var(--text-secondary); font-size: 0.85rem; margin: 0.25rem 0 0 1.5rem;">${att.description}</p>
                    ${att.reference_url ? `
                        <a href="${att.reference_url}" target="_blank" style="font-size: 0.75rem; color: var(--accent-teal); margin-left: 1.5rem; display: inline-flex; align-items: center; gap: 0.25rem; margin-top: 0.25rem;">
                            CISA Attachment Safety Guide
                            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                                <polyline points="15 3 21 3 21 9"></polyline>
                                <line x1="10" y1="14" x2="21" y2="3"></line>
                            </svg>
                        </a>
                    ` : ''}
                </div>
            `;
        });

        html += `
                </div>
            </div>
        `;
    }

    // Email Metadata Section
    if (data.email_metadata) {
        const meta = data.email_metadata;
        html += `
            <div class="card" style="margin-bottom: 1.5rem;">
                <div class="card-body">
                    <h3 style="color: var(--text-primary); margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
                            <polyline points="22,6 12,13 2,6"></polyline>
                        </svg>
                        Email Details
                    </h3>

                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                        <div>
                            <p style="font-weight: 600; color: var(--text-secondary); font-size: 0.75rem; margin-bottom: 0.25rem; text-transform: uppercase;">From</p>
                            <p style="color: var(--text-primary); font-size: 0.9rem; margin: 0; word-break: break-all;">${meta.from}</p>
                        </div>
                        <div>
                            <p style="font-weight: 600; color: var(--text-secondary); font-size: 0.75rem; margin-bottom: 0.25rem; text-transform: uppercase;">To</p>
                            <p style="color: var(--text-primary); font-size: 0.9rem; margin: 0; word-break: break-all;">${meta.to}</p>
                        </div>
                        <div style="grid-column: span 2;">
                            <p style="font-weight: 600; color: var(--text-secondary); font-size: 0.75rem; margin-bottom: 0.25rem; text-transform: uppercase;">Subject</p>
                            <p style="color: var(--text-primary); font-size: 0.9rem; margin: 0;">${meta.subject}</p>
                        </div>
                        <div>
                            <p style="font-weight: 600; color: var(--text-secondary); font-size: 0.75rem; margin-bottom: 0.25rem; text-transform: uppercase;">Date</p>
                            <p style="color: var(--text-primary); font-size: 0.9rem; margin: 0;">${meta.date}</p>
                        </div>
                        <div>
                            <p style="font-weight: 600; color: var(--text-secondary); font-size: 0.75rem; margin-bottom: 0.25rem; text-transform: uppercase;">URLs Found</p>
                            <p style="color: var(--text-primary); font-size: 0.9rem; margin: 0;">${meta.urls_count}</p>
                        </div>
                        <div>
                            <p style="font-weight: 600; color: var(--text-secondary); font-size: 0.75rem; margin-bottom: 0.25rem; text-transform: uppercase;">Attachments</p>
                            <p style="color: var(--text-primary); font-size: 0.9rem; margin: 0;">${meta.attachments_count}</p>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    // Scoring Criteria Reference Section (with CISA Guide in header)
    if (data.scoring_criteria && data.scoring_criteria.length > 0) {
        html += `
            <div class="card collapsible-card">
                <div class="card-header-collapsible" onclick="toggleCardCollapse('scoring-criteria-section')" style="cursor: pointer; padding: 1rem 1.5rem; display: flex; justify-content: space-between; align-items: center; background: var(--soft-white); border-radius: 12px 12px 0 0;">
                    <div style="display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;">
                        <h3 style="color: var(--text-primary); margin: 0; display: flex; align-items: center; gap: 0.5rem;">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                                <polyline points="14 2 14 8 20 8"></polyline>
                                <line x1="16" y1="13" x2="8" y2="13"></line>
                                <line x1="16" y1="17" x2="8" y2="17"></line>
                                <polyline points="10 9 9 9 8 9"></polyline>
                            </svg>
                            Scoring Criteria & References
                        </h3>
                        <a href="https://www.cisa.gov/secure-our-world/recognize-and-report-phishing" target="_blank" onclick="event.stopPropagation();" style="background: var(--gradient-warm); color: white; padding: 0.4rem 0.8rem; border-radius: 6px; text-decoration: none; font-size: 0.8rem; font-weight: 500; display: inline-flex; align-items: center; gap: 0.4rem;">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                            </svg>
                            CISA Phishing Guide
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                                <polyline points="15 3 21 3 21 9"></polyline>
                                <line x1="10" y1="14" x2="21" y2="3"></line>
                            </svg>
                        </a>
                    </div>
                    <svg id="scoring-criteria-section-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--text-secondary)" stroke-width="2" style="transition: transform 0.3s;">
                        <polyline points="6 9 12 15 18 9"></polyline>
                    </svg>
                </div>
                <div id="scoring-criteria-section" class="card-body" style="padding: 1.5rem;">
                    <div style="display: grid; gap: 0.75rem;">
        `;

        data.scoring_criteria.forEach(criteria => {
            // Skip the CISA guide entry since we show it in header
            if (criteria.url && criteria.description.includes('CISA')) {
                return;
            }
            if (criteria.url) {
                html += `
                    <a href="${criteria.url}" target="_blank" style="padding: 0.75rem; background: var(--powder-sky); border-radius: 8px; text-decoration: none; display: flex; align-items: center; justify-content: space-between;">
                        <span style="color: var(--accent-indigo); font-weight: 500;">${criteria.description}</span>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-teal)" stroke-width="2">
                            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                            <polyline points="15 3 21 3 21 9"></polyline>
                            <line x1="10" y1="14" x2="21" y2="3"></line>
                        </svg>
                    </a>
                `;
            } else {
                html += `
                    <div style="padding: 0.75rem; background: var(--cloud-white); border-radius: 8px; display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <span style="color: var(--text-primary); font-weight: 500;">${criteria.category}</span>
                            <p style="color: var(--text-secondary); font-size: 0.8rem; margin: 0.25rem 0 0 0;">${criteria.description}</p>
                        </div>
                        ${criteria.max_points ? `<span style="color: var(--text-muted); font-size: 0.85rem;">Max: ${criteria.max_points} pts</span>` : ''}
                    </div>
                `;
            }
        });

        html += `
                    </div>
                </div>
            </div>
        `;
    }

    resultsDiv.innerHTML = html;
}

// Drag and drop support
document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('phishing-file-label');

    if (dropZone) {
        // Prevent default drag behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });

        // Highlight drop zone when dragging over it
        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => {
                dropZone.style.borderColor = 'var(--accent-indigo)';
                dropZone.style.background = 'var(--powder-lavender)';
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => {
                dropZone.style.borderColor = 'var(--atmos-gray)';
                dropZone.style.background = 'var(--cloud-white)';
            }, false);
        });

        // Handle dropped files
        dropZone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;

            if (files.length > 0) {
                const fileInput = document.getElementById('phishing-file');
                fileInput.files = files;
                handleFileSelect({ target: fileInput });
            }
        }, false);
    }
});

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

/**
 * Toggle card collapse/expand
 */
function toggleCardCollapse(sectionId) {
    const section = document.getElementById(sectionId);
    const icon = document.getElementById(sectionId + '-icon');

    if (!section) return;

    if (section.style.display === 'none') {
        // Expand
        section.style.display = 'block';
        if (icon) icon.style.transform = 'rotate(0deg)';
    } else {
        // Collapse
        section.style.display = 'none';
        if (icon) icon.style.transform = 'rotate(-90deg)';
    }
}
