// Global state
let currentTarget = null;
let targetsData = [];
let findingsData = [];
let chainsData = [];
let runsData = [];
let learningsData = [];
let roiData = null;
let reportsData = [];
let currentReport = null;
let findingsChart = null;
let roiSeverityChart = null;
let roiTargetsChart = null;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    // Set up tab navigation
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Remove active class from all buttons and contents
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));
            
            // Add active class to clicked button and corresponding content
            button.classList.add('active');
            const tabId = button.getAttribute('data-tab');
            document.getElementById(`${tabId}-tab`).classList.add('active');
            
            // Load tab-specific data if needed
            if (tabId === 'reports' && reportsData.length === 0) {
                loadReports();
            }
        });
    });
    
    // Load initial data
    loadTargets();
    loadAgentStatus();
    loadRoiData();
    
    // Set up event listeners for the reports tab
    setupReportsTab();
    
    // Set up auto-refresh every 60 seconds
    setInterval(() => {
        loadAgentStatus();
        if (currentTarget) {
            refreshCurrentTargetData();
        }
    }, 60000);
});

// Load targets list
function loadTargets() {
    fetch('/api/targets')
        .then(response => response.json())
        .then(data => {
            targetsData = data;
            displayTargetsList(data);
        })
        .catch(error => console.error('Error loading targets:', error));
}

// Display targets in sidebar
function displayTargetsList(targets) {
    const targetsList = document.getElementById('targets-list');
    if (targets.length === 0) {
        targetsList.innerHTML = '<p>No targets found.</p>';
        return;
    }
    
    targetsList.innerHTML = '';
    targets.forEach(target => {
        const targetItem = document.createElement('div');
        targetItem.classList.add('target-item');
        targetItem.innerHTML = `
            <strong>${target.target}</strong>
            <div>${target.findings_count} findings</div>
        `;
        
        targetItem.addEventListener('click', () => {
            // Remove active class from all target items
            document.querySelectorAll('.target-item').forEach(item => {
                item.classList.remove('active');
            });
            
            // Add active class to clicked item
            targetItem.classList.add('active');
            
            // Set current target and load its data
            currentTarget = target.target;
            loadTargetData(target.target);
        });
        
        targetsList.appendChild(targetItem);
    });
    
    // Select first target by default if available
    if (targets.length > 0 && !currentTarget) {
        document.querySelector('.target-item').click();
    }
}

// Load current target data
function loadTargetData(target) {
    Promise.all([
        fetch(`/api/findings/${target}`).then(res => res.json()),
        fetch(`/api/chains/${target}`).then(res => res.json()),
        fetch(`/api/runs/${target}`).then(res => res.json()),
        fetch(`/api/learnings/${target}`).then(res => res.json())
    ])
    .then(([findings, chains, runs, learnings]) => {
        findingsData = findings;
        chainsData = chains;
        runsData = runs;
        learningsData = learnings;
        
        displayTargetSummary(target);
        displayRecentActivity(runs);
        displayFindingsChart(findings);
        displayFindingsTable(findings);
        displayChainsTable(chains);
        displayRunsTable(runs);
        displayLearningsTable(learnings);
    })
    .catch(error => console.error('Error loading target data:', error));
}

// Refresh current target data
function refreshCurrentTargetData() {
    if (currentTarget) {
        loadTargetData(currentTarget);
    }
}

// Load agent status
function loadAgentStatus() {
    fetch('/api/agent/status')
        .then(response => response.json())
        .then(data => {
            displayAgentStatus(data);
        })
        .catch(error => console.error('Error loading agent status:', error));
}

// Load ROI data
function loadRoiData() {
    fetch('/api/roi/summary')
        .then(response => response.json())
        .then(data => {
            roiData = data;
            displayRoiSummary(data);
            displayRoiSeverityChart(data);
            displayRoiTargetsChart(data);
        })
        .catch(error => console.error('Error loading ROI data:', error));
}

// Display target summary
function displayTargetSummary(target) {
    const targetInfo = targetsData.find(t => t.target === target);
    const summaryElement = document.getElementById('target-summary');
    
    if (!targetInfo) {
        summaryElement.innerHTML = '<p>Target information not available.</p>';
        return;
    }
    
    summaryElement.innerHTML = `
        <div class="stat-item">
            <span>Findings:</span>
            <span>${targetInfo.findings_count}</span>
        </div>
        <div class="stat-item">
            <span>Vulnerability Chains:</span>
            <span>${targetInfo.chains_count}</span>
        </div>
        <div class="stat-item">
            <span>Total Payout:</span>
            <span>$${targetInfo.total_payout.toFixed(2)}</span>
        </div>
        <div class="stat-item">
            <span>Time Spent:</span>
            <span>${targetInfo.total_time_spent?.toFixed(1) || 0} hours</span>
        </div>
        <div class="stat-item">
            <span>Average Hourly Rate:</span>
            <span>$${targetInfo.avg_hourly_rate?.toFixed(2) || 0}/hr</span>
        </div>
        <div class="stat-item">
            <span>Last Activity:</span>
            <span>${formatDate(targetInfo.last_activity)}</span>
        </div>
    `;
}

// Display recent activity
function displayRecentActivity(runs) {
    const recentActivity = document.getElementById('recent-activity');
    
    if (!runs || runs.length === 0) {
        recentActivity.innerHTML = '<p>No recent activity found.</p>';
        return;
    }
    
    // Show the 5 most recent runs
    const recentRuns = runs.slice(0, 5);
    
    recentActivity.innerHTML = `
        <ul class="activity-list">
            ${recentRuns.map(run => `
                <li>
                    <span class="status-${run.status}">${capitalizeFirst(run.status)}</span>
                    <strong>${run.module}</strong>
                    <span>${formatDate(run.end_time || run.start_time)}</span>
                </li>
            `).join('')}
        </ul>
    `;
}

// Display findings distribution chart
function displayFindingsChart(findings) {
    const ctx = document.getElementById('findings-chart');
    
    // Count findings by severity
    const severityCounts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0
    };
    
    findings.forEach(finding => {
        const severity = finding.severity.toLowerCase();
        if (severityCounts.hasOwnProperty(severity)) {
            severityCounts[severity]++;
        }
    });
    
    // Destroy existing chart if it exists
    if (findingsChart) {
        findingsChart.destroy();
    }
    
    // Create new chart
    findingsChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                data: [
                    severityCounts.critical,
                    severityCounts.high,
                    severityCounts.medium,
                    severityCounts.low,
                    severityCounts.info
                ],
                backgroundColor: [
                    '#d32f2f',
                    '#f57c00',
                    '#ffa000',
                    '#7cb342',
                    '#64b5f6'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                }
            }
        }
    });
}

// Display findings table
function displayFindingsTable(findings) {
    const tableContainer = document.getElementById('findings-table');
    
    if (!findings || findings.length === 0) {
        tableContainer.innerHTML = '<p>No findings available for this target.</p>';
        return;
    }
    
    tableContainer.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Vulnerability</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th>Payout</th>
                    <th>Time</th>
                    <th>ROI</th>
                    <th>Date</th>
                </tr>
            </thead>
            <tbody>
                ${findings.map(finding => `
                    <tr>
                        <td>${finding.host}</td>
                        <td>${finding.vulnerability}</td>
                        <td class="severity-${finding.severity.toLowerCase()}">${finding.severity}</td>
                        <td>${(finding.confidence * 100).toFixed()}%</td>
                        <td>${finding.payout ? '$' + finding.payout.toFixed(2) : '-'}</td>
                        <td>${finding.time_spent ? finding.time_spent.toFixed(1) + ' hrs' : '-'}</td>
                        <td>${finding.hourly_rate ? '$' + finding.hourly_rate.toFixed(2) + '/hr' : '-'}</td>
                        <td>${formatDate(finding.date)}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

// Display chains table
function displayChainsTable(chains) {
    const tableContainer = document.getElementById('chains-table');
    
    if (!chains || chains.length === 0) {
        tableContainer.innerHTML = '<p>No vulnerability chains available for this target.</p>';
        return;
    }
    
    tableContainer.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Chain Name</th>
                    <th>Description</th>
                    <th>Severity</th>
                    <th>Findings</th>
                    <th>Date</th>
                </tr>
            </thead>
            <tbody>
                ${chains.map(chain => `
                    <tr>
                        <td>${chain.host || '-'}</td>
                        <td>${chain.name}</td>
                        <td>${chain.description}</td>
                        <td class="severity-${chain.combined_severity.toLowerCase()}">${chain.combined_severity}</td>
                        <td>${chain.finding_ids}</td>
                        <td>${formatDate(chain.date_identified)}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

// Display runs table
function displayRunsTable(runs) {
    const tableContainer = document.getElementById('runs-table');
    
    if (!runs || runs.length === 0) {
        tableContainer.innerHTML = '<p>No agent runs available for this target.</p>';
        return;
    }
    
    tableContainer.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>Module</th>
                    <th>Command</th>
                    <th>Status</th>
                    <th>Duration</th>
                    <th>Start Time</th>
                    <th>End Time</th>
                </tr>
            </thead>
            <tbody>
                ${runs.map(run => {
                    // Calculate duration if both start and end times are available
                    let duration = '-';
                    if (run.start_time && run.end_time) {
                        const start = new Date(run.start_time);
                        const end = new Date(run.end_time);
                        const durationMs = end - start;
                        
                        if (durationMs < 60000) {
                            duration = `${Math.round(durationMs / 1000)} sec`;
                        } else {
                            duration = `${Math.round(durationMs / 60000)} min`;
                        }
                    }
                    
                    return `
                        <tr>
                            <td>${run.module}</td>
                            <td>${run.command}</td>
                            <td class="status-${run.status}">${capitalizeFirst(run.status)}</td>
                            <td>${duration}</td>
                            <td>${formatDate(run.start_time)}</td>
                            <td>${formatDate(run.end_time)}</td>
                        </tr>
                    `;
                }).join('')}
            </tbody>
        </table>
    `;
}

// Display learnings table
function displayLearningsTable(learnings) {
    const tableContainer = document.getElementById('learnings-table');
    
    if (!learnings || learnings.length === 0) {
        tableContainer.innerHTML = '<p>No agent learnings available for this target.</p>';
        return;
    }
    
    tableContainer.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>Module</th>
                    <th>Success</th>
                    <th>Insight</th>
                    <th>Date</th>
                </tr>
            </thead>
            <tbody>
                ${learnings.map(learning => `
                    <tr>
                        <td>${learning.module}</td>
                        <td class="status-${learning.success ? 'completed' : 'failed'}">${learning.success ? 'Yes' : 'No'}</td>
                        <td>${learning.insight}</td>
                        <td>${formatDate(learning.date_added)}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

// Display agent status
function displayAgentStatus(statusData) {
    const statusBadge = document.getElementById('agent-status');
    const statsContainer = document.getElementById('agent-stats');
    
    // Update status badge
    statusBadge.textContent = `${statusData.active_plans} active plan(s) | ${statusData.success_rate.toFixed(1)}% success rate`;
    
    // Update stats container
    statsContainer.innerHTML = `
        <div class="stat-item">
            <span>Active Plans:</span>
            <span>${statusData.active_plans}</span>
        </div>
        <div class="stat-item">
            <span>Success Rate:</span>
            <span>${statusData.success_rate.toFixed(1)}%</span>
        </div>
        <div class="stat-item">
            <span>Recent Runs:</span>
            <span>${statusData.recent_runs.length}</span>
        </div>
        <div class="stat-item">
            <span>Last Updated:</span>
            <span>${formatDate(statusData.last_updated)}</span>
        </div>
        
        <h3>Recent Learnings</h3>
        ${statusData.recent_learnings.map(learning => `
            <div class="learning-item">
                <small>${learning.target} - ${learning.module}</small>
                <p>${truncate(learning.insight, 100)}</p>
            </div>
        `).join('')}
    `;
}

// Display ROI summary
function displayRoiSummary(data) {
    const summaryContainer = document.getElementById('roi-summary');
    
    if (!data || !data.overall) {
        summaryContainer.innerHTML = '<p>No ROI data available.</p>';
        return;
    }
    
    const overall = data.overall;
    
    summaryContainer.innerHTML = `
        <div class="stat-item">
            <span>Average Hourly Rate:</span>
            <span>$${overall.avg_hourly_rate.toFixed(2)}/hr</span>
        </div>
        <div class="stat-item">
            <span>Total Payout:</span>
            <span>$${overall.total_payout.toFixed(2)}</span>
        </div>
        <div class="stat-item">
            <span>Total Time Invested:</span>
            <span>${overall.total_time.toFixed(1)} hours</span>
        </div>
        <div class="stat-item">
            <span>ROI Tracked Findings:</span>
            <span>${overall.count}</span>
        </div>
    `;
}

// Display ROI by severity chart
function displayRoiSeverityChart(data) {
    const ctx = document.getElementById('roi-severity-chart');
    
    if (!data || !data.by_severity || data.by_severity.length === 0) {
        return;
    }
    
    // Prepare chart data
    const severities = [];
    const hourlyRates = [];
    const payouts = [];
    
    data.by_severity.forEach(item => {
        severities.push(capitalizeFirst(item.severity));
        hourlyRates.push(item.avg_hourly_rate);
        payouts.push(item.total_payout);
    });
    
    // Destroy existing chart if it exists
    if (roiSeverityChart) {
        roiSeverityChart.destroy();
    }
    
    // Create new chart
    roiSeverityChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: severities,
            datasets: [
                {
                    label: 'Hourly Rate ($/hr)',
                    data: hourlyRates,
                    backgroundColor: 'rgba(54, 162, 235, 0.6)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1,
                    yAxisID: 'y'
                },
                {
                    label: 'Total Payout ($)',
                    data: payouts,
                    backgroundColor: 'rgba(255, 99, 132, 0.6)',
                    borderColor: 'rgba(255, 99, 132, 1)',
                    borderWidth: 1,
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    position: 'left',
                    title: {
                        display: true,
                        text: 'Hourly Rate ($/hr)'
                    }
                },
                y1: {
                    beginAtZero: true,
                    position: 'right',
                    grid: {
                        drawOnChartArea: false
                    },
                    title: {
                        display: true,
                        text: 'Total Payout ($)'
                    }
                }
            }
        }
    });
}

// Display ROI by target chart
function displayRoiTargetsChart(data) {
    const ctx = document.getElementById('roi-targets-chart');
    
    if (!data || !data.top_targets || data.top_targets.length === 0) {
        return;
    }
    
    // Prepare chart data
    const targets = [];
    const hourlyRates = [];
    
    data.top_targets.forEach(item => {
        targets.push(item.target);
        hourlyRates.push(item.avg_hourly_rate);
    });
    
    // Destroy existing chart if it exists
    if (roiTargetsChart) {
        roiTargetsChart.destroy();
    }
    
    // Create new chart
    roiTargetsChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: targets,
            datasets: [{
                label: 'Hourly Rate ($/hr)',
                data: hourlyRates,
                backgroundColor: 'rgba(75, 192, 192, 0.6)',
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Hourly Rate ($/hr)'
                    }
                }
            }
        }
    });
}

// Set up reports tab
function setupReportsTab() {
    // Set up event listeners for filter controls
    const targetFilter = document.getElementById('report-target-filter');
    const typeFilter = document.getElementById('report-type-filter');
    const refreshButton = document.getElementById('refresh-reports');
    
    // Load reports when the tab is clicked
    document.querySelector('[data-tab="reports"]').addEventListener('click', () => {
        loadReports();
    });
    
    // Set up filter change events
    if (targetFilter && typeFilter) {
        targetFilter.addEventListener('change', filterReports);
        typeFilter.addEventListener('change', filterReports);
    }
    
    // Set up refresh button
    if (refreshButton) {
        refreshButton.addEventListener('click', loadReports);
    }
    
    // Set up report details buttons
    document.getElementById('view-report').addEventListener('click', () => {
        if (currentReport && currentReport.report_file) {
            window.open(currentReport.report_file, '_blank');
        }
    });
    
    document.getElementById('download-report').addEventListener('click', () => {
        if (currentReport && currentReport.report_file) {
            const link = document.createElement('a');
            link.href = currentReport.report_file;
            link.download = currentReport.report_file.split('/').pop();
            link.click();
        }
    });
}

// Load reports data
function loadReports() {
    // Show loading state
    document.getElementById('reports-table').innerHTML = 'Loading reports...';
    
    // Build API endpoint
    let endpoint = '/api/reports';
    if (currentTarget !== "all" && currentTarget) {
        endpoint = `/api/reports/${currentTarget}`;
    }
    
    // Fetch reports data
    fetch(endpoint)
        .then(response => response.json())
        .then(data => {
            reportsData = data;
            
            // Update target filter options
            updateTargetFilterOptions(data);
            
            // Update report stats
            updateReportStats(data);
            
            // Display reports table
            displayReportsTable(data);
        })
        .catch(error => {
            console.error('Error loading reports:', error);
            document.getElementById('reports-table').innerHTML = 
                '<p>Error loading reports. Please try again later.</p>';
        });
}

// Update target filter options
function updateTargetFilterOptions(data) {
    const targetFilter = document.getElementById('report-target-filter');
    if (targetFilter) {
        // Save current selection
        const currentValue = targetFilter.value;
        
        // Clear existing options except the first "All Targets" option
        while (targetFilter.options.length > 1) {
            targetFilter.remove(1);
        }
        
        // Get unique targets
        const targets = new Set();
        data.forEach(report => targets.add(report.target));
        
        // Add target options
        targets.forEach(target => {
            const option = document.createElement('option');
            option.value = target;
            option.textContent = target;
            targetFilter.appendChild(option);
        });
        
        // Restore selection if possible
        if (currentValue && [...targets].includes(currentValue)) {
            targetFilter.value = currentValue;
        }
    }
}

// Update report stats
function updateReportStats(data) {
    // Update total reports count
    document.getElementById('total-reports').textContent = data.length;
    
    // Calculate total findings
    const totalFindings = data.reduce((sum, report) => sum + (report.findings_count || 0), 0);
    document.getElementById('total-report-findings').textContent = totalFindings;
    
    // Find latest report date
    if (data.length > 0) {
        // Sort by date (newest first)
        const sortedReports = [...data].sort((a, b) => new Date(b.date) - new Date(a.date));
        const latestReport = sortedReports[0];
        
        document.getElementById('latest-report-date').textContent = 
            formatDate(latestReport.date);
    }
}

// Display reports table
function displayReportsTable(data) {
    const tableContainer = document.getElementById('reports-table');
    
    // Apply filters
    const targetFilter = document.getElementById('report-target-filter').value;
    const typeFilter = document.getElementById('report-type-filter').value;
    
    let filteredData = data;
    
    if (targetFilter !== 'all') {
        filteredData = filteredData.filter(report => report.target === targetFilter);
    }
    
    if (typeFilter !== 'all') {
        filteredData = filteredData.filter(report => report.report_type === typeFilter);
    }
    
    // Sort by date (newest first)
    filteredData.sort((a, b) => new Date(b.date) - new Date(a.date));
    
    // Create table
    if (filteredData.length === 0) {
        tableContainer.innerHTML = '<p>No reports found matching the current filters.</p>';
        return;
    }
    
    tableContainer.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>Target</th>
                    <th>Type</th>
                    <th>Findings</th>
                    <th>Chains</th>
                    <th>Date</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${filteredData.map(report => `
                    <tr>
                        <td>${report.target}</td>
                        <td>${report.report_type.toUpperCase()}</td>
                        <td>${report.findings_count || 0}</td>
                        <td>${report.chains_count || 0}</td>
                        <td>${formatDate(report.date)}</td>
                        <td>
                            <button class="view-details-btn" data-report-id="${report.id}">View Details</button>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
    
    // Add event listeners to view details buttons
    document.querySelectorAll('.view-details-btn').forEach(button => {
        button.addEventListener('click', function() {
            const reportId = this.getAttribute('data-report-id');
            showReportDetails(reportId);
        });
    });
}

// Function to filter reports
function filterReports() {
    // Just redisplay with current filters
    displayReportsTable(reportsData);
}

// Function to show report details
function showReportDetails(reportId) {
    // Find the report in the data
    const report = reportsData.find(r => r.id == reportId);
    if (!report) return;
    
    // Update current report
    currentReport = report;
    
    // Show details card
    const detailsCard = document.getElementById('report-details-card');
    detailsCard.style.display = 'block';
    
    // Update details content
    document.getElementById('report-title').textContent = `Bug Bounty Report for ${report.target}`;
    document.getElementById('report-date').textContent = `Date: ${formatDate(report.date)}`;
    document.getElementById('report-target').textContent = `Target: ${report.target}`;
    document.getElementById('report-type').textContent = `Type: ${report.report_type.toUpperCase()}`;
    document.getElementById('report-findings-count').textContent = report.findings_count || 0;
    document.getElementById('report-chains-count').textContent = report.chains_count || 0;
    
    // Load findings preview if available
    loadFindingsPreview(report);
    
    // Scroll to details card
    detailsCard.scrollIntoView({ behavior: 'smooth' });
}

// Function to load findings preview
function loadFindingsPreview(report) {
    const previewContainer = document.getElementById('report-findings-preview');
    
    // Show loading state
    previewContainer.innerHTML = '<p>Loading findings preview...</p>';
    
    // Fetch findings data for this report
    fetch(`/api/findings/${report.target}?limit=5`)
        .then(response => response.json())
        .then(findings => {
            if (findings.length === 0) {
                previewContainer.innerHTML = '<p>No findings available for this report.</p>';
                return;
            }
            
            // Create findings preview
            previewContainer.innerHTML = `
                <table>
                    <thead>
                        <tr>
                            <th>Title</th>
                            <th>Severity</th>
                            <th>Host</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${findings.map(finding => `
                            <tr>
                                <td>${finding.vulnerability}</td>
                                <td class="severity-${finding.severity.toLowerCase()}">${finding.severity}</td>
                                <td>${finding.host}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
                <div class="view-more">
                    <a href="#" id="view-all-findings">View All Findings</a>
                </div>
            `;
            
            // Add event listener for view all findings link
            document.getElementById('view-all-findings').addEventListener('click', (e) => {
                e.preventDefault();
                // Switch to findings tab and filter for this target
                document.querySelector('[data-tab="findings"]').click();
                // Need to implement target filtering in the findings tab
            });
        })
        .catch(error => {
            console.error('Error loading findings preview:', error);
            previewContainer.innerHTML = '<p>Error loading findings preview.</p>';
        });
}

// Helper function to format dates
function formatDate(dateString) {
    if (!dateString) return '-';
    
    const date = new Date(dateString);
    return date.toLocaleString();
}

// Helper function to capitalize first letter
function capitalizeFirst(string) {
    if (!string) return '';
    return string.charAt(0).toUpperCase() + string.slice(1);
}

// Helper function to truncate text
function truncate(text, maxLength) {
    if (!text) return '';
    if (text.length <= maxLength) return text;
    return text.slice(0, maxLength) + '...';
}
