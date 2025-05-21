// Add this to your dashboard.js file to handle report management
// This extends the existing dashboard with a dedicated reports tab

// Initialize new global variables for reports data
let reportsData = {};
let currentReport = null;

// Modify the DOMContentLoaded event to add the reports tab
document.addEventListener('DOMContentLoaded', () => {
    // Existing tab setup code...
    
    // Add reports tab to the tabs list
    const tabsContainer = document.querySelector('.tabs');
    if (tabsContainer) {
        // Add reports tab after the existing tabs
        const reportsTabButton = document.createElement('button');
        reportsTabButton.className = 'tab-button';
        reportsTabButton.setAttribute('data-tab', 'reports');
        reportsTabButton.textContent = 'Reports';
        tabsContainer.appendChild(reportsTabButton);
        
        // Add reports tab content
        const mainContent = document.querySelector('.main-content');
        const tabContainer = mainContent.querySelector('.tab-container');
        
        const reportsTabContent = document.createElement('div');
        reportsTabContent.className = 'tab-content';
        reportsTabContent.id = 'reports-tab';
        
        reportsTabContent.innerHTML = `
            <div class="card full-width">
                <h3>Reports Dashboard</h3>
                <div class="report-summary-stats">
                    <div class="stat-box">
                        <div class="stat-label">Total Reports</div>
                        <div class="stat-value" id="total-reports">0</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-label">Findings</div>
                        <div class="stat-value" id="total-report-findings">0</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-label">Latest Report</div>
                        <div class="stat-value" id="latest-report-date">-</div>
                    </div>
                </div>
                <div class="report-filters">
                    <select id="report-target-filter">
                        <option value="all">All Targets</option>
                    </select>
                    <select id="report-type-filter">
                        <option value="all">All Types</option>
                        <option value="html">HTML</option>
                        <option value="markdown">Markdown</option>
                    </select>
                    <button id="refresh-reports">Refresh</button>
                </div>
                <div id="reports-table">Loading reports...</div>
            </div>
            
            <div class="card full-width" id="report-details-card" style="display: none;">
                <h3>Report Details</h3>
                <div id="report-details-content">
                    <div class="report-header">
                        <h4 id="report-title">Report Title</h4>
                        <div class="report-meta">
                            <span id="report-date">Date: -</span>
                            <span id="report-target">Target: -</span>
                            <span id="report-type">Type: -</span>
                        </div>
                    </div>
                    <div class="report-stats-bar">
                        <div class="stat-item">
                            <label>Findings:</label>
                            <span id="report-findings-count">0</span>
                        </div>
                        <div class="stat-item">
                            <label>Chains:</label>
                            <span id="report-chains-count">0</span>
                        </div>
                        <div class="stat-item">
                            <label>Status:</label>
                            <span id="report-status">Generated</span>
                        </div>
                        <div class="stat-item report-actions">
                            <button id="view-report">View Report</button>
                            <button id="download-report">Download</button>
                        </div>
                    </div>
                    <div class="report-findings-preview">
                        <h5>Findings Summary</h5>
                        <div id="report-findings-preview"></div>
                    </div>
                </div>
            </div>
        `;
        
        tabContainer.appendChild(reportsTabContent);
        
        // Set up event listeners for the reports tab
        setupReportsTab();
    }
});

// Function to set up reports tab
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

// Function to load reports data
function loadReports() {
    // Show loading state
    document.getElementById('reports-table').innerHTML = 'Loading reports...';
    
    // Get current target selection if available
    const currentTarget = currentTarget || "all";
    
    // Build API endpoint
    let endpoint = '/api/reports';
    if (currentTarget !== "all") {
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

// Function to update target filter options
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

// Function to update report stats
function updateReportStats(data) {
    // Update total reports count
    document.getElementById('total-reports').textContent = data.length;
    
    // Calculate total findings
    const totalFindings = data.reduce((sum, report) => sum + (report.findings_count || 0), 0);
    document.getElementById('total-report-findings').textContent = totalFindings;
    
    // Find latest report date
    if (data.length > 0) {
        const latestReport = data.reduce((latest, report) => {
            const reportDate = new Date(report.date);
            return reportDate > new Date(latest.date) ? report : latest;
        }, data[0]);
        
        document.getElementById('latest-report-date').textContent = 
            new Date(latestReport.date).toLocaleDateString();
    }
}

// Function to display reports table
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

// Add required CSS to your styles.css file

/*
Add this to your styles.css file:

.report-summary-stats {
    display: flex;
    justify-content: space-between;
    margin-bottom: 20px;
}

.report-filters {
    display: flex;
    gap: 10px;
    margin-bottom: 20px;
}

.report-filters select, .report-filters button {
    padding: 8px 12px;
    border: 1px solid #e1e4e8;
    border-radius: 4px;
}

.report-filters button {
    background-color: #1976d2;
    color: white;
    cursor: pointer;
}

.report-header {
    margin-bottom: 20px;
}

.report-meta {
    display: flex;
    gap: 20px;
    color: #666;
    margin-top: 5px;
}

.report-stats-bar {
    display: flex;
    justify-content: space-between;
    background-color: #f8f9fa;
    padding: 12px;
    border-radius: 4px;
    margin-bottom: 20px;
}

.stat-item label {
    font-weight: bold;
    margin-right: 5px;
}

.report-actions {
    display: flex;
    gap: 10px;
}

.report-actions button {
    padding: 5px 10px;
    background-color: #1976d2;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}

.view-details-btn {
    padding: 5px 10px;
    background-color: #1976d2;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}

.report-findings-preview {
    margin-top: 20px;
}

.view-more {
    text-align: right;
    margin-top: 10px;
}
*/