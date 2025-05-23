#!/usr/bin/env python3
# agent_dashboard.py - Web-based dashboard for the bug bounty agent

import sqlite3
import json
import os
import sys
import argparse
from datetime import datetime
from flask import Flask, jsonify, request, render_template, send_from_directory

# Database configuration
DB_PATH = "bugbounty.db"

app = Flask(__name__, template_folder='dashboard')

@app.route('/')
def index():
    """Serve the main dashboard page."""
    return render_template('index.html')

@app.route('/api/targets')
def get_targets():
    """Get all targets and their stats."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Get all unique targets
    c.execute("SELECT DISTINCT target FROM findings")
    targets = [row[0] for row in c.fetchall()]
    
    result = []
    for target in targets:
        # Get findings count
        c.execute("SELECT COUNT(*) FROM findings WHERE target = ?", (target,))
        findings_count = c.fetchone()[0] or 0
        
        # Get ROI stats
        c.execute("""
            SELECT AVG(hourly_rate), SUM(payout), SUM(time_spent)
            FROM findings 
            WHERE target = ? AND payout IS NOT NULL AND time_spent IS NOT NULL
        """, (target,))
        avg_hourly, total_payout, total_time = c.fetchone()
        
        # Get chain count
        try:
            c.execute("SELECT COUNT(*) FROM chains WHERE target = ?", (target,))
            chains_count = c.fetchone()[0] or 0
        except:
            chains_count = 0
        
        # Get last activity date
        c.execute("SELECT MAX(date) FROM findings WHERE target = ?", (target,))
        last_activity = c.fetchone()[0]
        
        result.append({
            "target": target,
            "findings_count": findings_count,
            "chains_count": chains_count,
            "avg_hourly_rate": avg_hourly or 0,
            "total_payout": total_payout or 0,
            "total_time_spent": total_time or 0,
            "last_activity": last_activity
        })
    
    conn.close()
    return jsonify(result)

@app.route('/api/findings/<target>')
def get_findings(target):
    """Get all findings for a target."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Get optional limit parameter
    limit = request.args.get('limit', None)
    limit_clause = f"LIMIT {limit}" if limit else ""
    
    c.execute(f"""
        SELECT id, host, vulnerability, severity, confidence, date, status, time_spent, payout, hourly_rate
        FROM findings
        WHERE target = ?
        ORDER BY date DESC
        {limit_clause}
    """, (target,))
    
    columns = ['id', 'host', 'vulnerability', 'severity', 'confidence', 'date', 'status', 'time_spent', 'payout', 'hourly_rate']
    findings = [dict(zip(columns, row)) for row in c.fetchall()]
    
    conn.close()
    return jsonify(findings)

@app.route('/api/chains/<target>')
def get_chains(target):
    """Get all vulnerability chains for a target."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute("""
            SELECT id, host, name, description, finding_ids, combined_severity, date_identified
            FROM chains
            WHERE target = ?
            ORDER BY date_identified DESC
        """, (target,))
        
        columns = ['id', 'host', 'name', 'description', 'finding_ids', 'combined_severity', 'date_identified']
        chains = [dict(zip(columns, row)) for row in c.fetchall()]
    except:
        chains = []
    
    conn.close()
    return jsonify(chains)

@app.route('/api/runs/<target>')
def get_runs(target):
    """Get all agent runs for a target."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute("""
            SELECT id, module, command, status, start_time, end_time, outcome
            FROM agent_runs
            WHERE target = ?
            ORDER BY start_time DESC
        """, (target,))
        
        columns = ['id', 'module', 'command', 'status', 'start_time', 'end_time', 'outcome']
        runs = []
        for row in c.fetchall():
            run = dict(zip(columns, row))
            # Parse the outcome JSON if it exists
            if run['outcome']:
                try:
                    run['outcome'] = json.loads(run['outcome'])
                except:
                    pass
            runs.append(run)
    except:
        runs = []
    
    conn.close()
    return jsonify(runs)

@app.route('/api/learnings/<target>')
def get_learnings(target):
    """Get all agent learnings for a target."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute("""
            SELECT id, module, success, insight, date_added
            FROM agent_learnings
            WHERE target = ?
            ORDER BY date_added DESC
        """, (target,))
        
        columns = ['id', 'module', 'success', 'insight', 'date_added']
        learnings = [dict(zip(columns, row)) for row in c.fetchall()]
    except:
        learnings = []
    
    conn.close()
    return jsonify(learnings)

@app.route('/api/reports')
def get_all_reports():
    """Get all reports from all targets."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        # Get all report summary files
        reports = []
        workspace_dir = os.path.join(os.getcwd(), "workspace")
        
        if os.path.exists(workspace_dir):
            for target_dir in os.listdir(workspace_dir):
                reports_dir = os.path.join(workspace_dir, target_dir, "reports")
                summary_file = os.path.join(reports_dir, "report_summary.json")
                
                if os.path.exists(summary_file):
                    try:
                        with open(summary_file, 'r') as f:
                            summary = json.load(f)
                            # Add ID field for reference
                            summary["id"] = f"{target_dir}_{len(reports)}"
                            reports.append(summary)
                    except:
                        pass
    except Exception as e:
        print(f"Error getting reports: {e}")
        reports = []
    
    conn.close()
    return jsonify(reports)

@app.route('/api/reports/<target>')
def get_target_reports(target):
    """Get all reports for a specific target."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        # Get report summary files for the target
        reports = []
        reports_dir = os.path.join(os.getcwd(), "workspace", target, "reports")
        summary_file = os.path.join(reports_dir, "report_summary.json")
        
        if os.path.exists(summary_file):
            try:
                with open(summary_file, 'r') as f:
                    summary = json.load(f)
                    # Add ID field for reference
                    summary["id"] = f"{target}_0"
                    reports.append(summary)
            except:
                pass
                
        # Also check for individual report files that might not be in the summary
        if os.path.exists(reports_dir):
            for file in os.listdir(reports_dir):
                if file.startswith("report_") and (file.endswith(".html") or file.endswith(".md")):
                    # Check if this report is already in the summary
                    report_path = os.path.join(reports_dir, file)
                    if not any(r.get("report_file") == report_path for r in reports):
                        report_type = "html" if file.endswith(".html") else "markdown"
                        report_date = datetime.fromtimestamp(os.path.getmtime(report_path)).isoformat()
                        
                        # Create a report entry
                        reports.append({
                            "id": f"{target}_{len(reports)}",
                            "target": target,
                            "report_type": report_type,
                            "report_file": report_path,
                            "findings_count": 0,  # Unknown
                            "chains_count": 0,    # Unknown
                            "date": report_date
                        })
    except Exception as e:
        print(f"Error getting reports for {target}: {e}")
        reports = []
    
    conn.close()
    return jsonify(reports)

@app.route('/api/roi/summary')
def get_roi_summary():
    """Get ROI summary stats across all targets."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Get overall ROI stats
    c.execute("""
        SELECT AVG(hourly_rate), SUM(payout), SUM(time_spent), COUNT(*)
        FROM findings 
        WHERE payout IS NOT NULL AND time_spent IS NOT NULL
    """)
    avg_hourly, total_payout, total_time, count = c.fetchone()
    
    # Get ROI by severity
    c.execute("""
        SELECT severity, AVG(hourly_rate), SUM(payout), SUM(time_spent), COUNT(*)
        FROM findings 
        WHERE payout IS NOT NULL AND time_spent IS NOT NULL
        GROUP BY severity
    """)
    by_severity = []
    for row in c.fetchall():
        severity, avg_hourly_rate, payout_sum, time_sum, finding_count = row
        by_severity.append({
            "severity": severity,
            "avg_hourly_rate": avg_hourly_rate or 0,
            "total_payout": payout_sum or 0,
            "total_time": time_sum or 0,
            "count": finding_count
        })
    
    # Get ROI by target (top 5)
    c.execute("""
        SELECT target, AVG(hourly_rate), SUM(payout), SUM(time_spent), COUNT(*)
        FROM findings 
        WHERE payout IS NOT NULL AND time_spent IS NOT NULL
        GROUP BY target
        ORDER BY AVG(hourly_rate) DESC
        LIMIT 5
    """)
    top_targets = []
    for row in c.fetchall():
        target, avg_hourly_rate, payout_sum, time_sum, finding_count = row
        top_targets.append({
            "target": target,
            "avg_hourly_rate": avg_hourly_rate or 0,
            "total_payout": payout_sum or 0,
            "total_time": time_sum or 0,
            "count": finding_count
        })
    
    conn.close()
    
    return jsonify({
        "overall": {
            "avg_hourly_rate": avg_hourly or 0,
            "total_payout": total_payout or 0,
            "total_time": total_time or 0,
            "count": count
        },
        "by_severity": by_severity,
        "top_targets": top_targets
    })

@app.route('/api/agent/status')
def get_agent_status():
    """Get current agent status and stats."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Get count of active plans
    c.execute("SELECT COUNT(*) FROM agent_plans WHERE status = 'in_progress'")
    active_plans = c.fetchone()[0] or 0
    
    # Get recent runs
    c.execute("""
        SELECT id, target, module, status, start_time, end_time
        FROM agent_runs
        ORDER BY start_time DESC
        LIMIT 10
    """)
    columns = ['id', 'target', 'module', 'status', 'start_time', 'end_time']
    recent_runs = [dict(zip(columns, row)) for row in c.fetchall()]
    
    # Get success rate
    c.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed
        FROM agent_runs
    """)
    total, completed = c.fetchone()
    success_rate = (completed / total * 100) if total > 0 else 0
    
    # Get recent learnings
    c.execute("""
        SELECT id, target, module, insight, date_added
        FROM agent_learnings
        ORDER BY date_added DESC
        LIMIT 5
    """)
    columns = ['id', 'target', 'module', 'insight', 'date_added']
    recent_learnings = [dict(zip(columns, row)) for row in c.fetchall()]
    
    conn.close()
    
    return jsonify({
        "active_plans": active_plans,
        "success_rate": success_rate,
        "recent_runs": recent_runs,
        "recent_learnings": recent_learnings,
        "last_updated": datetime.now().isoformat()
    })

@app.route('/dashboard/<path:path>')
def serve_dashboard_files(path):
    """Serve static dashboard files."""
    return send_from_directory('dashboard', path)

def create_dashboard_files():
    """Create the dashboard HTML/CSS/JS files."""
    # Create dashboard directory if it doesn't exist
    os.makedirs('dashboard', exist_ok=True)
    
    # Create index.html
    with open('dashboard/index.html', 'w') as f:
        f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Agent Dashboard</title>
    <link rel="stylesheet" href="/dashboard/styles.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <header>
        <h1>🛠️ Bug Bounty Agent Dashboard</h1>
        <div class="status-badge" id="agent-status">Loading...</div>
    </header>
    
    <div class="dashboard-container">
        <div class="sidebar">
            <div class="section">
                <h2>Targets</h2>
                <div id="targets-list" class="targets-list">Loading targets...</div>
            </div>
            <div class="section">
                <h2>Agent Stats</h2>
                <div id="agent-stats" class="agent-stats">Loading stats...</div>
            </div>
        </div>
        
        <div class="main-content">
            <div class="tab-container">
                <div class="tabs">
                    <button class="tab-button active" data-tab="overview">Overview</button>
                    <button class="tab-button" data-tab="findings">Findings</button>
                    <button class="tab-button" data-tab="chains">Chains</button>
                    <button class="tab-button" data-tab="runs">Agent Runs</button>
                    <button class="tab-button" data-tab="roi">ROI Analysis</button>
                    <button class="tab-button" data-tab="reports">Reports</button>
                </div>
                
                <div class="tab-content active" id="overview-tab">
                    <div class="card">
                        <h3>Target Summary</h3>
                        <div id="target-summary">Select a target</div>
                    </div>
                    
                    <div class="card">
                        <h3>Recent Activity</h3>
                        <div id="recent-activity">Select a target</div>
                    </div>
                    
                    <div class="card">
                        <h3>Findings Distribution</h3>
                        <div class="chart-container">
                            <canvas id="findings-chart"></canvas>
                        </div>
                    </div>
                </div>
                
                <div class="tab-content" id="findings-tab">
                    <div class="card full-width">
                        <h3>Vulnerabilities Found</h3>
                        <div id="findings-table">Select a target</div>
                    </div>
                </div>
                
                <div class="tab-content" id="chains-tab">
                    <div class="card full-width">
                        <h3>Vulnerability Chains</h3>
                        <div id="chains-table">Select a target</div>
                    </div>
                </div>
                
                <div class="tab-content" id="runs-tab">
                    <div class="card full-width">
                        <h3>Agent Execution History</h3>
                        <div id="runs-table">Select a target</div>
                    </div>
                    
                    <div class="card full-width">
                        <h3>Agent Learnings</h3>
                        <div id="learnings-table">Select a target</div>
                    </div>
                </div>
                
                <div class="tab-content" id="roi-tab">
                    <div class="card">
                        <h3>ROI Summary</h3>
                        <div id="roi-summary">Loading ROI data...</div>
                    </div>
                    
                    <div class="card">
                        <h3>ROI by Severity</h3>
                        <div class="chart-container">
                            <canvas id="roi-severity-chart"></canvas>
                        </div>
                    </div>
                    
                    <div class="card">
                        <h3>Most Profitable Targets</h3>
                        <div class="chart-container">
                            <canvas id="roi-targets-chart"></canvas>
                        </div>
                    </div>
                </div>
                
                <div class="tab-content" id="reports-tab">
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
                </div>
            </div>
        </div>
    </div>
    
    <script src="/dashboard/dashboard.js"></script>
</body>
</html>
""")
    
    # Create styles.css
    with open('dashboard/styles.css', 'w') as f:
        f.write("""* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: #333;
    background-color: #f4f6f8;
}

header {
    background-color: #2c3e50;
    color: white;
    padding: 1rem 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.status-badge {
    background-color: #27ae60;
    color: white;
    padding: 0.25rem 0.75rem;
    border-radius: 4px;
    font-size: 0.9rem;
}

.dashboard-container {
    display: flex;
    min-height: calc(100vh - 70px);
}

.sidebar {
    width: 300px;
    background-color: white;
    border-right: 1px solid #e1e4e8;
    padding: 1.5rem;
}

.section {
    margin-bottom: 2rem;
}

.section h2 {
    font-size: 1.2rem;
    margin-bottom: 1rem;
    color: #2c3e50;
    border-bottom: 1px solid #e1e4e8;
    padding-bottom: 0.5rem;
}

.targets-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
}

.target-item {
    padding: 0.5rem;
    border-radius: 4px;
    cursor: pointer;
    transition: background-color 0.2s;
}

.target-item:hover {
    background-color: #f0f4f8;
}

.target-item.active {
    background-color: #e3f2fd;
    border-left: 3px solid #1976d2;
}

.agent-stats {
    font-size: 0.9rem;
}

.stat-item {
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.5rem;
}

.main-content {
    flex-grow: 1;
    padding: 1.5rem;
    overflow-y: auto;
}

.tab-container {
    background-color: white;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
    overflow: hidden;
}

.tabs {
    display: flex;
    border-bottom: 1px solid #e1e4e8;
    background-color: #f8fafb;
}

.tab-button {
    padding: 1rem 1.5rem;
    border: none;
    background: none;
    cursor: pointer;
    font-size: 1rem;
    color: #555;
    transition: all 0.2s;
}

.tab-button:hover {
    background-color: #e3f2fd;
}

.tab-button.active {
    color: #1976d2;
    border-bottom: 2px solid #1976d2;
    background-color: white;
}

.tab-content {
    display: none;
    padding: 1.5rem;
}

.tab-content.active {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
    gap: 1.5rem;
}

.card {
    background-color: white;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
    padding: 1.5rem;
    border: 1px solid #e1e4e8;
}

.card h3 {
    margin-bottom: 1rem;
    color: #2c3e50;
    font-size: 1.1rem;
}

.full-width {
    grid-column: 1 / -1;
}

.chart-container {
    height: 250px;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 1rem;
}

table th {
    text-align: left;
    padding: 0.75rem;
    background-color: #f8fafb;
    border-bottom: 2px solid #e1e4e8;
}

table td {
    padding: 0.75rem;
    border-bottom: 1px solid #e1e4e8;
}

tr:hover {
    background-color: #f5f9ff;
}

.severity-high {
    color: #e53935;
    font-weight: bold;
}

.severity-medium {
    color: #f57c00;
}

.severity-low {
    color: #7cb342;
}

.status-completed {
    color: #27ae60;
}

.status-failed {
    color: #e53935;
}

.status-running {
    color: #2196f3;
}

/* Report styles */
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
""")
    
    # Create dashboard.js
    with open('dashboard/dashboard.js', 'w') as f:
        f.write("""// Global state
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
""")
    
    print("Dashboard files created successfully.")

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="AI-driven bug bounty automation agent dashboard")
    parser.add_argument("--port", type=int, default=5000, help="Port to run the dashboard on")
    parser.add_argument("--host", default="127.0.0.1", help="Host to run the dashboard on")
    parser.add_argument("--debug", action="store_true", help="Run in debug mode")
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    # Create dashboard files
    create_dashboard_files()
    
    # Start the dashboard
    print(f"Starting dashboard on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == "__main__":
    main()