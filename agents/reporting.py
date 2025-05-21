#!/usr/bin/env python3
# reporting.py - ReportingAgent for the bug bounty automation framework

import os
import sys
import json
import sqlite3
import logging
import pathlib
import time
import markdown
import jinja2
from datetime import datetime
from autogen import ConversableAgent

# Add parent directory to path to access utilities
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.config_loader import get_model_config
from utils.message_utils import (
    create_standard_message, create_request_message,
    create_response_message, create_error_message, create_result_message,
    message_to_string, message_to_chat_message
)

class ReportingAgent:
    """
    Specialized agent for report generation in the bug bounty process.
    Creates comprehensive reports of findings and vulnerability chains.
    """
    
    def __init__(self):
        # Get the configuration for the agent
        model_config = get_model_config("gpt-4o") if os.getenv("USE_ENHANCED_MODEL") else get_model_config()
        
        # Create the ConversableAgent
        self.agent = ConversableAgent(
            name="ReportingAgent",
            system_message="""You are the ReportingAgent for a bug bounty automation framework.
            Your responsibilities include:
            1. Creating comprehensive reports of vulnerability findings
            2. Organizing vulnerability chains and attack paths
            3. Generating proof-of-concept documentation
            4. Providing remediation recommendations
            
            You extract information from the database and create well-structured reports
            that highlight the most critical findings and their business impact.""",
            llm_config={
                "config_list": [
                    {
                        "model": model_config["model"],
                        "api_key": model_config["api_key"]
                    }
                ],
                "temperature": 0.3
            }
        )
        
        # Initialize the database connection
        self.db_path = os.getenv("DB_PATH", "bugbounty.db")
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("bugbounty.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("reporting_agent")
        
        # Set up templates directory
        self.templates_dir = pathlib.Path("templates")
        if not self.templates_dir.exists():
            self.templates_dir.mkdir(parents=True, exist_ok=True)
            self.create_default_templates()
        
        # Initialize Jinja2 environment
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.templates_dir)),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
        
        # Initialize report learning system
        self.learning_system = ReportLearningSystem(self.db_path, self.logger)
    
    def create_default_templates(self):
        """Create default report templates if they don't exist."""
        # HTML report template
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ report.title }}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            text-align: center;
            margin-bottom: 40px;
        }
        
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        
        h2 {
            color: #2c3e50;
            margin-top: 30px;
            border-bottom: 1px solid #eee;
            padding-bottom: 5px;
        }
        
        h3 {
            color: #3498db;
        }
        
        .exec-summary {
            background-color: #f8f9fa;
            padding: 20px;
            border-left: 5px solid #3498db;
            margin-bottom: 30px;
        }
        
        .finding {
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }
        
        .finding h3 {
            margin-top: 0;
        }
        
        .severity-high {
            border-left: 5px solid #e74c3c;
        }
        
        .severity-medium {
            border-left: 5px solid #f39c12;
        }
        
        .severity-low {
            border-left: 5px solid #2ecc71;
        }
        
        .severity-info {
            border-left: 5px solid #3498db;
        }
        
        .severity-label {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 3px;
            font-weight: bold;
            color: white;
        }
        
        .severity-high .severity-label {
            background-color: #e74c3c;
        }
        
        .severity-medium .severity-label {
            background-color: #f39c12;
        }
        
        .severity-low .severity-label {
            background-color: #2ecc71;
        }
        
        .severity-info .severity-label {
            background-color: #3498db;
        }
        
        .meta-info {
            color: #7f8c8d;
            font-size: 0.9em;
            margin-bottom: 15px;
        }
        
        .evidence {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 3px;
            font-family: monospace;
            white-space: pre-wrap;
            margin-top: 10px;
        }
        
        .remediation {
            background-color: #eafaf1;
            padding: 15px;
            border-radius: 3px;
            margin-top: 15px;
        }
        
        footer {
            text-align: center;
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #7f8c8d;
        }
        
        .stats {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-around;
            margin: 30px 0;
        }
        
        .stat-box {
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 15px;
            min-width: 150px;
            text-align: center;
            margin-bottom: 15px;
        }
        
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #3498db;
            margin: 10px 0;
        }
        
        .stat-label {
            color: #7f8c8d;
        }
        
        .chain {
            background-color: #f0f7fb;
            border: 1px solid #d0e3ef;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .chain-steps {
            margin-left: 20px;
        }
        
        @media print {
            body {
                font-size: 12pt;
            }
            
            .finding, .chain {
                break-inside: avoid;
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <header>
        <h1>{{ report.title }}</h1>
        <p>{{ report.generated_at }}</p>
    </header>
    
    <div class="exec-summary">
        <h2>Executive Summary</h2>
        {{ report.executive_summary|safe }}
        
        <div class="stats">
            <div class="stat-box">
                <div class="stat-label">Vulnerabilities</div>
                <div class="stat-value">{{ report.stats.total_findings }}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Critical</div>
                <div class="stat-value">{{ report.stats.critical_count }}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">High</div>
                <div class="stat-value">{{ report.stats.high_count }}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Medium</div>
                <div class="stat-value">{{ report.stats.medium_count }}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Low</div>
                <div class="stat-value">{{ report.stats.low_count }}</div>
            </div>
        </div>
    </div>
    
    <h2>Findings Overview</h2>
    <p>{{ report.findings_overview|safe }}</p>
    
    <h2>Detailed Findings</h2>
    {% for finding in report.findings %}
        <div class="finding severity-{{ finding.severity|lower }}">
            <h3>{{ finding.title }}</h3>
            <div class="meta-info">
                <span class="severity-label">{{ finding.severity|upper }}</span>
                <span> | Host: {{ finding.host }}</span>
                <span> | Confidence: {{ finding.confidence }}%</span>
                <span> | Date: {{ finding.date }}</span>
            </div>
            
            <h4>Description</h4>
            <div>{{ finding.description|safe }}</div>
            
            <h4>Technical Details</h4>
            <div>{{ finding.technical_details|safe }}</div>
            
            {% if finding.evidence %}
            <h4>Evidence</h4>
            <div class="evidence">{{ finding.evidence }}</div>
            {% endif %}
            
            <h4>Business Impact</h4>
            <div>{{ finding.business_impact|safe }}</div>
            
            <div class="remediation">
                <h4>Remediation</h4>
                {{ finding.remediation|safe }}
            </div>
        </div>
    {% endfor %}
    
    {% if report.chains %}
    <h2>Attack Chains</h2>
    <p>{{ report.chains_overview|safe }}</p>
    
    {% for chain in report.chains %}
        <div class="chain">
            <h3>{{ chain.name }}</h3>
            <div class="meta-info">
                <span class="severity-label">{{ chain.severity|upper }}</span>
                <span> | Host: {{ chain.host }}</span>
                <span> | Date: {{ chain.date }}</span>
            </div>
            
            <h4>Description</h4>
            <div>{{ chain.description|safe }}</div>
            
            <h4>Attack Path</h4>
            <div class="chain-steps">
                <ol>
                {% for step in chain.steps %}
                    <li>{{ step|safe }}</li>
                {% endfor %}
                </ol>
            </div>
            
            <h4>Business Impact</h4>
            <div>{{ chain.business_impact|safe }}</div>
            
            <div class="remediation">
                <h4>Remediation</h4>
                {{ chain.remediation|safe }}
            </div>
        </div>
    {% endfor %}
    {% endif %}
    
    <h2>Methodology</h2>
    <div>{{ report.methodology|safe }}</div>
    
    <h2>Recommendations</h2>
    <div>{{ report.recommendations|safe }}</div>
    
    <footer>
        <p>Report generated by the AI Bug Bounty Agent on {{ report.generated_at }}</p>
    </footer>
</body>
</html>
"""
        
        # Markdown report template
        markdown_template = """# {{ report.title }}

*Generated on: {{ report.generated_at }}*

## Executive Summary

{{ report.executive_summary }}

### Key Statistics

- **Total Vulnerabilities:** {{ report.stats.total_findings }}
- **Critical:** {{ report.stats.critical_count }}
- **High:** {{ report.stats.high_count }}
- **Medium:** {{ report.stats.medium_count }}
- **Low:** {{ report.stats.low_count }}

## Findings Overview

{{ report.findings_overview }}

## Detailed Findings

{% for finding in report.findings %}
### {{ finding.title }}

**Severity:** {{ finding.severity|upper }}  
**Host:** {{ finding.host }}  
**Confidence:** {{ finding.confidence }}%  
**Date:** {{ finding.date }}

#### Description

{{ finding.description }}

#### Technical Details

{{ finding.technical_details }}

{% if finding.evidence %}
#### Evidence

```
{{ finding.evidence }}
```
{% endif %}

#### Business Impact

{{ finding.business_impact }}

#### Remediation

{{ finding.remediation }}

---
{% endfor %}

{% if report.chains %}
## Attack Chains

{{ report.chains_overview }}

{% for chain in report.chains %}
### {{ chain.name }}

**Severity:** {{ chain.severity|upper }}  
**Host:** {{ chain.host }}  
**Date:** {{ chain.date }}  

#### Description

{{ chain.description }}

#### Attack Path

{% for step in chain.steps %}
{{ loop.index }}. {{ step }}
{% endfor %}

#### Business Impact

{{ chain.business_impact }}

#### Remediation

{{ chain.remediation }}

---
{% endfor %}
{% endif %}

## Methodology

{{ report.methodology }}

## Recommendations

{{ report.recommendations }}

---

*Report generated by the AI Bug Bounty Agent on {{ report.generated_at }}*
"""
        
        # Create template files
        with open(self.templates_dir / "report.html", "w") as f:
            f.write(html_template)
        
        with open(self.templates_dir / "report.md", "w") as f:
            f.write(markdown_template)
        
        self.logger.info("Created default report templates")
    
    def get_db_connection(self):
        """Create a connection to the SQLite database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def generate_report(self, target, report_type="html", options=None):
        """Generate a report for the target."""
        self.logger.info(f"Generating {report_type} report for {target}")
        
        # Set default options if none provided
        if options is None:
            options = {
                "include_chains": True,
                "include_evidence": True,
                "include_remediation": True,
                "max_findings": 100,
                "sort_by": "severity"
            }
        
        # Record run start
        run_id = self.record_run_start(target, f"generate_{report_type}_report for {target}")
        
        # Get findings data
        findings = self.get_findings_data(target, options.get("max_findings", 100), options.get("sort_by", "severity"))
        
        # Get chain data if requested
        chains = []
        if options.get("include_chains", True):
            chains = self.get_chains_data(target)
        
        # Generate summaries and statistics
        stats = self.generate_statistics(findings, chains)
        executive_summary = self.generate_executive_summary(target, findings, chains, stats)
        findings_overview = self.generate_findings_overview(findings)
        chains_overview = self.generate_chains_overview(chains) if chains else ""
        methodology = self.generate_methodology(target)
        recommendations = self.generate_recommendations(target, findings, chains)
        
        # Create report data structure
        report_data = {
            "title": f"Bug Bounty Report for {target}",
            "target": target,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "executive_summary": executive_summary,
            "findings_overview": findings_overview,
            "chains_overview": chains_overview,
            "methodology": methodology,
            "recommendations": recommendations,
            "stats": stats,
            "findings": findings,
            "chains": chains
        }
        
        # Render report template
        report_content = ""
        if report_type == "html":
            template = self.jinja_env.get_template("report.html")
            report_content = template.render(report=report_data)
        elif report_type == "markdown" or report_type == "md":
            template = self.jinja_env.get_template("report.md")
            report_content = template.render(report=report_data)
        else:
            self.logger.error(f"Unsupported report type: {report_type}")
            return None
        
        # Create report directory
        report_dir = pathlib.Path("workspace") / target / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        
        # Save report file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if report_type == "html":
            report_file = report_dir / f"report_{timestamp}.html"
        else:
            report_file = report_dir / f"report_{timestamp}.md"
        
        with open(report_file, "w") as f:
            f.write(report_content)
        
        # Record run end
        self.record_run_end(run_id, True, {"report_file": str(report_file)})
        
        # Create summary
        summary = {
            "target": target,
            "report_type": report_type,
            "report_file": str(report_file),
            "findings_count": len(findings),
            "chains_count": len(chains),
            "date": datetime.now().isoformat()
        }
        
        # Save summary
        summary_path = report_dir / "report_summary.json"
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)
        
        # Learn from report generation
        if findings:
            self.learning_system.learn_from_report(target, findings, chains, report_data)
        
        self.logger.info(f"Report generated and saved to {report_file}")
        
        # Notify orchestrator
        self.notify_orchestrator(target, summary)
        
        return {
            "status": "success",
            "report_file": str(report_file),
            "report_type": report_type,
            "findings_count": len(findings),
            "chains_count": len(chains)
        }
    
    def get_findings_data(self, target, max_findings=100, sort_by="severity"):
        """Get findings data from the database."""
        conn = self.get_db_connection()
        c = conn.cursor()
        
        # Create findings table if it doesn't exist
        try:
            c.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                host TEXT,
                vulnerability TEXT,
                severity TEXT,
                confidence REAL,
                date TEXT,
                status TEXT,
                time_spent REAL,
                payout REAL,
                hourly_rate REAL
            )
            """)
            conn.commit()
        except Exception as e:
            self.logger.error(f"Error creating findings table: {e}")
        
        # Determine sort order
        if sort_by == "severity":
            # Use CASE to sort by severity (critical, high, medium, low, info)
            sort_clause = """
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                WHEN 'info' THEN 5
                ELSE 6
            END
            """
        elif sort_by == "date":
            sort_clause = "date DESC"
        elif sort_by == "confidence":
            sort_clause = "confidence DESC"
        else:
            sort_clause = "id"
        
        # Get findings
        try:
            c.execute(f"""
                SELECT id, host, vulnerability, severity, confidence, date, status
                FROM findings
                WHERE target = ?
                ORDER BY {sort_clause}
                LIMIT ?
            """, (target, max_findings))
            
            findings = []
            for row in c.fetchall():
                finding = {
                    "id": row["id"],
                    "host": row["host"],
                    "title": row["vulnerability"],
                    "severity": row["severity"],
                    "confidence": int(row["confidence"] * 100),
                    "date": row["date"],
                    "status": row["status"]
                }
                
                # Add additional details from vulnerabilities table if available
                try:
                    c.execute("""
                        SELECT parameter, vulnerability_type, payload, evidence, notes
                        FROM vulnerabilities
                        WHERE target = ? AND url = ? AND vulnerability_type = ?
                        LIMIT 1
                    """, (target, finding["host"], finding["title"].split()[0].lower()))
                    
                    vuln_row = c.fetchone()
                    if vuln_row:
                        finding["parameter"] = vuln_row["parameter"]
                        finding["vulnerability_type"] = vuln_row["vulnerability_type"]
                        finding["payload"] = vuln_row["payload"]
                        finding["evidence"] = vuln_row["evidence"]
                        
                        # Parse notes if available
                        if vuln_row["notes"]:
                            try:
                                notes = json.loads(vuln_row["notes"])
                                finding.update(notes)
                            except:
                                pass
                except Exception as e:
                    self.logger.debug(f"Error getting vulnerability details: {e}")
                
                # Generate descriptions from available data
                finding["description"] = self.generate_finding_description(finding)
                finding["technical_details"] = self.generate_technical_details(finding)
                finding["business_impact"] = self.generate_business_impact(finding)
                finding["remediation"] = self.generate_remediation(finding)
                
                findings.append(finding)
            
            conn.close()
            return findings
        
        except Exception as e:
            self.logger.error(f"Error getting findings: {e}")
            conn.close()
            return []
    
    def get_chains_data(self, target):
        """Get vulnerability chains data from the database."""
        conn = self.get_db_connection()
        c = conn.cursor()
        
        # Create chains table if it doesn't exist
        try:
            c.execute("""
            CREATE TABLE IF NOT EXISTS chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                host TEXT,
                name TEXT,
                description TEXT,
                finding_ids TEXT,
                original_severities TEXT,
                combined_severity TEXT,
                technical_details TEXT,
                business_impact TEXT,
                evidence_requirements TEXT,
                date_identified TEXT
            )
            """)
            conn.commit()
        except Exception as e:
            self.logger.error(f"Error creating chains table: {e}")
        
        # Get chains
        try:
            c.execute("""
                SELECT id, host, name, description, finding_ids, combined_severity, 
                      technical_details, business_impact, date_identified
                FROM chains
                WHERE target = ?
                ORDER BY CASE combined_severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                    ELSE 6
                END
            """, (target,))
            
            chains = []
            for row in c.fetchall():
                chain = {
                    "id": row["id"],
                    "host": row["host"],
                    "name": row["name"],
                    "description": row["description"],
                    "severity": row["combined_severity"],
                    "date": row["date_identified"]
                }
                
                # Get finding IDs
                finding_ids = []
                if row["finding_ids"]:
                    try:
                        finding_ids = json.loads(row["finding_ids"])
                    except:
                        finding_ids = row["finding_ids"].split(",")
                
                # Get step information
                steps = []
                if finding_ids:
                    try:
                        finding_ids_str = ",".join([str(fid) for fid in finding_ids])
                        c.execute(f"""
                            SELECT id, host, vulnerability, severity
                            FROM findings
                            WHERE id IN ({finding_ids_str})
                            ORDER BY id
                        """)
                        
                        for finding_row in c.fetchall():
                            steps.append(f"{finding_row['vulnerability']} on {finding_row['host']} ({finding_row['severity'].upper()})")
                    except Exception as e:
                        self.logger.error(f"Error getting chain steps: {e}")
                
                chain["steps"] = steps
                
                # Add technical details and business impact
                chain["technical_details"] = row["technical_details"] if row["technical_details"] else "Technical details not available."
                chain["business_impact"] = row["business_impact"] if row["business_impact"] else "Business impact not available."
                
                # Generate remediation
                chain["remediation"] = self.generate_chain_remediation(chain)
                
                chains.append(chain)
            
            conn.close()
            return chains
        
        except Exception as e:
            self.logger.error(f"Error getting chains: {e}")
            conn.close()
            return []
    
    def generate_finding_description(self, finding):
        """Generate a description for the finding."""
        # Extract data from finding
        vulnerability_type = finding.get("vulnerability_type", "unspecified vulnerability")
        parameter = finding.get("parameter", "unknown parameter")
        host = finding.get("host", "unknown host")
        
        # Format vulnerability type properly
        if vulnerability_type == "xss":
            vulnerability_type = "Cross-Site Scripting (XSS)"
        elif vulnerability_type == "sqli":
            vulnerability_type = "SQL Injection"
        elif vulnerability_type == "ssrf":
            vulnerability_type = "Server-Side Request Forgery (SSRF)"
        elif vulnerability_type == "lfi":
            vulnerability_type = "Local File Inclusion (LFI)"
        elif vulnerability_type == "rce":
            vulnerability_type = "Remote Code Execution (RCE)"
        elif vulnerability_type == "idor":
            vulnerability_type = "Insecure Direct Object Reference (IDOR)"
        
        # Create description
        description = f"""A {vulnerability_type} vulnerability was discovered in the {parameter} parameter on {host}. 
This vulnerability could allow an attacker to """
        
        # Add specific impact based on vulnerability type
        if "xss" in vulnerability_type.lower():
            description += "inject malicious JavaScript code that executes in users' browsers, potentially leading to session hijacking, data theft, or other client-side attacks."
        elif "sql" in vulnerability_type.lower():
            description += "manipulate database queries, potentially leading to unauthorized data access, data manipulation, or even full database compromise."
        elif "ssrf" in vulnerability_type.lower():
            description += "make server-side requests to internal services or external systems, potentially exposing sensitive information or bypassing access controls."
        elif "file inclusion" in vulnerability_type.lower():
            description += "include arbitrary files from the server, potentially leading to sensitive information disclosure or remote code execution."
        elif "code execution" in vulnerability_type.lower():
            description += "execute arbitrary code on the server, potentially leading to complete system compromise."
        elif "idor" in vulnerability_type.lower():
            description += "access or modify data belonging to other users by manipulating object references, potentially leading to unauthorized data access or modification."
        else:
            description += "compromise the security of the application in various ways depending on the context."
        
        return description
    
    def generate_technical_details(self, finding):
        """Generate technical details for the finding."""
        vulnerability_type = finding.get("vulnerability_type", "unspecified")
        parameter = finding.get("parameter", "unknown")
        payload = finding.get("payload", "unknown")
        host = finding.get("host", "unknown")
        
        details = f"""The {vulnerability_type} vulnerability was found in the {parameter} parameter on {host}. 
The following payload was used to confirm the vulnerability:

`{payload}`

"""
        
        # Add vulnerability-specific technical information
        if finding.get("evidence"):
            details += f"The server's response contained the following evidence of vulnerability:\n\n"
            details += f"`{finding.get('evidence')}`\n\n"
        
        # Add additional technical information based on vulnerability type
        if "xss" in vulnerability_type.lower():
            details += "The application fails to properly sanitize user input before reflecting it in the response. This allows injected JavaScript to execute in the context of other users' browsers."
        elif "sql" in vulnerability_type.lower():
            details += "The application fails to properly parameterize SQL queries, allowing attacker-controlled input to modify the structure of database queries."
        elif "ssrf" in vulnerability_type.lower():
            details += "The application makes HTTP requests based on user-supplied input without proper validation, allowing attackers to direct requests to internal services."
        elif "file inclusion" in vulnerability_type.lower():
            details += "The application includes files based on user-controlled input without proper validation, allowing attackers to include arbitrary files from the server."
        elif "code execution" in vulnerability_type.lower():
            details += "The application evaluates user-controlled input as code, allowing attackers to execute arbitrary commands on the server."
        elif "idor" in vulnerability_type.lower():
            details += "The application uses predictable references to access user-specific resources without properly validating access permissions."
        
        return details
    
    def generate_business_impact(self, finding):
        """Generate business impact for the finding."""
        severity = finding.get("severity", "medium").lower()
        vulnerability_type = finding.get("vulnerability_type", "unspecified")
        
        impact = "This vulnerability could result in "
        
        # Severity-specific impact
        if severity == "critical":
            impact += "catastrophic consequences for the organization, including:"
        elif severity == "high":
            impact += "serious consequences for the organization, including:"
        elif severity == "medium":
            impact += "moderate consequences for the organization, including:"
        elif severity == "low":
            impact += "minor consequences for the organization, including:"
        else:
            impact += "potential consequences for the organization, including:"
        
        # Add bullet points based on vulnerability type
        impact += "\n\n"
        
        if "xss" in vulnerability_type.lower():
            impact += "- Theft of user credentials and session tokens\n"
            impact += "- Unauthorized actions performed on behalf of users\n"
            impact += "- Theft of sensitive data visible to users\n"
            impact += "- Damage to company reputation and user trust\n"
        elif "sql" in vulnerability_type.lower():
            impact += "- Unauthorized access to sensitive data in the database\n"
            impact += "- Modification or deletion of database content\n"
            impact += "- Potential access to user credentials and personal information\n"
            impact += "- Regulatory compliance violations and associated penalties\n"
        elif "ssrf" in vulnerability_type.lower():
            impact += "- Access to internal services not intended for public access\n"
            impact += "- Ability to scan internal networks and discover services\n"
            impact += "- Potential to bypass firewall restrictions\n"
            impact += "- Access to cloud provider metadata services leading to escalation of privileges\n"
        elif "file inclusion" in vulnerability_type.lower():
            impact += "- Disclosure of sensitive system files and configurations\n"
            impact += "- Access to credentials and secrets stored in configuration files\n"
            impact += "- Potential for remote code execution through specific techniques\n"
            impact += "- System compromise and unauthorized access\n"
        elif "code execution" in vulnerability_type.lower():
            impact += "- Complete compromise of the application server\n"
            impact += "- Access to all data processed by the application\n"
            impact += "- Ability to pivot to other systems in the network\n"
            impact += "- Installation of persistent backdoors and malware\n"
        elif "idor" in vulnerability_type.lower():
            impact += "- Unauthorized access to other users' data\n"
            impact += "- Modification of other users' information\n"
            impact += "- Privacy violations and potential regulatory issues\n"
            impact += "- Damage to user trust and company reputation\n"
        else:
            impact += "- Unauthorized access to sensitive information\n"
            impact += "- Potential system compromise\n"
            impact += "- Damage to company reputation\n"
            impact += "- Potential regulatory compliance issues\n"
        
        return impact
    
    def generate_remediation(self, finding):
        """Generate remediation recommendations for the finding."""
        vulnerability_type = finding.get("vulnerability_type", "unspecified")
        
        remediation = "To remediate this vulnerability, consider implementing the following measures:\n\n"
        
        # Add vulnerability-specific remediation steps
        if "xss" in vulnerability_type.lower():
            remediation += "1. Implement proper output encoding for all user-controlled data before rendering it in HTML context\n"
            remediation += "2. Use Content-Security-Policy (CSP) headers to restrict script execution\n"
            remediation += "3. Validate and sanitize all user inputs on the server side\n"
            remediation += "4. Consider using frameworks that automatically escape output\n"
            remediation += "5. Use the HttpOnly flag for sensitive cookies to prevent JavaScript access\n"
        elif "sql" in vulnerability_type.lower():
            remediation += "1. Use parameterized queries or prepared statements for all database operations\n"
            remediation += "2. Implement an ORM (Object-Relational Mapping) layer for database access\n"
            remediation += "3. Apply the principle of least privilege to database accounts\n"
            remediation += "4. Validate and sanitize all user inputs\n"
            remediation += "5. Use stored procedures for complex database operations\n"
        elif "ssrf" in vulnerability_type.lower():
            remediation += "1. Implement a whitelist of allowed hosts and URLs\n"
            remediation += "2. Use a URL parser to validate and normalize URLs before processing\n"
            remediation += "3. Block requests to private IP addresses and localhost\n"
            remediation += "4. Configure an outbound proxy for all HTTP requests\n"
            remediation += "5. Disable support for dangerous URL schemes like file:// and dict://\n"
        elif "file inclusion" in vulnerability_type.lower():
            remediation += "1. Avoid passing user-supplied input to file inclusion functions\n"
            remediation += "2. Implement a whitelist of allowed files or resources\n"
            remediation += "3. Use a mapping of allowed file identifiers to actual file paths\n"
            remediation += "4. Validate user input against strict patterns\n"
            remediation += "5. Configure proper file permissions to limit access to sensitive files\n"
        elif "code execution" in vulnerability_type.lower():
            remediation += "1. Never pass user-supplied input to code execution functions\n"
            remediation += "2. Use safer alternatives to eval() and similar functions\n"
            remediation += "3. Implement strict input validation and sanitization\n"
            remediation += "4. Apply the principle of least privilege to application processes\n"
            remediation += "5. Use sandboxing and containerization to limit the impact of successful attacks\n"
        elif "idor" in vulnerability_type.lower():
            remediation += "1. Implement proper access control checks on all resource access\n"
            remediation += "2. Use indirect references that are mapped server-side to actual resources\n"
            remediation += "3. Verify that the current user has access to the requested resource\n"
            remediation += "4. Avoid using predictable or sequential identifiers\n"
            remediation += "5. Apply the principle of least privilege in system design\n"
        else:
            remediation += "1. Validate and sanitize all user inputs\n"
            remediation += "2. Implement proper access controls\n"
            remediation += "3. Follow the principle of least privilege\n"
            remediation += "4. Keep all software and dependencies up to date\n"
            remediation += "5. Conduct regular security reviews and penetration testing\n"
        
        return remediation
    
    def generate_chain_remediation(self, chain):
        """Generate remediation recommendations for vulnerability chains."""
        severity = chain.get("severity", "medium").lower()
        
        # Base remediation on severity
        if severity == "critical" or severity == "high":
            remediation = "This vulnerability chain represents a critical risk and should be addressed immediately. To remediate this chain of vulnerabilities:\n\n"
        else:
            remediation = "To remediate this chain of vulnerabilities:\n\n"
        
        # Add general chain remediation steps
        remediation += "1. Address each individual vulnerability in the chain as described in their respective findings\n"
        remediation += "2. Implement defense-in-depth strategies to break the attack chain at multiple points\n"
        remediation += "3. Consider architectural changes to eliminate the possibility of chaining these vulnerabilities\n"
        remediation += "4. Implement monitoring and alerting for activities that might indicate exploitation of these vulnerabilities\n"
        remediation += "5. Conduct a thorough review of similar components that might suffer from the same issues\n"
        
        return remediation
    
    def generate_statistics(self, findings, chains):
        """Generate statistics for the report."""
        # Count findings by severity
        critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        medium_count = sum(1 for f in findings if f.get("severity", "").lower() == "medium")
        low_count = sum(1 for f in findings if f.get("severity", "").lower() == "low")
        info_count = sum(1 for f in findings if f.get("severity", "").lower() == "info")
        
        # Count chains by severity
        critical_chains = sum(1 for c in chains if c.get("severity", "").lower() == "critical")
        high_chains = sum(1 for c in chains if c.get("severity", "").lower() == "high")
        medium_chains = sum(1 for c in chains if c.get("severity", "").lower() == "medium")
        low_chains = sum(1 for c in chains if c.get("severity", "").lower() == "low")
        
        # Calculate weighted risk score
        risk_score = critical_count * 10 + high_count * 5 + medium_count * 2 + low_count * 1
        
        return {
            "total_findings": len(findings),
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "info_count": info_count,
            "total_chains": len(chains),
            "critical_chains": critical_chains,
            "high_chains": high_chains,
            "medium_chains": medium_chains,
            "low_chains": low_chains,
            "risk_score": risk_score
        }
    
    def generate_executive_summary(self, target, findings, chains, stats):
        """Generate an executive summary for the report."""
        # Base summary on statistics
        if stats["critical_count"] > 0 or stats["high_count"] > 0:
            risk_level = "high"
            action_needed = "immediate"
        elif stats["medium_count"] > 0:
            risk_level = "moderate"
            action_needed = "prompt"
        else:
            risk_level = "low"
            action_needed = "scheduled"
        
        # Generate summary
        summary = f"""This report presents the findings of a security assessment conducted on {target}. 
The assessment identified **{stats['total_findings']} vulnerabilities** of varying severity levels, 
including {stats['critical_count']} critical, {stats['high_count']} high, {stats['medium_count']} medium, 
and {stats['low_count']} low-severity issues."""
        
        if chains:
            summary += f""" Additionally, {stats['total_chains']} vulnerability chains were identified, 
demonstrating how multiple vulnerabilities could be combined to achieve greater impact."""
        
        summary += f"""

Based on these findings, the overall security risk for {target} is assessed as **{risk_level.upper()}**. 
This assessment indicates that {action_needed} action is required to address the identified vulnerabilities 
and improve the security posture of the application.

The most critical findings include:
"""
        
        # Add top findings
        critical_and_high = [f for f in findings if f.get("severity", "").lower() in ["critical", "high"]]
        if critical_and_high:
            for i, finding in enumerate(critical_and_high[:3], 1):
                summary += f"\n{i}. **{finding['title']}** ({finding['severity'].upper()}) - {finding['host']}"
        else:
            medium = [f for f in findings if f.get("severity", "").lower() == "medium"]
            for i, finding in enumerate(medium[:3], 1):
                summary += f"\n{i}. **{finding['title']}** ({finding['severity'].upper()}) - {finding['host']}"
        
        summary += """

This report provides detailed technical information about each vulnerability, 
along with recommended remediation steps to address the identified issues.
"""
        
        return summary
    
    def generate_findings_overview(self, findings):
        """Generate an overview of the findings."""
        if not findings:
            return "No vulnerabilities were identified during the assessment."
        
        # Group findings by severity
        by_severity = {}
        for finding in findings:
            severity = finding.get("severity", "unknown").lower()
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)
        
        # Generate overview
        overview = "The following sections provide an overview of the identified vulnerabilities by severity level."
        
        # Add critical findings
        if "critical" in by_severity and by_severity["critical"]:
            overview += """

## Critical Severity

Critical vulnerabilities pose an immediate and direct threat to the application and its data. 
These issues require immediate attention and remediation. The following critical vulnerabilities were identified:
"""
            for finding in by_severity["critical"]:
                overview += f"\n- **{finding['title']}** on {finding['host']}"
        
        # Add high findings
        if "high" in by_severity and by_severity["high"]:
            overview += """

## High Severity

High severity vulnerabilities represent significant security risks that could lead to system compromise. 
These issues should be addressed promptly. The following high severity vulnerabilities were identified:
"""
            for finding in by_severity["high"]:
                overview += f"\n- **{finding['title']}** on {finding['host']}"
        
        # Add medium findings
        if "medium" in by_severity and by_severity["medium"]:
            overview += """

## Medium Severity

Medium severity vulnerabilities represent moderate security risks that should be addressed as part of 
the normal security maintenance cycle. The following medium severity vulnerabilities were identified:
"""
            for finding in by_severity["medium"]:
                overview += f"\n- **{finding['title']}** on {finding['host']}"
        
        # Add low findings
        if "low" in by_severity and by_severity["low"]:
            overview += """

## Low Severity

Low severity vulnerabilities represent minor security risks with limited impact. 
The following low severity vulnerabilities were identified:
"""
            for finding in by_severity["low"]:
                overview += f"\n- **{finding['title']}** on {finding['host']}"
        
        return overview
    
    def generate_chains_overview(self, chains):
        """Generate an overview of vulnerability chains."""
        if not chains:
            return ""
        
        overview = f"""The assessment identified {len(chains)} vulnerability chains, 
where multiple individual vulnerabilities can be combined to create attack paths with higher impact. 
These chains demonstrate how a sophisticated attacker might exploit the application:
"""
        
        for chain in chains:
            overview += f"\n- **{chain['name']}** ({chain['severity'].upper()}) - {chain['host']}"
        
        overview += """

Each chain represents a unique attack path that should be addressed holistically 
in addition to remediating individual vulnerabilities.
"""
        
        return overview
    
    def generate_methodology(self, target):
        """Generate a methodology section for the report."""
        methodology = f"""The security assessment of {target} was conducted using an automated bug bounty agent 
that employs a combination of dynamic analysis, vulnerability scanning, and AI-powered testing techniques. 
The methodology consisted of the following phases:

1. **Discovery Phase**: Automated discovery of endpoints, APIs, and content using tools such as ffuf and httpx.
   The discovered endpoints were then classified based on their security relevance.

2. **Vulnerability Testing Phase**: Systematic testing of identified endpoints for common web vulnerabilities,
   including but not limited to:
   - Cross-Site Scripting (XSS)
   - SQL Injection
   - Server-Side Request Forgery (SSRF)
   - Local File Inclusion (LFI)
   - Remote Code Execution (RCE)
   - Insecure Direct Object References (IDOR)

3. **Validation Phase**: Validation of detected vulnerabilities to minimize false positives and
   provide concrete evidence of exploitability.

4. **Chain Analysis Phase**: Analysis of individual vulnerabilities to identify potential chains
   where multiple vulnerabilities could be combined to achieve greater impact.

5. **Reporting Phase**: Generation of this comprehensive report detailing all findings,
   their impact, and recommended remediation steps.

The assessment was conducted in a non-intrusive manner, focusing on identifying security issues
without causing disruption to production systems or exposing sensitive data.
"""
        
        return methodology
    
    def generate_recommendations(self, target, findings, chains):
        """Generate overall recommendations for the report."""
        # Base recommendations on findings
        has_critical = any(f.get("severity", "").lower() == "critical" for f in findings)
        has_high = any(f.get("severity", "").lower() == "high" for f in findings)
        has_medium = any(f.get("severity", "").lower() == "medium" for f in findings)
        
        # Generate recommendations based on severity
        if has_critical:
            urgency = "immediate"
            risk = "critical"
        elif has_high:
            urgency = "prompt"
            risk = "high"
        elif has_medium:
            urgency = "timely"
            risk = "moderate"
        else:
            urgency = "scheduled"
            risk = "low"
        
        recommendations = f"""Based on the assessment of {target}, the following recommendations are provided to improve the overall security posture:

1. **Vulnerability Remediation**: Address the identified vulnerabilities with {urgency} action, 
   prioritizing {risk} risk issues as outlined in the findings section.

2. **Security Testing**: Implement regular security testing as part of the development lifecycle,
   including static code analysis, dynamic application security testing, and manual penetration testing.

3. **Developer Training**: Provide security awareness and secure coding training to development teams
   to prevent similar vulnerabilities in future development."""
        
        # Add additional recommendations based on finding types
        vuln_types = set()
        for finding in findings:
            vuln_type = finding.get("vulnerability_type", "").lower()
            if vuln_type:
                vuln_types.add(vuln_type)
        
        if "xss" in vuln_types:
            recommendations += """

4. **Output Encoding**: Implement proper output encoding for all user-controlled data
   before rendering it in HTML context to prevent Cross-Site Scripting attacks."""
        
        if "sqli" in vuln_types:
            recommendations += """

5. **Parameterized Queries**: Standardize the use of parameterized queries or prepared statements
   for all database operations to prevent SQL Injection attacks."""
        
        if "ssrf" in vuln_types or "lfi" in vuln_types:
            recommendations += """

6. **Input Validation**: Implement strict input validation for all user-supplied data,
   especially when it is used to access files or make server-side requests."""
        
        if "idor" in vuln_types:
            recommendations += """

7. **Access Control**: Strengthen access control mechanisms to ensure proper authorization
   for all resource access, preventing Insecure Direct Object References."""
        
        # Add security program recommendations
        recommendations += """

8. **Security Monitoring**: Implement security monitoring and logging to detect and respond
   to potential security incidents in a timely manner.

9. **Vulnerability Management**: Establish a vulnerability management program to track and remediate
   security issues throughout the application lifecycle.

10. **Third-Party Dependencies**: Regularly review and update third-party libraries and components
    to address known vulnerabilities in dependencies.

By implementing these recommendations, the overall security posture of the application will be
significantly improved, reducing the risk of successful attacks and potential data breaches.
"""
        
        return recommendations
    
    def record_run_start(self, target, command):
        """Record the start of a report generation run in the database."""
        conn = self.get_db_connection()
        c = conn.cursor()
        run_id = None
        
        try:
            c.execute("""
                INSERT INTO agent_runs (target, module, command, status, start_time)
                VALUES (?, ?, ?, ?, ?)
            """, (
                target,
                "report_generation",
                command,
                "running",
                datetime.now().isoformat()
            ))
            run_id = c.lastrowid
            conn.commit()
        except Exception as e:
            self.logger.error(f"Error recording run start: {e}")
        finally:
            conn.close()
        
        return run_id
    
    def record_run_end(self, run_id, success, outcome):
        """Record the end of a report generation run in the database."""
        if not run_id:
            return
        
        conn = self.get_db_connection()
        c = conn.cursor()
        
        try:
            c.execute("""
                UPDATE agent_runs 
                SET status = ?, end_time = ?, outcome = ?
                WHERE id = ?
            """, (
                "completed" if success else "failed",
                datetime.now().isoformat(),
                json.dumps(outcome),
                run_id
            ))
            conn.commit()
        except Exception as e:
            self.logger.error(f"Error recording run end: {e}")
        finally:
            conn.close()
    
    def analyze_report_quality(self, report_data):
        """Analyze the quality of a report."""
        quality_score = 0
        quality_factors = {}
        
        # Check executive summary quality
        if len(report_data.get("executive_summary", "")) > 200:
            quality_score += 10
            quality_factors["executive_summary"] = "Good"
        else:
            quality_factors["executive_summary"] = "Could be more detailed"
        
        # Check findings details
        findings = report_data.get("findings", [])
        if findings:
            detailed_findings = sum(1 for f in findings if 
                                   len(f.get("description", "")) > 100 and 
                                   len(f.get("technical_details", "")) > 100 and
                                   len(f.get("remediation", "")) > 100)
            
            quality_score += min(20, detailed_findings * 5)
            quality_factors["findings_detail"] = f"{detailed_findings}/{len(findings)} findings have detailed information"
        
        # Check for chains
        chains = report_data.get("chains", [])
        if chains:
            quality_score += min(15, len(chains) * 5)
            quality_factors["chains"] = f"{len(chains)} vulnerability chains documented"
        
        # Check recommendations quality
        if len(report_data.get("recommendations", "")) > 300:
            quality_score += 15
            quality_factors["recommendations"] = "Comprehensive"
        else:
            quality_factors["recommendations"] = "Basic"
        
        return {
            "quality_score": quality_score,
            "quality_factors": quality_factors,
            "date": datetime.now().isoformat()
        }
    
    # Agent communication methods
    
    def handle_agent_message(self, message):
        """Handle a message from another agent."""
        self.logger.info(f"Received message: {message_to_chat_message(message)}")
        
        # Process based on message type
        if message["type"] == "request":
            # Handle request from another agent
            action = message["metadata"]["action"]
            
            if action == "generate_report":
                # Extract parameters
                target = message["metadata"]["parameters"].get("target")
                report_type = message["metadata"]["parameters"].get("report_type", "html")
                options = message["metadata"]["parameters"].get("options", {})
                
                # Generate report
                result = self.generate_report(target, report_type, options)
                
                # Return a response
                return create_response_message(
                    "ReportingAgent",
                    message["metadata"]["from"],
                    action,
                    result
                )
                
            else:
                # Unknown action
                return create_error_message(
                    "ReportingAgent",
                    message["metadata"]["from"],
                    action,
                    f"Unknown action: {action}"
                )
        
        elif message["type"] == "response":
            # Process response from an agent
            self.logger.info(f"Received response from {message['metadata']['from']}")
            return None
        
        elif message["type"] == "error":
            # Handle error from an agent
            self.logger.error(f"Error from {message['metadata']['from']}: {message['metadata']['error']}")
            return None
        
        else:
            # Unknown message type
            self.logger.warning(f"Unknown message type: {message['type']}")
            return None
    
    def send_message_to_agent(self, to_agent, message):
        """Send a message to another agent."""
        self.logger.info(f"Sending message: {message_to_chat_message(message)}")
        
        # In a real implementation, this would use Autogen's messaging system
        # For now, we'll implement a simple direct call if the agent is in the same process
        
        # Import locally to avoid circular imports
        from agents.orchestrator import OrchestratorAgent
        
        if to_agent == "OrchestratorAgent":
            orchestrator = OrchestratorAgent()
            return orchestrator.handle_agent_message(message)
        
        # If we can't handle the message locally, log a warning
        self.logger.warning(f"Could not send message to {to_agent}: agent not available locally")
        return None
    
    def notify_orchestrator(self, target, summary):
        """Notify the orchestrator of report generation results."""
        message = create_result_message(
            "ReportingAgent",
            "generate_report",
            {
                "target": target,
                "report_file": summary.get("report_file", ""),
                "report_type": summary.get("report_type", ""),
                "findings_count": summary.get("findings_count", 0),
                "chains_count": summary.get("chains_count", 0),
                "timestamp": datetime.now().isoformat()
            }
        )
        
        return self.send_message_to_agent("OrchestratorAgent", message)

    # Learning system methods
    def get_roi_data(self, target):
        """Get ROI (Return on Investment) data for a target."""
        conn = self.get_db_connection()
        c = conn.cursor()
        
        try:
            c.execute("""
                SELECT AVG(hourly_rate), SUM(payout), SUM(time_spent), COUNT(*)
                FROM findings
                WHERE target = ? AND payout IS NOT NULL AND time_spent IS NOT NULL
            """, (target,))
            
            result = c.fetchone()
            if result:
                avg_hourly, total_payout, total_time, count = result
                
                roi_data = {
                    "avg_hourly_rate": avg_hourly or 0,
                    "total_payout": total_payout or 0, 
                    "total_time_spent": total_time or 0,
                    "findings_count": count or 0,
                    "date": datetime.now().isoformat()
                }
                
                # Calculate by severity
                c.execute("""
                    SELECT severity, AVG(hourly_rate), SUM(payout), SUM(time_spent), COUNT(*)
                    FROM findings
                    WHERE target = ? AND payout IS NOT NULL AND time_spent IS NOT NULL
                    GROUP BY severity
                """, (target,))
                
                by_severity = []
                for row in c.fetchall():
                    severity, avg_rate, payout_sum, time_sum, finding_count = row
                    by_severity.append({
                        "severity": severity,
                        "avg_hourly_rate": avg_rate or 0,
                        "total_payout": payout_sum or 0,
                        "total_time_spent": time_sum or 0,
                        "count": finding_count or 0
                    })
                
                roi_data["by_severity"] = by_severity
                
                conn.close()
                return roi_data
            
            conn.close()
            return None
        
        except Exception as e:
            self.logger.error(f"Error getting ROI data: {e}")
            conn.close()
            return None

    def update_roi_with_predictions(self, target, new_findings):
        """Update ROI data with predictions for new findings."""
        roi_data = self.get_roi_data(target)
        
        if not roi_data or roi_data["findings_count"] == 0:
            # No historical data available, use default values
            return
        
        conn = self.get_db_connection()
        c = conn.cursor()
        
        try:
            # For each new finding, predict ROI
            for finding in new_findings:
                if not finding.get("payout") and not finding.get("time_spent"):
                    severity = finding.get("severity", "medium").lower()
                    
                    # Find averages for this severity
                    matching_severity = next((s for s in roi_data.get("by_severity", []) 
                                            if s["severity"].lower() == severity), None)
                    
                    if matching_severity and matching_severity["count"] > 0:
                        # Use severity-specific averages
                        avg_payout = matching_severity["total_payout"] / matching_severity["count"]
                        avg_time = matching_severity["total_time_spent"] / matching_severity["count"]
                    else:
                        # Use overall averages
                        avg_payout = roi_data["total_payout"] / roi_data["findings_count"] if roi_data["findings_count"] > 0 else 0
                        avg_time = roi_data["total_time_spent"] / roi_data["findings_count"] if roi_data["findings_count"] > 0 else 0
                    
                    # Apply confidence adjustment
                    confidence = finding.get("confidence", 50) / 100  # Convert percentage to decimal
                    predicted_payout = avg_payout * confidence
                    predicted_time = avg_time * (0.8 + (0.4 * confidence))  # Time estimate less affected by confidence
                    
                    # Update finding with predictions
                    c.execute("""
                        UPDATE findings
                        SET payout = ?, time_spent = ?, hourly_rate = ?
                        WHERE id = ?
                    """, (
                        predicted_payout,
                        predicted_time,
                        predicted_payout / predicted_time if predicted_time > 0 else 0,
                        finding["id"]
                    ))
            
            conn.commit()
        except Exception as e:
            self.logger.error(f"Error updating ROI predictions: {e}")
        finally:
            conn.close()


class ReportLearningSystem:
    """
    Learning system for the ReportingAgent to improve report quality over time.
    """
    
    def __init__(self, db_path, logger):
        self.db_path = db_path
        self.logger = logger
        self.setup_learning_tables()
    
    def setup_learning_tables(self):
        """Set up database tables for the learning system."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            # Create report_quality table
            c.execute("""
            CREATE TABLE IF NOT EXISTS report_quality (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                report_type TEXT,
                report_file TEXT,
                quality_score REAL,
                quality_factors TEXT,
                date TEXT
            )
            """)
            
            # Create report_feedback table
            c.execute("""
            CREATE TABLE IF NOT EXISTS report_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER,
                feedback_source TEXT,
                rating INTEGER,
                comments TEXT,
                date TEXT,
                FOREIGN KEY(report_id) REFERENCES report_quality(id)
            )
            """)
            
            # Create agent_learnings table if it doesn't exist
            c.execute("""
            CREATE TABLE IF NOT EXISTS agent_learnings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                module TEXT,
                success BOOLEAN,
                insight TEXT,
                date_added TEXT
            )
            """)
            
            conn.commit()
        except Exception as e:
            self.logger.error(f"Error setting up learning tables: {e}")
        finally:
            conn.close()
    
    def learn_from_report(self, target, findings, chains, report_data):
        """Learn from report generation to improve future reports."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            # Analyze report quality
            quality_analysis = self.analyze_report_quality(report_data)
            
            # Save quality analysis
            c.execute("""
                INSERT INTO report_quality 
                (target, report_type, report_file, quality_score, quality_factors, date)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                target,
                report_data.get("report_type", "unknown"),
                report_data.get("report_file", ""),
                quality_analysis["quality_score"],
                json.dumps(quality_analysis["quality_factors"]),
                datetime.now().isoformat()
            ))
            report_quality_id = c.lastrowid
            
            # Generate insights
            insights = self.generate_insights(target, findings, chains, quality_analysis)
            
            # Save insights to agent_learnings
            for insight in insights:
                c.execute("""
                    INSERT INTO agent_learnings 
                    (target, module, success, insight, date_added)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    target,
                    "report_generation",
                    True,
                    insight,
                    datetime.now().isoformat()
                ))
            
            conn.commit()
            
            self.logger.info(f"Learned from report generation for {target}. Quality score: {quality_analysis['quality_score']}")
            
        except Exception as e:
            self.logger.error(f"Error learning from report: {e}")
        finally:
            conn.close()
    
    def analyze_report_quality(self, report_data):
        """Analyze the quality of a report."""
        quality_score = 0
        quality_factors = {}
        
        # Check executive summary quality
        if len(report_data.get("executive_summary", "")) > 200:
            quality_score += 10
            quality_factors["executive_summary"] = "Good"
        else:
            quality_factors["executive_summary"] = "Could be more detailed"
        
        # Check findings details
        findings = report_data.get("findings", [])
        if findings:
            detailed_findings = sum(1 for f in findings if 
                                   len(f.get("description", "")) > 100 and 
                                   len(f.get("technical_details", "")) > 100 and
                                   len(f.get("remediation", "")) > 100)
            
            quality_score += min(20, detailed_findings * 5)
            quality_factors["findings_detail"] = f"{detailed_findings}/{len(findings)} findings have detailed information"
        
        # Check for chains
        chains = report_data.get("chains", [])
        if chains:
            quality_score += min(15, len(chains) * 5)
            quality_factors["chains"] = f"{len(chains)} vulnerability chains documented"
        
        # Check recommendations quality
        if len(report_data.get("recommendations", "")) > 300:
            quality_score += 15
            quality_factors["recommendations"] = "Comprehensive"
        else:
            quality_factors["recommendations"] = "Basic"
        
        return {
            "quality_score": quality_score,
            "quality_factors": quality_factors,
            "date": datetime.now().isoformat()
        }
    
    def generate_insights(self, target, findings, chains, quality_analysis):
        """Generate insights from report data to improve future reports."""
        insights = []
        
        # Analyze findings distribution
        if findings:
            severity_counts = {}
            for finding in findings:
                severity = finding.get("severity", "medium").lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Check severity distribution
            if severity_counts.get("critical", 0) + severity_counts.get("high", 0) > len(findings) * 0.7:
                insights.append(f"Target {target} has an unusually high proportion of critical and high severity findings. Consider review for validation.")
            
            # Check evidence quality
            evidence_missing = sum(1 for f in findings if not f.get("evidence"))
            if evidence_missing > len(findings) * 0.3:
                insights.append(f"Many findings ({evidence_missing}/{len(findings)}) for {target} lack supporting evidence. Consider enhancing evidence collection.")
        
        # Analyze chains
        if chains:
            # Check for long chains
            long_chains = [c for c in chains if len(c.get("steps", [])) > 3]
            if long_chains:
                insights.append(f"Identified {len(long_chains)} complex attack chains with 4+ steps on {target}. These provide high value in reports.")
        
        # Analyze quality
        quality_factors = quality_analysis.get("quality_factors", {})
        for factor, rating in quality_factors.items():
            if "Could be more" in rating or rating == "Basic":
                insights.append(f"Report quality factor '{factor}' needs improvement for {target}.")
        
        # Generate ROI insight
        if findings and any(f.get("payout") for f in findings):
            payouts = [f.get("payout", 0) for f in findings if f.get("payout")]
            if payouts:
                avg_payout = sum(payouts) / len(payouts)
                insights.append(f"Average payout for {target} findings is ${avg_payout:.2f}. Consider prioritizing similar targets for better ROI.")
        
        return insights

    # Additional learning methods would go here
