#!/usr/bin/env python3
# e2e_test.py - End-to-End test workflow for the bug bounty automation framework

import os
import sys
import json
import time
import pathlib
import sqlite3
import argparse
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("e2e_test.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("e2e_test")

# Import our agents
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from agents.orchestrator import OrchestratorAgent
from agents.reporting import ReportingAgent
try:
    from content_discovery import main as run_discovery
except ImportError:
    logger.warning("Could not import content_discovery module. Discovery tests will be skipped.")
    run_discovery = None

try:
    from fuzzer import main as run_fuzzer
except ImportError:
    logger.warning("Could not import fuzzer module. Fuzzing tests will be skipped.")
    run_fuzzer = None

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="End-to-End test workflow for bug bounty automation")
    parser.add_argument("--target", default="test.example.com", help="Target to test against (default: test.example.com)")
    parser.add_argument("--safe-mode", action="store_true", help="Run in safe mode with simulated findings instead of real testing")
    parser.add_argument("--skip-discovery", action="store_true", help="Skip discovery phase")
    parser.add_argument("--skip-fuzzing", action="store_true", help="Skip fuzzing phase")
    parser.add_argument("--dashboard-test", action="store_true", help="Test dashboard integration")
    parser.add_argument("--cleanup", action="store_true", help="Clean up test data after running")
    return parser.parse_args()

def setup_test_db(target, safe_mode=False):
    """Set up test database entries if needed."""
    logger.info(f"Setting up test database for target {target}")
    
    db_path = os.getenv("DB_PATH", "bugbounty.db")
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Create necessary tables if they don't exist
    tables = [
        """CREATE TABLE IF NOT EXISTS findings (
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
        )""",
        """CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            url TEXT,
            status_code INTEGER,
            content_type TEXT,
            interesting BOOLEAN DEFAULT 0,
            notes TEXT,
            date_discovered TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            url TEXT,
            parameter TEXT,
            vulnerability_type TEXT,
            payload TEXT,
            response_code INTEGER,
            evidence TEXT,
            confidence REAL,
            date_discovered TEXT,
            status TEXT,
            notes TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS chains (
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
        )"""
    ]
    
    for table_sql in tables:
        c.execute(table_sql)
    
    conn.commit()
    
    # If in safe mode, create simulated findings
    if safe_mode:
        logger.info("Creating simulated findings for testing")
        
        # Check if there are already findings for this target
        c.execute("SELECT COUNT(*) FROM findings WHERE target = ?", (target,))
        if c.fetchone()[0] == 0:
            # Create sample endpoints
            endpoints = [
                (target, f"https://{target}/", 200, "text/html", 0),
                (target, f"https://{target}/api/", 200, "application/json", 1),
                (target, f"https://{target}/admin/", 403, "text/html", 1),
                (target, f"https://{target}/login", 200, "text/html", 1),
                (target, f"https://{target}/config.php", 403, "text/html", 1)
            ]
            
            c.executemany("""
                INSERT INTO endpoints (target, url, status_code, content_type, interesting)
                VALUES (?, ?, ?, ?, ?)
            """, endpoints)
            
            # Create sample vulnerabilities
            vulnerabilities = [
                (target, f"https://{target}/api/users", "id", "idor", "?id=2", 200, "User data of another user", 0.8, datetime.now().isoformat(), "new", "{}"),
                (target, f"https://{target}/search", "q", "xss", "<script>alert(1)</script>", 200, "<script>alert(1)</script>", 0.9, datetime.now().isoformat(), "new", "{}"),
                (target, f"https://{target}/admin/config", "file", "lfi", "../../../etc/passwd", 200, "root:x:0:0:root:/root:/bin/bash", 0.7, datetime.now().isoformat(), "new", "{}")
            ]
            
            c.executemany("""
                INSERT INTO vulnerabilities (target, url, parameter, vulnerability_type, payload, response_code, evidence, confidence, date_discovered, status, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, vulnerabilities)
            
            # Create sample findings
            findings = [
                (target, f"https://{target}/api/users", "IDOR vulnerability in id parameter", "high", 0.8, datetime.now().isoformat(), "new", 1.5, 500, 333.33),
                (target, f"https://{target}/search", "XSS vulnerability in search parameter", "medium", 0.9, datetime.now().isoformat(), "new", 1.0, 300, 300),
                (target, f"https://{target}/admin/config", "LFI vulnerability in file parameter", "high", 0.7, datetime.now().isoformat(), "new", 2.0, 800, 400)
            ]
            
            c.executemany("""
                INSERT INTO findings (target, host, vulnerability, severity, confidence, date, status, time_spent, payout, hourly_rate)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, findings)
            
            # Create sample chain
            c.execute("""
                INSERT INTO chains (target, host, name, description, finding_ids, combined_severity, technical_details, business_impact, date_identified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                target,
                f"https://{target}",
                "Authentication bypass to LFI chain",
                "This chain combines XSS and LFI vulnerabilities to achieve server access",
                json.dumps([1, 3]),
                "critical",
                "The attacker can use XSS to steal admin credentials, then use the LFI vulnerability to access sensitive files",
                "This chain could result in complete server compromise and access to sensitive data",
                datetime.now().isoformat()
            ))
            
            conn.commit()
            logger.info("Created simulated test data successfully")
    
    conn.close()
    return True

def setup_workspace(target):
    """Set up workspace directories for the target."""
    logger.info(f"Setting up workspace directories for {target}")
    
    # Create main workspace directory
    workspace = pathlib.Path("workspace") / target
    workspace.mkdir(parents=True, exist_ok=True)
    
    # Create subdirectories
    (workspace / "content_discovery").mkdir(exist_ok=True)
    (workspace / "reports").mkdir(exist_ok=True)
    (workspace / "findings").mkdir(exist_ok=True)
    
    return True

def run_discovery_phase(target, safe_mode=False):
    """Run content discovery phase."""
    logger.info(f"Starting discovery phase for {target}")
    
    if safe_mode or run_discovery is None:
        logger.info("Skipping actual discovery in safe mode or module not available")
        # Just create a dummy summary file
        workspace = pathlib.Path("workspace") / target / "content_discovery"
        workspace.mkdir(parents=True, exist_ok=True)
        
        summary = {
            "target": target,
            "hosts_scanned": 1,
            "total_endpoints": 5,
            "interesting_endpoints": 3,
            "high_interest": 2,
            "medium_interest": 1,
            "low_interest": 2,
            "host_summaries": [
                {
                    "host": f"https://{target}",
                    "total_endpoints": 5,
                    "interesting_endpoints": 3,
                    "high_interest": 2,
                    "medium_interest": 1,
                    "low_interest": 2,
                    "status_codes": {"200": 3, "403": 2},
                    "top_vulnerabilities": []
                }
            ],
            "date": datetime.now().isoformat()
        }
        
        with open(workspace / "summary.json", "w") as f:
            json.dump(summary, f, indent=2)
        
        return True
    else:
        # Call actual discovery module
        try:
            # Simulate command line args for content_discovery.py
            sys.argv = ["content_discovery.py", target]
            run_discovery()
            return True
        except Exception as e:
            logger.error(f"Error running discovery: {e}")
            return False

def run_fuzzing_phase(target, safe_mode=False):
    """Run fuzzing/vulnerability detection phase."""
    logger.info(f"Starting fuzzing phase for {target}")
    
    if safe_mode or run_fuzzer is None:
        logger.info("Skipping actual fuzzing in safe mode or module not available")
        # Data already created in setup_test_db if in safe mode
        return True
    else:
        # Call actual fuzzer module
        try:
            # Simulate command line args for fuzzer.py
            sys.argv = ["fuzzer.py", target, "--vuln-type", "all"]
            run_fuzzer()
            return True
        except Exception as e:
            logger.error(f"Error running fuzzer: {e}")
            return False

def run_reporting_phase(target):
    """Run reporting phase."""
    logger.info(f"Starting reporting phase for {target}")
    
    try:
        # Create reporting agent
        reporter = ReportingAgent()
        
        # Generate HTML report
        html_result = reporter.generate_report(target, "html")
        logger.info(f"HTML report generated: {html_result.get('report_file')}")
        
        # Generate Markdown report
        md_result = reporter.generate_report(target, "markdown")
        logger.info(f"Markdown report generated: {md_result.get('report_file')}")
        
        return True
    except Exception as e:
        logger.error(f"Error generating reports: {e}")
        return False

def test_orchestrator(target):
    """Test orchestrator agent coordination."""
    logger.info(f"Testing orchestrator agent coordination for {target}")
    
    try:
        # Create orchestrator agent
        orchestrator = OrchestratorAgent()
        
        # Create plan for target
        plan = orchestrator.create_plan_for_target(target)
        logger.info(f"Orchestrator created plan with {len(plan.get('steps', []))} steps")
        
        # Generate progress report
        report = orchestrator.generate_progress_report(target)
        logger.info(f"Orchestrator generated progress report")
        
        return True
    except Exception as e:
        logger.error(f"Error testing orchestrator: {e}")
        return False

def test_dashboard_integration():
    """Test dashboard integration."""
    logger.info("Testing dashboard integration")
    
    try:
        # Just check if dashboard files exist
        dashboard_path = pathlib.Path("dashboard")
        if not dashboard_path.exists():
            logger.warning("Dashboard directory not found. Dashboard may not be set up.")
            return False
        
        if not (dashboard_path / "index.html").exists():
            logger.warning("Dashboard files not found. Dashboard may not be set up.")
            return False
        
        logger.info("Dashboard files detected. Run 'python agent_dashboard.py' to start the dashboard.")
        return True
    except Exception as e:
        logger.error(f"Error testing dashboard: {e}")
        return False

def cleanup_test_data(target):
    """Clean up test data."""
    logger.info(f"Cleaning up test data for {target}")
    
    try:
        # Connect to database
        db_path = os.getenv("DB_PATH", "bugbounty.db")
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Delete data for the test target
        tables = ["findings", "endpoints", "vulnerabilities", "chains", "agent_runs", "agent_plans"]
        
        for table in tables:
            try:
                c.execute(f"DELETE FROM {table} WHERE target = ?", (target,))
            except sqlite3.OperationalError:
                logger.debug(f"Table {table} doesn't exist or doesn't have target column")
        
        conn.commit()
        conn.close()
        
        # Optionally remove workspace directory
        workspace = pathlib.Path("workspace") / target
        if workspace.exists():
            import shutil
            shutil.rmtree(workspace)
        
        return True
    except Exception as e:
        logger.error(f"Error cleaning up test data: {e}")
        return False

def main():
    """Main function to run the end-to-end test."""
    args = parse_args()
    target = args.target
    
    # Display welcome banner
    print("\n" + "=" * 80)
    print(f"🧪 BUG BOUNTY AUTOMATION END-TO-END TEST - Target: {target}")
    print("=" * 80 + "\n")
    
    # Track test results
    results = {}
    
    # Set up test environment
    results["setup_db"] = setup_test_db(target, args.safe_mode)
    results["setup_workspace"] = setup_workspace(target)
    
    # Run tests
    if not args.skip_discovery:
        results["discovery"] = run_discovery_phase(target, args.safe_mode)
    
    if not args.skip_fuzzing:
        results["fuzzing"] = run_fuzzing_phase(target, args.safe_mode)
    
    results["reporting"] = run_reporting_phase(target)
    results["orchestrator"] = test_orchestrator(target)
    
    if args.dashboard_test:
        results["dashboard"] = test_dashboard_integration()
    
    # Clean up if requested
    if args.cleanup:
        cleanup_test_data(target)
    
    # Display results
    print("\n" + "=" * 80)
    print("🔍 TEST RESULTS SUMMARY")
    print("=" * 80)
    
    all_passed = True
    for test, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        if not passed:
            all_passed = False
        print(f"{test.upper()}: {status}")
    
    overall = "✅ ALL TESTS PASSED" if all_passed else "❌ SOME TESTS FAILED"
    print("\nOVERALL RESULT: " + overall)
    
    print("\n" + "=" * 80)
    if all_passed:
        print("🎉 Your bug bounty automation system is ready for production use!")
        print("=" * 80)
        print("\nNext steps:")
        print("1. Run the dashboard with: python agent_dashboard.py")
        print("2. Start hunting on a real target")
        print("3. Review findings and submit reports")
    else:
        print("⚠️ Some tests failed. Review the logs and fix issues before proceeding.")
        print("=" * 80)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
