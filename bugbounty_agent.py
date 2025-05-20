#!/usr/bin/env python3
# bugbounty_agent.py — AI-driven bug bounty automation controller

import os
import sys
import json
import logging
import openai
import sqlite3
import subprocess
import time
import argparse
import pathlib
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bugbounty.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("bugbounty_agent")

# Database configuration
DB_PATH = "bugbounty.db"

# OpenAI client
client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="AI-driven bug bounty automation agent")
    parser.add_argument("--target", help="Specific target to focus on")
    parser.add_argument("--mode", choices=["plan", "execute", "analyze", "full"], default="full", 
                       help="Operation mode (default: full)")
    parser.add_argument("--steps", help="Specific steps to run, comma-separated")
    parser.add_argument("--auto", action="store_true", help="Run in fully autonomous mode")
    parser.add_argument("--max-targets", type=int, default=3, help="Maximum targets to process")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    return parser.parse_args()

def setup_agent_database():
    """Set up database tables for agent operation."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Create agent_plans table
    c.execute("""
    CREATE TABLE IF NOT EXISTS agent_plans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        plan TEXT,
        status TEXT,
        created_at TEXT,
        updated_at TEXT
    )
    """)
    
    # Create agent_runs table
    c.execute("""
    CREATE TABLE IF NOT EXISTS agent_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        module TEXT,
        command TEXT,
        status TEXT,
        start_time TEXT,
        end_time TEXT,
        outcome TEXT
    )
    """)
    
    # Create agent_learnings table
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
    conn.close()

def get_available_targets():
    """Get all targets available in the workspace."""
    workspace = pathlib.Path("workspace")
    if not workspace.exists():
        return []
    
    return [d.name for d in workspace.iterdir() if d.is_dir()]

def get_target_metrics(target):
    """Get metrics for a target to assess its potential."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Get count of findings
    c.execute("SELECT COUNT(*) FROM findings WHERE target = ?", (target,))
    findings_count = c.fetchone()[0] or 0
    
    # Get count of endpoints
    try:
        c.execute("SELECT COUNT(*) FROM endpoints WHERE target = ?", (target,))
        endpoints_count = c.fetchone()[0] or 0
        
        # Get count of interesting endpoints
        c.execute("SELECT COUNT(*) FROM endpoints WHERE target = ? AND interesting = 1", (target,))
        interesting_endpoints_count = c.fetchone()[0] or 0
    except sqlite3.OperationalError:
        # Endpoints table might not exist yet
        endpoints_count = 0
        interesting_endpoints_count = 0
    
    # Get count of chains
    try:
        c.execute("SELECT COUNT(*) FROM chains WHERE target = ?", (target,))
        chains_count = c.fetchone()[0] or 0
    except sqlite3.OperationalError:
        # Chains table might not exist yet
        chains_count = 0
    
    conn.close()
    
    return {
        "target": target,
        "findings_count": findings_count,
        "endpoints_count": endpoints_count,
        "interesting_endpoints_count": interesting_endpoints_count,
        "chains_count": chains_count,
        "last_activity": get_last_activity(target)
    }

def get_last_activity(target):
    """Get the timestamp of the last activity for a target."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    tables = ["findings", "agent_runs"]
    latest_date = None
    
    for table in tables:
        try:
            date_field = "date" if table == "findings" else "end_time"
            
            c.execute(f"SELECT MAX({date_field}) FROM {table} WHERE target = ?", (target,))
            result = c.fetchone()
            
            if result and result[0]:
                if not latest_date or result[0] > latest_date:
                    latest_date = result[0]
        except sqlite3.OperationalError:
            # Table might not exist yet
            continue
    
    conn.close()
    return latest_date

def prioritize_targets(targets, max_targets=3):
    """Prioritize targets based on metrics and potential."""
    if not targets:
        return []
    
    # Get metrics for each target
    target_metrics = [get_target_metrics(target) for target in targets]
    
    # Use GPT to prioritize targets
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": """You are an AI agent specializing in bug bounty target selection.
                Analyze the provided metrics for each target and prioritize them based on:
                1. Number of findings already identified
                2. Number of endpoints discovered
                3. Number of interesting endpoints
                4. Number of vulnerability chains
                5. Recent activity (targets with recent activity might have new changes)
                
                Return a JSON array of targets in priority order, with a brief explanation for each.
                """},
                {"role": "user", "content": f"""Here are the metrics for {len(target_metrics)} targets:
                
                {json.dumps(target_metrics, indent=2)}
                
                Select and prioritize up to {max_targets} targets to focus on.
                """}
            ],
            response_format={"type": "json_object"},
            temperature=0.7
        )
        
        prioritized = json.loads(response.choices[0].message.content)
        return prioritized.get("targets", [])
        
    except Exception as e:
        logger.error(f"Error prioritizing targets: {e}")
        # Fallback to simple prioritization
        sorted_targets = sorted(
            target_metrics,
            key=lambda x: (
                x["interesting_endpoints_count"] * 10 + 
                x["chains_count"] * 5 + 
                x["findings_count"] * 2 +
                x["endpoints_count"]
            ),
            reverse=True
        )
        return [{"target": t["target"], "reason": "Fallback prioritization"} for t in sorted_targets[:max_targets]]

def create_target_plan(target):
    """Create an execution plan for a target."""
    # Get target metrics
    metrics = get_target_metrics(target)
    
    # Determine which steps have already been completed
    steps_completed = {
        "discovery": metrics["endpoints_count"] > 0,
        "content_discovery": metrics["endpoints_count"] > 100,  # Arbitrary threshold
        "triage": metrics["findings_count"] > 0,
        "attack_planning": False,  # Need to check if attack plan exists
        "verification": False,  # Need to check if verifications exist
        "chain_detection": metrics["chains_count"] > 0,
        "reporting": False  # Need to check if reports exist
    }
    
    # Check if attack plan exists
    plan_file = pathlib.Path("workspace") / target / "attack_plan.json"
    steps_completed["attack_planning"] = plan_file.exists()
    
    # Check if reports exist
    reports_dir = pathlib.Path("workspace") / target / "reports"
    steps_completed["reporting"] = reports_dir.exists() and any(reports_dir.iterdir()) if reports_dir.exists() else False
    
    # Create plan with GPT
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": """You are an AI agent specializing in bug bounty planning.
                Based on the current state of a target, create a detailed execution plan.
                
                Your plan should specify:
                1. Which modules to run and in what order
                2. Any specific parameters or options
                3. Success criteria for each step
                4. Dependencies between steps
                
                Return a JSON object with the plan structure.
                """},
                {"role": "user", "content": f"""Target: {target}
                
                Current metrics:
                {json.dumps(metrics, indent=2)}
                
                Steps already completed:
                {json.dumps(steps_completed, indent=2)}
                
                Create a detailed execution plan for this target.
                """}
            ],
            response_format={"type": "json_object"},
            temperature=0.7
        )
        
        plan = json.loads(response.choices[0].message.content)
        
        # Save plan to database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            INSERT INTO agent_plans (target, plan, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            target,
            json.dumps(plan),
            "created",
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        conn.commit()
        conn.close()
        
        return plan
        
    except Exception as e:
        logger.error(f"Error creating plan for {target}: {e}")
        
        # Fallback to basic plan
        basic_plan = {
            "target": target,
            "steps": []
        }
        
        # Add steps based on what's missing
        if not steps_completed["discovery"]:
            basic_plan["steps"].append({
                "module": "discover",
                "command": f"python3 discover.py {target}",
                "priority": 1
            })
        
        if not steps_completed["triage"] and steps_completed["discovery"]:
            basic_plan["steps"].append({
                "module": "ai_triage",
                "command": f"python3 ai_triage.py {target}",
                "priority": 2
            })
        
        if not steps_completed["attack_planning"] and steps_completed["triage"]:
            basic_plan["steps"].append({
                "module": "attack_coordinator",
                "command": f"python3 attack_coordinator.py {target}",
                "priority": 3
            })
            
        if not steps_completed["verification"] and steps_completed["attack_planning"]:
            basic_plan["steps"].append({
                "module": "verify",
                "command": f"python3 verify.py {target}",
                "priority": 4
            })
            
        if not steps_completed["chain_detection"] and steps_completed["triage"]:
            basic_plan["steps"].append({
                "module": "chain_detector",
                "command": f"python3 chain_detector.py {target}",
                "priority": 5
            })
            
        if not steps_completed["reporting"] and (steps_completed["verification"] or steps_completed["chain_detection"]):
            basic_plan["steps"].append({
                "module": "report_engine",
                "command": f"python3 report_engine.py {target}",
                "priority": 6
            })
        
        return basic_plan

def execute_plan(plan):
    """Execute a target plan."""
    target = plan.get("target")
    steps = plan.get("steps", [])
    
    if not steps:
        logger.info(f"No steps to execute for {target}")
        return
    
    # Sort steps by priority
    steps.sort(key=lambda x: x.get("priority", 999))
    
    for step in steps:
        module = step.get("module")
        command = step.get("command")
        
        if not command:
            continue
        
        logger.info(f"Executing step: {module} for {target}")
        logger.info(f"Command: {command}")
        
        # Record start in database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            INSERT INTO agent_runs (target, module, command, status, start_time)
            VALUES (?, ?, ?, ?, ?)
        """, (
            target,
            module,
            command,
            "running",
            datetime.now().isoformat()
        ))
        run_id = c.lastrowid
        conn.commit()
        conn.close()
        
        # Execute command
        start_time = time.time()
        try:
            process = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Determine outcome
            success = process.returncode == 0
            outcome = {
                "exit_code": process.returncode,
                "duration": time.time() - start_time,
                "stdout": process.stdout[:1000],  # First 1000 chars
                "stderr": process.stderr[:1000] if process.stderr else ""
            }
            
            status = "completed" if success else "failed"
            
        except Exception as e:
            status = "error"
            outcome = {
                "error": str(e),
                "duration": time.time() - start_time
            }
            success = False
        
        # Update run record
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            UPDATE agent_runs 
            SET status = ?, end_time = ?, outcome = ?
            WHERE id = ?
        """, (
            status,
            datetime.now().isoformat(),
            json.dumps(outcome),
            run_id
        ))
        conn.commit()
        conn.close()
        
        # Learn from outcome
        learn_from_execution(target, module, success, outcome)
        
        # Update plan status
        update_plan_status(target, module, success)
        
        if not success:
            logger.warning(f"Step {module} failed for {target}. Stopping plan execution.")
            break

def learn_from_execution(target, module, success, outcome):
    """Learn from execution results to improve future runs."""
    if not client:
        return
    
    try:
        # Ask GPT for insights
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": """You are an AI agent specializing in learning from bug bounty tool executions.
                Analyze the execution outcome and extract insights that could improve future runs.
                
                Focus on:
                1. Patterns of success or failure
                2. Performance bottlenecks
                3. Potential improvements to parameters or workflow
                4. Anomalies that might indicate bugs or issues
                
                Return a concise insight that could be used to improve future executions.
                """},
                {"role": "user", "content": f"""Module: {module}
                Target: {target}
                Success: {success}
                
                Execution outcome:
                {json.dumps(outcome, indent=2)}
                
                What insights can we learn from this execution?
                """}
            ],
            temperature=0.7,
            max_tokens=300
        )
        
        insight = response.choices[0].message.content.strip()
        
        # Save insight to database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            INSERT INTO agent_learnings (target, module, success, insight, date_added)
            VALUES (?, ?, ?, ?, ?)
        """, (
            target,
            module,
            1 if success else 0,
            insight,
            datetime.now().isoformat()
        ))
        conn.commit()
        conn.close()
        
        logger.info(f"Learned from {module} execution: {insight[:100]}...")
        
    except Exception as e:
        logger.error(f"Error learning from execution: {e}")

def update_plan_status(target, module, success):
    """Update the plan status for a target."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Get latest plan for target
    c.execute("""
        SELECT id, plan FROM agent_plans 
        WHERE target = ? 
        ORDER BY created_at DESC LIMIT 1
    """, (target,))
    result = c.fetchone()
    
    if result:
        plan_id, plan_json = result
        plan = json.loads(plan_json)
        
        # Update step status
        for step in plan.get("steps", []):
            if step.get("module") == module:
                step["status"] = "completed" if success else "failed"
                step["completed_at"] = datetime.now().isoformat()
        
        # Update overall plan status
        all_completed = all(step.get("status") == "completed" for step in plan.get("steps", []))
        any_failed = any(step.get("status") == "failed" for step in plan.get("steps", []))
        
        status = "completed" if all_completed else "failed" if any_failed else "in_progress"
        
        # Save updated plan
        c.execute("""
            UPDATE agent_plans 
            SET plan = ?, status = ?, updated_at = ?
            WHERE id = ?
        """, (
            json.dumps(plan),
            status,
            datetime.now().isoformat(),
            plan_id
        ))
    
    conn.commit()
    conn.close()

def analyze_target_results(target):
    """Analyze results for a target and generate insights."""
    if not client:
        return None
    
    # Gather all data for target
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Get findings
    c.execute("SELECT vulnerability, severity, confidence FROM findings WHERE target = ?", (target,))
    findings = [{"vulnerability": row[0], "severity": row[1], "confidence": row[2]} for row in c.fetchall()]
    
    # Get chains
    try:
        c.execute("SELECT name, description, combined_severity FROM chains WHERE target = ?", (target,))
        chains = [{"name": row[0], "description": row[1], "severity": row[2]} for row in c.fetchall()]
    except sqlite3.OperationalError:
        # Chains table might not exist yet
        chains = []
    
    # Get interesting endpoints
    try:
        c.execute("SELECT url FROM endpoints WHERE target = ? AND interesting = 1 LIMIT 50", (target,))
        interesting_endpoints = [row[0] for row in c.fetchall()]
    except sqlite3.OperationalError:
        # Endpoints table might not exist yet
        interesting_endpoints = []
    
    conn.close()
    
    # Send to GPT for analysis
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": """You are an AI agent specializing in bug bounty analysis.
                Review the findings, vulnerability chains, and endpoints for a target to generate insights.
                
                Focus on:
                1. Overall security posture
                2. Most promising vulnerabilities
                3. Patterns or trends in findings
                4. Recommended next steps
                5. Potential high-impact issues that might have been missed
                
                Return a comprehensive analysis in JSON format.
                """},
                {"role": "user", "content": f"""Target: {target}
                
                Findings:
                {json.dumps(findings, indent=2)}
                
                Vulnerability Chains:
                {json.dumps(chains, indent=2)}
                
                Interesting Endpoints:
                {json.dumps(interesting_endpoints, indent=2)}
                
                Provide a comprehensive analysis of this target's security posture and highest-value opportunities.
                """}
            ],
            response_format={"type": "json_object"},
            temperature=0.7
        )
        
        analysis = json.loads(response.choices[0].message.content)
        
        # Save to workspace
        workspace = pathlib.Path("workspace") / target
        workspace.mkdir(parents=True, exist_ok=True)
        analysis_file = workspace / "agent_analysis.json"
        with open(analysis_file, "w") as f:
            json.dump(analysis, f, indent=2)
        
        logger.info(f"Generated analysis for {target}, saved to {analysis_file}")
        return analysis
        
    except Exception as e:
        logger.error(f"Error analyzing results for {target}: {e}")
        return None

def generate_progress_report(target=None):
    """Generate an overall progress report for the agent."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    if target:
        # Get target-specific stats
        c.execute("SELECT COUNT(*) FROM findings WHERE target = ?", (target,))
        findings_count = c.fetchone()[0] or 0
        
        try:
            c.execute("SELECT COUNT(*) FROM chains WHERE target = ?", (target,))
            chains_count = c.fetchone()[0] or 0
        except sqlite3.OperationalError:
            chains_count = 0
        
        try:
            c.execute("SELECT COUNT(*) FROM endpoints WHERE target = ?", (target,))
            endpoints_count = c.fetchone()[0] or 0
        except sqlite3.OperationalError:
            endpoints_count = 0
        
        c.execute("SELECT COUNT(*) FROM agent_runs WHERE target = ?", (target,))
        runs_count = c.fetchone()[0] or 0
        
        c.execute("SELECT COUNT(*) FROM agent_runs WHERE target = ? AND status = 'completed'", (target,))
        successful_runs = c.fetchone()[0] or 0
        
        report = {
            "target": target,
            "findings": findings_count,
            "chains": chains_count,
            "endpoints": endpoints_count,
            "runs": runs_count,
            "successful_runs": successful_runs,
            "success_rate": round((successful_runs / runs_count) * 100, 2) if runs_count else 0,
            "generated_at": datetime.now().isoformat()
        }
    else:
        # Get overall stats
        c.execute("SELECT COUNT(DISTINCT target) FROM findings")
        targets_count = c.fetchone()[0] or 0
        
        c.execute("SELECT COUNT(*) FROM findings")
        findings_count = c.fetchone()[0] or 0
        
        try:
            c.execute("SELECT COUNT(*) FROM chains")
            chains_count = c.fetchone()[0] or 0
        except sqlite3.OperationalError:
            chains_count = 0
        
        try:
            c.execute("SELECT COUNT(*) FROM endpoints")
            endpoints_count = c.fetchone()[0] or 0
        except sqlite3.OperationalError:
            endpoints_count = 0
        
        c.execute("SELECT COUNT(*) FROM agent_runs")
        runs_count = c.fetchone()[0] or 0
        
        c.execute("SELECT COUNT(*) FROM agent_runs WHERE status = 'completed'")
        successful_runs = c.fetchone()[0] or 0
        
        # Get recent learnings
        c.execute("SELECT target, module, insight FROM agent_learnings ORDER BY date_added DESC LIMIT 5")
        recent_learnings = [{"target": row[0], "module": row[1], "insight": row[2]} for row in c.fetchall()]
        
        report = {
            "targets": targets_count,
            "findings": findings_count,
            "chains": chains_count,
            "endpoints": endpoints_count,
            "runs": runs_count,
            "successful_runs": successful_runs,
            "success_rate": round((successful_runs / runs_count) * 100, 2) if runs_count else 0,
            "recent_learnings": recent_learnings,
            "generated_at": datetime.now().isoformat()
        }
    
    conn.close()
    
    # Save report
    if target:
        workspace = pathlib.Path("workspace") / target
        workspace.mkdir(parents=True, exist_ok=True)
        report_path = workspace / "agent_progress_report.json"
    else:
        report_path = pathlib.Path("agent_progress_report.json")
    
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Generated progress report: {report_path}")
    return report

def print_progress_report(report):
    """Print a human-readable progress report."""
    print("\n" + "=" * 60)
    
    if "target" in report:
        # Target-specific report
        print(f"PROGRESS REPORT FOR TARGET: {report['target']}")
        print("=" * 60)
        print(f"Findings discovered: {report['findings']}")
        print(f"Vulnerability chains identified: {report['chains']}")
        print(f"Endpoints cataloged: {report['endpoints']}")
        print(f"Agent actions executed: {report['runs']}")
        print(f"Success rate: {report['success_rate']}%")
    else:
        # Overall report
        print("OVERALL AGENT PROGRESS REPORT")
        print("=" * 60)
        print(f"Targets analyzed: {report['targets']}")
        print(f"Total findings discovered: {report['findings']}")
        print(f"Vulnerability chains identified: {report['chains']}")
        print(f"Endpoints cataloged: {report['endpoints']}")
        print(f"Agent actions executed: {report['runs']}")
        print(f"Success rate: {report['success_rate']}%")
        
        if report.get('recent_learnings'):
            print("\nRecent Learnings:")
            for i, learning in enumerate(report['recent_learnings'], 1):
                print(f"{i}. [{learning['target']} - {learning['module']}] {learning['insight'][:100]}...")
    
    print("=" * 60)

def run_autonomous_cycle(args):
    """Run a full autonomous cycle of the agent."""
    logger.info("Starting autonomous cycle")
    
    # Get and prioritize targets
    if args.target:
        targets = [args.target]
    else:
        all_targets = get_available_targets()
        prioritized = prioritize_targets(all_targets, args.max_targets)
        targets = [t["target"] for t in prioritized]
    
    if not targets:
        logger.warning("No targets available for processing")
        return
    
    # Process each target
    for target in targets:
        logger.info(f"Processing target: {target}")
        
        # Create plan
        plan = create_target_plan(target)
        
        # Execute plan
        execute_plan(plan)
        
        # Analyze results
        analyze_target_results(target)
        
        # Generate progress report
        report = generate_progress_report(target)
        print_progress_report(report)
    
    # Generate overall progress report
    overall_report = generate_progress_report()
    print_progress_report(overall_report)
    
    logger.info("Autonomous cycle completed")

def main():
    args = parse_arguments()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Setup database
    setup_agent_database()
    
    # Execute based on mode
    if args.mode == "plan":
        if not args.target:
            logger.error("Target required for planning mode")
            return 1
        
        plan = create_target_plan(args.target)
        print(json.dumps(plan, indent=2))
        
    elif args.mode == "execute":
        if not args.target:
            logger.error("Target required for execution mode")
            return 1
        
        # Get latest plan
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT plan FROM agent_plans 
            WHERE target = ? 
            ORDER BY created_at DESC LIMIT 1
        """, (args.target,))
        result = c.fetchone()
        conn.close()
        
        if result:
            plan = json.loads(result[0])
            execute_plan(plan)
        else:
            logger.error(f"No plan found for {args.target}")
            return 1
        
    elif args.mode == "analyze":
        if not args.target:
            logger.error("Target required for analysis mode")
            return 1
        
        analysis = analyze_target_results(args.target)
        if analysis:
            print(json.dumps(analysis, indent=2))
        
    elif args.mode == "full" or args.auto:
        run_autonomous_cycle(args)
        
    else:
        logger.error(f"Unknown mode: {args.mode}")
        return 1
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
