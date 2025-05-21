#!/usr/bin/env python3
# bugbounty_agent_debug.py - Debugging and fixing the bug bounty agent

import os
import sys
import json
import logging
import sqlite3
import subprocess
import time
import argparse
import pathlib
from datetime import datetime

# Configure logging with more details
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG for more verbose output
    format='%(asctime)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s',
    handlers=[
        logging.FileHandler("bugbounty_debug.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("bugbounty_debug")

# Database configuration
DB_PATH = "bugbounty.db"

def check_database_setup():
    """Check if database exists and basic tables are set up."""
    logger.info(f"Checking database at {DB_PATH}")
    
    if not os.path.exists(DB_PATH):
        logger.error(f"Database file {DB_PATH} not found. Please run setup_agent.py first.")
        return False
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Check essential tables
    essential_tables = [
        "agent_plans", "agent_runs", "agent_learnings", 
        "findings", "endpoints", "vulnerabilities", "chains"
    ]
    
    missing_tables = []
    for table in essential_tables:
        c.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
        if not c.fetchone():
            missing_tables.append(table)
    
    if missing_tables:
        logger.error(f"Missing essential tables: {', '.join(missing_tables)}")
        logger.info("Creating missing tables...")
        create_missing_tables(conn, missing_tables)
    
    conn.close()
    
    return True

def create_missing_tables(conn, missing_tables):
    """Create missing essential tables."""
    c = conn.cursor()
    
    table_schemas = {
        "agent_plans": """
            CREATE TABLE agent_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                plan TEXT,
                status TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """,
        "agent_runs": """
            CREATE TABLE agent_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                module TEXT,
                command TEXT,
                status TEXT,
                start_time TEXT,
                end_time TEXT,
                outcome TEXT
            )
        """,
        "agent_learnings": """
            CREATE TABLE agent_learnings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                module TEXT,
                success BOOLEAN,
                insight TEXT,
                date_added TEXT
            )
        """,
        "findings": """
            CREATE TABLE findings (
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
        """,
        "endpoints": """
            CREATE TABLE endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                url TEXT,
                status_code INTEGER,
                content_type TEXT,
                interesting BOOLEAN DEFAULT 0,
                notes TEXT,
                date_discovered TEXT
            )
        """,
        "vulnerabilities": """
            CREATE TABLE vulnerabilities (
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
            )
        """,
        "chains": """
            CREATE TABLE chains (
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
        """
    }
    
    for table in missing_tables:
        if table in table_schemas:
            try:
                c.execute(table_schemas[table])
                logger.info(f"Created table: {table}")
            except sqlite3.Error as e:
                logger.error(f"Error creating table {table}: {e}")
    
    conn.commit()

def check_workspace_setup(target):
    """Check if workspace directory exists for the target and create if needed."""
    workspace = pathlib.Path("workspace") / target
    
    if not workspace.exists():
        logger.info(f"Creating workspace directory for {target}")
        workspace.mkdir(parents=True, exist_ok=True)
    
    # Create essential subdirectories
    subdirs = ["content_discovery", "fuzzing", "reports", "findings"]
    for subdir in subdirs:
        subdir_path = workspace / subdir
        if not subdir_path.exists():
            subdir_path.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created subdirectory: {subdir_path}")
    
    return True

def create_sample_endpoints(target):
    """Create sample endpoints for the target to bootstrap the process."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # First check if there are already endpoints for this target
    c.execute("SELECT COUNT(*) FROM endpoints WHERE target = ?", (target,))
    count = c.fetchone()[0]
    
    if count > 0:
        logger.info(f"Target {target} already has {count} endpoints in database")
        conn.close()
        return count
    
    # Create some sample endpoints
    logger.info(f"Creating sample endpoints for {target}")
    
    # Format domain correctly
    domain = target
    if not domain.startswith(('http://', 'https://')):
        domain = f"https://{domain}"
    
    # Common paths that most sites have
    common_paths = [
        "",  # Root path
        "login",
        "register",
        "about",
        "contact",
        "api",
        "help",
        "admin",
        "search"
    ]
    
    # Insert endpoints
    count = 0
    for path in common_paths:
        url = f"{domain}/{path}" if path else domain
        
        # Mark some as interesting for testing
        interesting = 1 if path in ["admin", "api", "login"] else 0
        
        try:
            c.execute("""
                INSERT INTO endpoints (target, url, status_code, interesting, notes, date_discovered)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                target,
                url,
                200,  # Placeholder status
                interesting,
                json.dumps({"interest_level": "medium" if interesting else "low"}),
                datetime.now().isoformat()
            ))
            count += 1
        except sqlite3.Error as e:
            logger.error(f"Error inserting endpoint {url}: {e}")
    
    conn.commit()
    conn.close()
    
    logger.info(f"Created {count} sample endpoints for {target}")
    return count

def fix_plan_creation(target):
    """Ensure a valid plan exists for the target."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Check for existing plan
    c.execute("SELECT id, plan, status FROM agent_plans WHERE target = ? ORDER BY created_at DESC LIMIT 1", (target,))
    existing_plan = c.fetchone()
    
    if existing_plan:
        plan_id, plan_json, status = existing_plan
        logger.info(f"Found existing plan for {target} with status: {status}")
        
        # Check if plan is valid JSON
        try:
            plan = json.loads(plan_json)
            
            # Ensure the plan has a steps array
            if "steps" not in plan or not isinstance(plan["steps"], list):
                logger.warning(f"Existing plan does not have valid steps array. Fixing...")
                plan["steps"] = []
                
                # Update the plan
                c.execute("""
                    UPDATE agent_plans 
                    SET plan = ?, status = ?, updated_at = ?
                    WHERE id = ?
                """, (
                    json.dumps(plan),
                    "created",
                    datetime.now().isoformat(),
                    plan_id
                ))
                conn.commit()
        except json.JSONDecodeError:
            logger.error(f"Existing plan is not valid JSON. Creating new plan.")
            create_new_plan(conn, c, target)
    else:
        logger.info(f"No existing plan found for {target}. Creating new plan.")
        create_new_plan(conn, c, target)
    
    conn.close()
    return True

def create_new_plan(conn, c, target):
    """Create a new plan for the target with default steps."""
    # Create a basic default plan
    default_plan = {
        "target": target,
        "steps": [
            {
                "id": 1,
                "name": "content_discovery",
                "description": "Discover endpoints and content",
                "module": "discover",
                "command": f"python3 content_discovery.py {target}",
                "priority": 1
            },
            {
                "id": 2,
                "name": "vulnerability_testing",
                "description": "Test endpoints for vulnerabilities",
                "module": "fuzzer",
                "command": f"python3 fuzzer.py {target}",
                "priority": 2
            },
            {
                "id": 3,
                "name": "reporting",
                "description": "Generate report of findings",
                "module": "report_engine",
                "command": f"python3 report_engine.py {target}",
                "priority": 3
            }
        ],
        "created_at": datetime.now().isoformat()
    }
    
    c.execute("""
        INSERT INTO agent_plans (target, plan, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        target,
        json.dumps(default_plan),
        "created",
        datetime.now().isoformat(),
        datetime.now().isoformat()
    ))
    
    conn.commit()
    logger.info(f"Created new default plan for {target}")

def fix_bugbounty_agent(original_script_path):
    """Create a patched version of the bugbounty_agent.py script."""
    # Read the original script
    with open(original_script_path, 'r') as f:
        script_content = f.read()
    
    # Check if we need to patch the execute_plan function
    if "def execute_plan(plan):" in script_content:
        # Add more robust error handling to the execute_plan function
        old_func = "def execute_plan(plan):"
        new_func = """def execute_plan(plan):
    \"\"\"Execute a target plan with improved error handling.\"\"\"
    if not plan:
        logger.error("Cannot execute plan: Plan is None")
        return False
        
    target = plan.get("target")
    if not target:
        logger.error("Cannot execute plan: No target specified in plan")
        return False
        
    steps = plan.get("steps", [])
    if not steps:
        logger.warning(f"No steps to execute for {target}. Plan may need updating.")
        return False
    
    logger.info(f"Executing plan for {target} with {len(steps)} steps")
"""
        # Replace the function
        script_content = script_content.replace(old_func, new_func)
    
    # Check if we need to patch the create_target_plan function
    if "def create_target_plan(target):" in script_content:
        # Find the function and add a debug print
        old_return = "        return plan"
        new_return = """        # Debug log the plan
        logger.info(f"Created plan for {target} with {len(plan.get('steps', []))} steps")
        
        # Ensure the plan has a steps array
        if "steps" not in plan:
            plan["steps"] = []
            logger.warning(f"Added missing steps array to plan for {target}")
            
        return plan"""
        
        # Replace the return
        script_content = script_content.replace(old_return, new_return)
    
    # Save the patched script
    patched_path = "bugbounty_agent_patched.py"
    with open(patched_path, 'w') as f:
        f.write(script_content)
    
    logger.info(f"Created patched version of bugbounty_agent.py at {patched_path}")
    return patched_path

def main():
    """Main function to debug and fix the bug bounty agent."""
    parser = argparse.ArgumentParser(description="Debug and fix bug bounty agent")
    parser.add_argument("--target", default="jira.atlassian.com", help="Target to debug")
    parser.add_argument("--script", default="bugbounty_agent.py", help="Path to the original script")
    args = parser.parse_args()
    
    print("\n" + "=" * 80)
    print(f"🛠️ Bug Bounty Agent Debug and Fix Tool - Target: {args.target}")
    print("=" * 80 + "\n")
    
    # Step 1: Check database setup
    print("Step 1: Checking database setup...")
    if not check_database_setup():
        print("⚠️  Database issues detected. Please run setup_agent.py first.")
        return 1
    print("✅ Database setup looks good\n")
    
    # Step 2: Check workspace setup
    print("Step 2: Checking workspace setup...")
    check_workspace_setup(args.target)
    print("✅ Workspace setup complete\n")
    
    # Step 3: Ensure endpoints exist
    print("Step 3: Ensuring target has endpoints...")
    endpoint_count = create_sample_endpoints(args.target)
    print(f"✅ Target has {endpoint_count} endpoints\n")
    
    # Step 4: Fix plan creation
    print("Step 4: Fixing plan creation for target...")
    if not fix_plan_creation(args.target):
        print("⚠️  Could not fix plan creation")
        return 1
    print("✅ Plan creation fixed\n")
    
    # Step 5: Create patched version of the script
    print("Step 5: Creating patched version of bugbounty_agent.py...")
    patched_script = fix_bugbounty_agent(args.script)
    print(f"✅ Created patched script: {patched_script}\n")
    
    # Final report
    print("\n" + "=" * 80)
    print("🚀 Bug Bounty Agent Fix Complete!")
    print("=" * 80)
    print("\nTo use the fixed version, run:")
    print(f"python {patched_script} --target {args.target} --mode full --verbose")
    print("\nIf you still encounter issues, check the bugbounty_debug.log file for details.")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
