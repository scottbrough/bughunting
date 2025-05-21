#!/usr/bin/env python3
# fix_plan_creation.py - Fix plan creation issues for bug bounty agent

import os
import sys
import json
import sqlite3
import logging
import argparse
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("plan_fix.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("plan_fix")

# Database configuration
DB_PATH = "bugbounty.db"

def get_db_connection():
    """Create a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def check_plan_issues(target):
    """Check for issues with the plan for the target."""
    conn = get_db_connection()
    c = conn.cursor()
    
    # Check for existing plan
    c.execute("SELECT id, plan FROM agent_plans WHERE target = ? ORDER BY created_at DESC LIMIT 1", (target,))
    result = c.fetchone()
    
    if not result:
        logger.info(f"No plan found for target {target}")
        conn.close()
        return False, None, None
    
    plan_id, plan_json = result
    
    try:
        plan = json.loads(plan_json)
        issues = []
        
        # Check if 'target' field exists and is correct
        if 'target' not in plan:
            issues.append("Missing 'target' field")
        elif plan['target'] != target:
            issues.append(f"'target' field is incorrect: '{plan['target']}' (should be '{target}')")
        
        # Check if 'steps' field exists and has content
        if 'steps' not in plan:
            issues.append("Missing 'steps' field")
        elif not isinstance(plan['steps'], list):
            issues.append("'steps' field is not a list")
        elif len(plan['steps']) == 0:
            issues.append("'steps' field is empty")
        
        conn.close()
        return len(issues) > 0, plan_id, issues
    
    except json.JSONDecodeError:
        logger.error(f"Plan for {target} is not valid JSON")
        conn.close()
        return True, plan_id, ["Invalid JSON"]

def fix_plan(target):
    """Fix the plan for the target."""
    has_issues, plan_id, issues = check_plan_issues(target)
    
    if not has_issues:
        logger.info(f"Plan for {target} has no issues")
        return True
    
    logger.info(f"Plan for {target} has issues: {issues}")
    
    # Create a new correctly formatted plan
    new_plan = {
        "target": target,
        "steps": [
            {
                "id": 1,
                "name": "content_discovery",
                "description": "Discover endpoints and content",
                "module": "discover",
                "command": f"python3 content_discovery.py {target}",
                "agent": "DiscoveryAgent",
                "priority": 1,
                "status": "pending"
            },
            {
                "id": 2,
                "name": "vulnerability_testing",
                "description": "Test endpoints for vulnerabilities",
                "module": "fuzzer",
                "command": f"python3 fuzzer.py {target}",
                "agent": "FuzzerAgent",
                "priority": 2,
                "status": "pending"
            },
            {
                "id": 3,
                "name": "reporting",
                "description": "Generate report of findings",
                "module": "report_engine",
                "command": f"python3 report_engine.py {target}",
                "agent": "ReportingAgent",
                "priority": 3,
                "status": "pending"
            }
        ],
        "created_at": datetime.now().isoformat()
    }
    
    conn = get_db_connection()
    c = conn.cursor()
    
    if plan_id:
        # Update existing plan
        c.execute("""
            UPDATE agent_plans 
            SET plan = ?, status = ?, updated_at = ?
            WHERE id = ?
        """, (
            json.dumps(new_plan),
            "created",
            datetime.now().isoformat(),
            plan_id
        ))
        logger.info(f"Updated plan for {target} with id {plan_id}")
    else:
        # Create new plan
        c.execute("""
            INSERT INTO agent_plans (target, plan, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            target,
            json.dumps(new_plan),
            "created",
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        logger.info(f"Created new plan for {target}")
    
    conn.commit()
    conn.close()
    
    return True

def patch_create_target_plan_function():
    """Create a patch for the create_target_plan function in bugbounty_agent.py."""
    patch = """
def create_target_plan(target):
    \"\"\"Create an execution plan for a target.\"\"\"
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
                {"role": "system", "content": \"\"\"You are an AI agent specializing in bug bounty planning.
                Based on the current state of a target, create a detailed execution plan.
                
                Your plan should specify:
                1. Which modules to run and in what order
                2. Any specific parameters or options
                3. Success criteria for each step
                4. Dependencies between steps
                
                Return a JSON object with the plan structure.
                \"\"\"},
                {"role": "user", "content": f\"\"\"Target: {target}
                
                Current metrics:
                {json.dumps(metrics, indent=2)}
                
                Steps already completed:
                {json.dumps(steps_completed, indent=2)}
                
                Create a detailed execution plan for this target.
                \"\"\"}
            ],
            response_format={"type": "json_object"},
            temperature=0.7
        )
        
        plan = json.loads(response.choices[0].message.content)
        
        # Ensure target field is correct
        if "target" not in plan or plan["target"] != target:
            logger.warning(f"Plan missing target or incorrect target. Setting target to {target}")
            plan["target"] = target
        
        # Ensure steps field exists
        if "steps" not in plan or not isinstance(plan["steps"], list):
            logger.warning(f"Plan missing steps or steps is not a list. Creating default steps for {target}")
            plan["steps"] = [
                {
                    "id": 1,
                    "name": "content_discovery",
                    "description": "Discover endpoints and content",
                    "module": "discover",
                    "command": f"python3 content_discovery.py {target}",
                    "agent": "DiscoveryAgent",
                    "priority": 1, 
                    "status": "pending"
                },
                {
                    "id": 2,
                    "name": "vulnerability_testing",
                    "description": "Test endpoints for vulnerabilities",
                    "module": "fuzzer",
                    "command": f"python3 fuzzer.py {target}",
                    "agent": "FuzzerAgent",
                    "priority": 2,
                    "status": "pending"
                },
                {
                    "id": 3,
                    "name": "reporting",
                    "description": "Generate report of findings", 
                    "module": "report_engine",
                    "command": f"python3 report_engine.py {target}",
                    "agent": "ReportingAgent",
                    "priority": 3,
                    "status": "pending"
                }
            ]
        
        # Save plan to database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(\"\"\"
            INSERT INTO agent_plans (target, plan, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        \"\"\", (
            target,
            json.dumps(plan),
            "created",
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        conn.commit()
        conn.close()
        
        logger.info(f"Plan saved to database for {target}")
        logger.info(f"Created plan for {target} with {len(plan.get('steps', []))} steps")
        
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
                "id": 1,
                "name": "content_discovery",
                "description": "Discover endpoints and content",
                "module": "discover",
                "command": f"python3 content_discovery.py {target}",
                "agent": "DiscoveryAgent",
                "priority": 1,
                "status": "pending"
            })
        
        if not steps_completed["triage"] and steps_completed["discovery"]:
            basic_plan["steps"].append({
                "id": len(basic_plan["steps"]) + 1,
                "name": "vulnerability_testing",
                "description": "Test endpoints for vulnerabilities",
                "module": "fuzzer",
                "command": f"python3 fuzzer.py {target}",
                "agent": "FuzzerAgent",
                "priority": 2,
                "status": "pending"
            })
            
        if not steps_completed["attack_planning"] and steps_completed["triage"]:
            basic_plan["steps"].append({
                "id": len(basic_plan["steps"]) + 1,
                "name": "attack_planning",
                "description": "Plan attacks based on findings",
                "module": "attack_coordinator",
                "command": f"python3 attack_coordinator.py {target}",
                "agent": "AttackPlannerAgent",
                "priority": 3,
                "status": "pending"
            })
            
        if not steps_completed["verification"] and steps_completed["attack_planning"]:
            basic_plan["steps"].append({
                "id": len(basic_plan["steps"]) + 1,
                "name": "vulnerability_verification",
                "description": "Verify vulnerabilities",
                "module": "verify",
                "command": f"python3 verify.py {target}",
                "agent": "VerificationAgent",
                "priority": 4,
                "status": "pending"
            })
            
        if not steps_completed["chain_detection"] and steps_completed["triage"]:
            basic_plan["steps"].append({
                "id": len(basic_plan["steps"]) + 1,
                "name": "vulnerability_chaining",
                "description": "Detect vulnerability chains",
                "module": "chain_detector",
                "command": f"python3 chain_detector.py {target}",
                "agent": "ChainDetectorAgent",
                "priority": 5,
                "status": "pending"
            })
            
        if not steps_completed["reporting"] and (steps_completed["verification"] or steps_completed["chain_detection"]):
            basic_plan["steps"].append({
                "id": len(basic_plan["steps"]) + 1,
                "name": "reporting",
                "description": "Generate report of findings",
                "module": "report_engine",
                "command": f"python3 report_engine.py {target}",
                "agent": "ReportingAgent",
                "priority": 6,
                "status": "pending"
            })
        
        # If still no steps, add default steps
        if len(basic_plan["steps"]) == 0:
            logger.warning(f"Fallback plan has no steps. Adding default steps.")
            basic_plan["steps"] = [
                {
                    "id": 1,
                    "name": "content_discovery",
                    "description": "Discover endpoints and content",
                    "module": "discover",
                    "command": f"python3 content_discovery.py {target}",
                    "agent": "DiscoveryAgent",
                    "priority": 1,
                    "status": "pending"
                },
                {
                    "id": 2,
                    "name": "vulnerability_testing",
                    "description": "Test endpoints for vulnerabilities",
                    "module": "fuzzer",
                    "command": f"python3 fuzzer.py {target}",
                    "agent": "FuzzerAgent",
                    "priority": 2,
                    "status": "pending"
                },
                {
                    "id": 3,
                    "name": "reporting",
                    "description": "Generate report of findings",
                    "module": "report_engine",
                    "command": f"python3 report_engine.py {target}",
                    "agent": "ReportingAgent",
                    "priority": 3,
                    "status": "pending"
                }
            ]
        
        return basic_plan
"""
    
    # Save the patch
    with open("create_target_plan_patch.py", "w") as f:
        f.write(patch)
    
    return "create_target_plan_patch.py"

def apply_patch_to_script(script_path, function_name, patch_file):
    """Apply the patch to the script."""
    # Read the original script
    with open(script_path, 'r') as f:
        script_content = f.read()
    
    # Read the patch
    with open(patch_file, 'r') as f:
        patch_content = f.read()
    
    # Find the start of the function
    function_start = script_content.find(f"def {function_name}(")
    if function_start == -1:
        logger.error(f"Function {function_name} not found in {script_path}")
        return False
    
    # Find the end of the function
    next_function_start = script_content.find("def ", function_start + 1)
    if next_function_start == -1:
        # This is the last function in the file
        function_end = len(script_content)
    else:
        function_end = next_function_start
    
    # Replace the function
    new_script_content = script_content[:function_start] + patch_content + script_content[function_end:]
    
    # Save the patched script
    patched_path = f"{script_path.replace('.py', '')}_patched_v2.py"
    with open(patched_path, 'w') as f:
        f.write(new_script_content)
    
    logger.info(f"Created patched script at {patched_path}")
    return patched_path

def main():
    """Main function to fix plan creation issues."""
    parser = argparse.ArgumentParser(description="Fix plan creation issues for bug bounty agent")
    parser.add_argument("--target", default="jira.atlassian.com", help="Target to fix plan for")
    parser.add_argument("--script", default="bugbounty_agent.py", help="Path to the original script")
    args = parser.parse_args()
    
    print("\n" + "=" * 70)
    print(f"🛠️ Bug Bounty Agent Plan Fix - Target: {args.target}")
    print("=" * 70 + "\n")
    
    # Step 1: Check and fix plan
    print("Step 1: Checking plan for issues...")
    has_issues, plan_id, issues = check_plan_issues(args.target)
    
    if has_issues:
        print(f"Issues found: {issues}")
        fix_plan(args.target)
        print("✅ Plan fixed\n")
    else:
        print("✅ Plan has no issues\n")
    
    # Step 2: Create a patch for the create_target_plan function
    print("Step 2: Creating patch for create_target_plan function...")
    patch_file = patch_create_target_plan_function()
    print(f"✅ Patch created: {patch_file}\n")
    
    # Step 3: Apply the patch to the script
    print("Step 3: Applying patch to script...")
    if os.path.exists(args.script):
        patched_script = apply_patch_to_script(args.script, "create_target_plan", patch_file)
        if patched_script:
            print(f"✅ Patched script created: {patched_script}\n")
        else:
            print("❌ Failed to apply patch\n")
    else:
        print(f"❌ Script not found: {args.script}\n")
    
    # Final report
    print("\n" + "=" * 70)
    print("🚀 Bug Bounty Agent Plan Fix Complete!")
    print("=" * 70)
    print("\nTo use the fixed version, run:")
    if 'patched_script' in locals():
        print(f"python {patched_script} --target {args.target} --mode full --verbose")
    else:
        print(f"python bugbounty_agent.py --target {args.target} --mode full --verbose")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
