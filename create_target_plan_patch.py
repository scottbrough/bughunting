
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
