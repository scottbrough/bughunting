import os
import sys
import json
import sqlite3
import time
from datetime import datetime
from autogen import ConversableAgent

# Add parent directory to path to access utilities
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import utilities from separate files
from utils.config_loader import get_model_config
from utils.message_utils import (
    create_standard_message, create_plan_message, create_request_message,
    create_response_message, create_error_message, create_result_message,
    message_to_string, message_to_chat_message
)

class OrchestratorAgent:
    """
    Coordinates the overall bug bounty process by delegating tasks to specialized agents,
    monitoring progress and adjusting strategy based on findings.
    """
    
    def __init__(self):
        # Get the configuration for the agent
        model_config = get_model_config("gpt-4o") if os.getenv("USE_ENHANCED_MODEL") else get_model_config()
        
        # Create the ConversableAgent
        self.agent = ConversableAgent(
            name="OrchestratorAgent",
            system_message="""You are the OrchestratorAgent for a bug bounty automation framework. 
            Your responsibilities include:
            1. Selecting and prioritizing targets
            2. Creating execution plans 
            3. Delegating tasks to specialized agents
            4. Monitoring progress and adjusting strategy
            5. Ensuring ROI optimization

            You have access to a database of bug bounty programs, findings, and historical data.
            Use this information to make strategic decisions about resource allocation.""",
            llm_config={
                "config_list": [
                    {
                        "model": model_config["model"],
                        "api_key": model_config["api_key"]
                    }
                ],
                "temperature": 0.2
            }
        )
        
        # Initialize the database connection
        self.db_path = os.getenv("DB_PATH", "bugbounty.db")
    
    def get_db_connection(self):
        """Create a connection to the SQLite database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def get_target_metrics(self, target):
        """Get metrics for a target to assess its potential."""
        conn = self.get_db_connection()
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
            "last_activity": self.get_last_activity(target)
        }
    
    def get_last_activity(self, target):
        """Get the timestamp of the last activity for a target."""
        conn = self.get_db_connection()
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
    
    def prioritize_targets(self, targets, max_targets=3):
        """Prioritize targets based on metrics and potential."""
        if not targets:
            return []
        
        # Get metrics for each target
        target_metrics = [self.get_target_metrics(target) for target in targets]
        
        # For now, simple prioritization without LLM
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
        
        return [{"target": t["target"], "reason": "Automated prioritization"} for t in sorted_targets[:max_targets]]
    
    def create_plan_for_target(self, target):
        """Create an execution plan for a target."""
        # Get target metrics
        metrics = self.get_target_metrics(target)
        
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
        plan_file = os.path.join("workspace", target, "attack_plan.json")
        steps_completed["attack_planning"] = os.path.exists(plan_file)
        
        # Check if reports exist
        reports_dir = os.path.join("workspace", target, "reports")
        steps_completed["reporting"] = os.path.exists(reports_dir) and any(os.listdir(reports_dir)) if os.path.exists(reports_dir) else False
        
        # Create a plan with steps based on what's missing
        plan = {
            "target": target,
            "created_at": datetime.now().isoformat(),
            "steps": []
        }
        
        # Add steps based on what's missing
        if not steps_completed["discovery"]:
            plan["steps"].append({
                "id": len(plan["steps"]) + 1,
                "name": "content_discovery",
                "description": "Discover endpoints and content",
                "agent": "DiscoveryAgent",
                "status": "pending",
                "priority": 1
            })
        
        if not steps_completed["triage"] and steps_completed["discovery"]:
            plan["steps"].append({
                "id": len(plan["steps"]) + 1,
                "name": "vulnerability_testing",
                "description": "Test endpoints for vulnerabilities",
                "agent": "FuzzerAgent",
                "status": "pending",
                "priority": 2
            })
        
        if not steps_completed["chain_detection"] and steps_completed["triage"]:
            plan["steps"].append({
                "id": len(plan["steps"]) + 1,
                "name": "vulnerability_chaining",
                "description": "Analyze vulnerabilities for attack chains",
                "agent": "AnalysisAgent",
                "status": "pending", 
                "priority": 3
            })
        
        if not steps_completed["reporting"] and (steps_completed["verification"] or steps_completed["chain_detection"]):
            plan["steps"].append({
                "id": len(plan["steps"]) + 1,
                "name": "report_generation",
                "description": "Generate report of findings",
                "agent": "ReportingAgent",
                "status": "pending",
                "priority": 4
            })
        
        # Save plan to database
        self.save_plan_to_db(target, plan)
        
        return plan
    
    def save_plan_to_db(self, target, plan):
        """Save a plan to the database."""
        conn = self.get_db_connection()
        c = conn.cursor()
        
        try:
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
        except Exception as e:
            print(f"Error saving plan to database: {e}")
        finally:
            conn.close()
    
    def execute_step(self, target, step, agent):
        """Execute a step in the plan using the appropriate agent."""
        print(f"Executing step {step['name']} for {target} using {step['agent']}")
        
        # Record start in database
        conn = self.get_db_connection()
        c = conn.cursor()
        run_id = None
        
        try:
            c.execute("""
                INSERT INTO agent_runs (target, module, command, status, start_time)
                VALUES (?, ?, ?, ?, ?)
            """, (
                target,
                step['name'],
                f"Autogen {step['agent']} executing {step['name']}",
                "running",
                datetime.now().isoformat()
            ))
            run_id = c.lastrowid
            conn.commit()
        except Exception as e:
            print(f"Error recording step start: {e}")
        finally:
            conn.close()
        
        # Execute the step
        success = False
        result = None
        
        try:
            # The specific execution will depend on the agent implementation
            # For now, we'll just simulate success
            time.sleep(1)  # Simulate execution time
            success = True
            result = {"status": "success", "message": f"Completed {step['name']} for {target}"}
        except Exception as e:
            print(f"Error executing step: {e}")
            result = {"status": "error", "message": str(e)}
        
        # Update run record
        if run_id:
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
                    json.dumps(result),
                    run_id
                ))
                conn.commit()
            except Exception as e:
                print(f"Error updating run record: {e}")
            finally:
                conn.close()
        
        # Update plan status
        self.update_plan_status(target, step['name'], success)
        
        return success, result
    
    def update_plan_status(self, target, step_name, success):
        """Update the plan status for a target."""
        conn = self.get_db_connection()
        c = conn.cursor()
        
        try:
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
                    if step.get("name") == step_name:
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
        except Exception as e:
            print(f"Error updating plan status: {e}")
        finally:
            conn.close()
    
    def run_autonomous_cycle(self, max_targets=3):
        """Run a full autonomous cycle of the agent."""
        print("Starting autonomous cycle")
        
        # Get and prioritize targets
        all_targets = self.get_available_targets()
        prioritized = self.prioritize_targets(all_targets, max_targets)
        targets = [t["target"] for t in prioritized]
        
        if not targets:
            print("No targets available for processing")
            return
        
        print(f"Processing targets: {', '.join(targets)}")
        
        # Process each target
        for target in targets:
            print(f"Processing target: {target}")
            
            # Create plan
            plan = self.create_plan_for_target(target)
            
            # Execute plan
            for step in plan.get("steps", []):
                agent_mapping = {
                    "DiscoveryAgent": None,  # Will be implemented in later phases
                    "FuzzerAgent": None,     # Will be implemented in later phases
                    "AnalysisAgent": None,   # Will be implemented in later phases
                    "ReportingAgent": None   # Will be implemented in later phases
                }
                
                agent = agent_mapping.get(step.get("agent"))
                
                # Skip steps where agent is not implemented yet
                if agent is None:
                    print(f"Skipping step {step['name']} - agent {step['agent']} not implemented yet")
                    continue
                
                success, result = self.execute_step(target, step, agent)
                
                if not success:
                    print(f"Step {step['name']} failed for {target}. Stopping plan execution.")
                    break
            
            # Generate progress report
            self.generate_progress_report(target)
        
        # Generate overall progress report
        self.generate_progress_report()
        
        print("Autonomous cycle completed")
    
    def get_available_targets(self):
        """Get all targets available in the workspace."""
        workspace = os.path.join(os.getcwd(), "workspace")
        if not os.path.exists(workspace):
            return []
        
        return [d for d in os.listdir(workspace) if os.path.isdir(os.path.join(workspace, d))]
    
    def generate_progress_report(self, target=None):
        """Generate a progress report for a target or overall."""
        conn = self.get_db_connection()
        c = conn.cursor()
        
        if target:
            # Target-specific report
            try:
                # Get findings count
                c.execute("SELECT COUNT(*) FROM findings WHERE target = ?", (target,))
                findings_count = c.fetchone()[0] or 0
                
                # Get chains count
                try:
                    c.execute("SELECT COUNT(*) FROM chains WHERE target = ?", (target,))
                    chains_count = c.fetchone()[0] or 0
                except sqlite3.OperationalError:
                    chains_count = 0
                
                # Get endpoints count
                try:
                    c.execute("SELECT COUNT(*) FROM endpoints WHERE target = ?", (target,))
                    endpoints_count = c.fetchone()[0] or 0
                except sqlite3.OperationalError:
                    endpoints_count = 0
                
                # Get runs count
                c.execute("SELECT COUNT(*) FROM agent_runs WHERE target = ?", (target,))
                runs_count = c.fetchone()[0] or 0
                
                # Get successful runs count
                c.execute("SELECT COUNT(*) FROM agent_runs WHERE target = ? AND status = 'completed'", (target,))
                successful_runs = c.fetchone()[0] or 0
                
                # Calculate success rate
                success_rate = (successful_runs / runs_count * 100) if runs_count > 0 else 0
                
                report = {
                    "target": target,
                    "findings": findings_count,
                    "chains": chains_count,
                    "endpoints": endpoints_count,
                    "runs": runs_count,
                    "successful_runs": successful_runs,
                    "success_rate": success_rate,
                    "generated_at": datetime.now().isoformat()
                }
                
                # Save report to file
                workspace_dir = os.path.join(os.getcwd(), "workspace", target)
                os.makedirs(workspace_dir, exist_ok=True)
                
                report_path = os.path.join(workspace_dir, "agent_progress_report.json")
                with open(report_path, "w") as f:
                    json.dump(report, f, indent=2)
                
                print(f"Generated progress report for {target}: {report_path}")
                
                # Also print a summary
                print("\n" + "=" * 60)
                print(f"PROGRESS REPORT FOR TARGET: {target}")
                print("=" * 60)
                print(f"Findings discovered: {findings_count}")
                print(f"Vulnerability chains: {chains_count}")
                print(f"Endpoints cataloged: {endpoints_count}")
                print(f"Actions executed: {runs_count}")
                print(f"Success rate: {success_rate:.1f}%")
                print("=" * 60 + "\n")
                
            except Exception as e:
                print(f"Error generating target report: {e}")
                report = {"error": str(e)}
        
        else:
            # Overall report
            try:
                # Get targets count
                c.execute("SELECT COUNT(DISTINCT target) FROM findings")
                targets_count = c.fetchone()[0] or 0
                
                # Get findings count
                c.execute("SELECT COUNT(*) FROM findings")
                findings_count = c.fetchone()[0] or 0
                
                # Get chains count
                try:
                    c.execute("SELECT COUNT(*) FROM chains")
                    chains_count = c.fetchone()[0] or 0
                except sqlite3.OperationalError:
                    chains_count = 0
                
                # Get endpoints count
                try:
                    c.execute("SELECT COUNT(*) FROM endpoints")
                    endpoints_count = c.fetchone()[0] or 0
                except sqlite3.OperationalError:
                    endpoints_count = 0
                
                # Get runs count
                c.execute("SELECT COUNT(*) FROM agent_runs")
                runs_count = c.fetchone()[0] or 0
                
                # Get successful runs count
                c.execute("SELECT COUNT(*) FROM agent_runs WHERE status = 'completed'")
                successful_runs = c.fetchone()[0] or 0
                
                # Calculate success rate
                success_rate = (successful_runs / runs_count * 100) if runs_count > 0 else 0
                
                # Get recent learnings
                try:
                    c.execute("SELECT target, module, insight FROM agent_learnings ORDER BY date_added DESC LIMIT 5")
                    recent_learnings = [{"target": row[0], "module": row[1], "insight": row[2]} for row in c.fetchall()]
                except sqlite3.OperationalError:
                    recent_learnings = []
                
                report = {
                    "targets": targets_count,
                    "findings": findings_count,
                    "chains": chains_count,
                    "endpoints": endpoints_count,
                    "runs": runs_count,
                    "successful_runs": successful_runs,
                    "success_rate": success_rate,
                    "recent_learnings": recent_learnings,
                    "generated_at": datetime.now().isoformat()
                }
                
                # Save report to file
                report_path = os.path.join(os.getcwd(), "agent_progress_report.json")
                with open(report_path, "w") as f:
                    json.dump(report, f, indent=2)
                
                print(f"Generated overall progress report: {report_path}")
                
                # Also print a summary
                print("\n" + "=" * 60)
                print("OVERALL AGENT PROGRESS REPORT")
                print("=" * 60)
                print(f"Targets analyzed: {targets_count}")
                print(f"Findings discovered: {findings_count}")
                print(f"Vulnerability chains: {chains_count}")
                print(f"Endpoints cataloged: {endpoints_count}")
                print(f"Actions executed: {runs_count}")
                print(f"Success rate: {success_rate:.1f}%")
                
                if recent_learnings:
                    print("\nRecent Learnings:")
                    for i, learning in enumerate(recent_learnings, 1):
                        print(f"{i}. [{learning['target']} - {learning['module']}] {learning['insight'][:100]}...")
                
                print("=" * 60 + "\n")
                
            except Exception as e:
                print(f"Error generating overall report: {e}")
                report = {"error": str(e)}
        
        conn.close()
        
        return report
    
    def handle_agent_message(self, message):
        """Handle a message from another agent."""
        print(f"Received message: {message}")
        
        # Process based on message type
        if message["type"] == "request":
            # Handle request from another agent
            action = message["metadata"]["action"]
            
            if action == "create_plan":
                # Create a plan for a target
                target = message["metadata"]["parameters"].get("target")
                plan = self.create_plan_for_target(target)
                
                # Return a response
                return create_response_message(
                    "OrchestratorAgent",
                    message["metadata"]["from"],
                    action,
                    {"plan": plan}
                )
            
            elif action == "update_plan_status":
                # Update a plan's status
                target = message["metadata"]["parameters"].get("target")
                step_name = message["metadata"]["parameters"].get("step_name")
                success = message["metadata"]["parameters"].get("success", False)
                
                self.update_plan_status(target, step_name, success)
                
                # Return a response
                return create_response_message(
                    "OrchestratorAgent", 
                    message["metadata"]["from"],
                    action,
                    {"status": "updated"}
                )
            
            else:
                # Unknown action
                return create_error_message(
                    "OrchestratorAgent",
                    message["metadata"]["from"],
                    action,
                    f"Unknown action: {action}"
                )
        
        elif message["type"] == "response":
            # Process response from an agent
            pass  # Will implement in later phase
        
        elif message["type"] == "error":
            # Handle error from an agent
            print(f"Error from {message['metadata']['from']}: {message['metadata']['error']}")
        
        elif message["type"] == "result":
            # Process result from an agent
            pass  # Will implement in later phase
        
        else:
            # Unknown message type
            print(f"Unknown message type: {message['type']}")

    def send_message_to_agent(self, to_agent, message):
        """Send a message to another agent."""
        # In the actual implementation, this would use Autogen's messaging
        # For now, just print the message
        print(f"Sending message: {message}")
        
        # Simulate receiving a response
        # This will be replaced with actual agent communication
        if to_agent == "DiscoveryAgent" and message["type"] == "request":
            return create_response_message(
                "DiscoveryAgent",
                "OrchestratorAgent",
                message["metadata"]["action"],
                {"status": "simulated_success"}
            )
        
        return None