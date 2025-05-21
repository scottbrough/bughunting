#!/usr/bin/env python3
# autogen_integration.py - Autogen integration and agent setup for bug bounty automation

import os
import sys
import json
import logging
from dotenv import load_dotenv
import autogen
from autogen import ConversableAgent, Agent

# Ensure environment variables are loaded
try:
    load_dotenv()
except Exception as e:
    print(f"Warning: Error loading .env file: {e}")

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import agents with error handling
try:
    from agents.orchestrator import OrchestratorAgent
    from agents.discovery import DiscoveryAgent
    from agents.fuzzer import FuzzerAgent
except ImportError as e:
    print(f"Error importing agent modules: {e}")
    print("Make sure you have the correct directory structure.")
    sys.exit(1)

def init_agents():
    """Initialize and return the agent instances."""
    # Create agent instances
    orchestrator = OrchestratorAgent()
    discovery = DiscoveryAgent()
    fuzzer = FuzzerAgent()
    
    return {
        "orchestrator": orchestrator,
        "discovery": discovery,
        "fuzzer": fuzzer
    }

def setup_agent_group(agents):
    """Set up an Autogen agent group."""
    # Create the agent group
    agent_group = autogen.AgentGroup(
        name="BugBountyGroup",
        agents=[
            agents["orchestrator"].agent,
            agents["discovery"].agent,
            agents["fuzzer"].agent
        ],
        max_consecutive_auto_reply=3
    )
    
    return agent_group

def execute_bug_bounty_workflow(target, agents, options=None):
    """Execute a complete bug bounty workflow on a target."""
    logging.info(f"Starting bug bounty workflow for {target}")
    
    # Have the orchestrator create a plan
    plan = agents["orchestrator"].create_plan_for_target(target)
    print(f"Created plan for {target}:")
    print(json.dumps(plan, indent=2))
    
    # Execute each step in the plan
    for step in plan.get("steps", []):
        # Determine which agent should handle the step
        agent_name = step.get("agent")
        if not agent_name:
            continue
        
        print(f"\nExecuting step: {step['name']} with {agent_name}")
        
        if agent_name == "DiscoveryAgent" and step['name'] == "content_discovery":
            # Send a request to the DiscoveryAgent
            from utils.message_utils import create_request_message
            
            request = create_request_message(
                "OrchestratorAgent",
                "DiscoveryAgent",
                "discover_endpoints",
                {"target": target, "options": options}
            )
            
            # Get response
            response = agents["discovery"].handle_agent_message(request)
            
            # Process response
            if response and response["type"] == "response":
                result = response["metadata"]["result"]
                print(f"Discovery completed with status: {result['status']}")
                print(f"Found {result.get('endpoints_found', 0)} endpoints, {result.get('interesting_endpoints', 0)} interesting")
                
                # Update plan status
                agents["orchestrator"].update_plan_status(
                    target, step['name'], result['status'] == "success"
                )
            else:
                print(f"Error executing {step['name']}: No valid response received")
        
        elif agent_name == "FuzzerAgent" and step['name'] == "vulnerability_testing":
            # Send a request to the FuzzerAgent
            from utils.message_utils import create_request_message
            
            fuzzer_options = {
                "threads": options.get("threads", 5) if options else 5,
                "delay": options.get("delay", 0.2) if options else 0.2,
                "timeout": options.get("timeout", 10) if options else 10,
                "max_urls": options.get("max_urls", 25) if options else 25,
                "max_payloads": options.get("max_payloads", 10) if options else 10,
                "vuln_types": "all"
            }
            
            request = create_request_message(
                "OrchestratorAgent",
                "FuzzerAgent",
                "fuzz_target",
                {"target": target, "options": fuzzer_options}
            )
            
            # Get response
            response = agents["fuzzer"].handle_agent_message(request)
            
            # Process response
            if response and response["type"] == "response":
                result = response["metadata"]["result"]
                print(f"Fuzzing completed with status: {result['status']}")
                print(f"Found {result.get('vulnerabilities_found', 0)} vulnerabilities, created {result.get('findings_created', 0)} findings")
                
                # Update plan status
                agents["orchestrator"].update_plan_status(
                    target, step['name'], result['status'] == "success"
                )
            else:
                print(f"Error executing {step['name']}: No valid response received")
    
    # Generate a progress report
    report = agents["orchestrator"].generate_progress_report(target)
    print("\nProgress Report:")
    print(json.dumps(report, indent=2))
    
    return report

def main():
    """Main entry point for autogen integration."""
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description="Run bug bounty workflow with Autogen")
    parser.add_argument("target", help="Target domain to analyze")
    parser.add_argument("--depth", type=int, default=2, help="Discovery recursion depth")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print(f"Initializing bug bounty workflow for {args.target}...")
    
    # Initialize agents
    agents = init_agents()
    
    # Execute workflow
    options = {
        "depth": args.depth,
        "threads": 10,
        "timeout": 30
    }
    
    execute_bug_bounty_workflow(args.target, agents, options)
    
    print("\nWorkflow completed!")

if __name__ == "__main__":
    main()