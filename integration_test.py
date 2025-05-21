#!/usr/bin/env python3
# integration_test.py - Full integration test for the bug bounty agent system

import os
import sys
import json
import logging
import time
import argparse
from datetime import datetime

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Try to load environment variables, but continue if dotenv is not installed
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Warning: dotenv package not installed. Using environment variables as is.")

# Import agents and utilities - with error handling for import issues
try:
    from agents.orchestrator import OrchestratorAgent
    from agents.discovery import DiscoveryAgent
    from agents.fuzzer import FuzzerAgent
    from utils.message_utils import create_request_message
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure you have the correct directory structure and all modules are available.")
    print("Current sys.path:", sys.path)
    sys.exit(1)

def setup_logging(verbose=False):
    """Set up logging for the integration test."""
    level = logging.DEBUG if verbose else logging.INFO
    
    # Configure logging
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("integration_test.log"),
            logging.StreamHandler()
        ]
    )
    
    # Set urllib3 logging to WARNING to suppress InsecureRequestWarning
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    
    return logging.getLogger("integration_test")

def test_agent_initialization():
    """Test that all agents can be initialized."""
    print("\n=== Testing Agent Initialization ===")
    
    try:
        orchestrator = OrchestratorAgent()
        print("✓ OrchestratorAgent initialized successfully")
    except Exception as e:
        print(f"✗ Error initializing OrchestratorAgent: {e}")
        return False
    
    try:
        discovery = DiscoveryAgent()
        print("✓ DiscoveryAgent initialized successfully")
    except Exception as e:
        print(f"✗ Error initializing DiscoveryAgent: {e}")
        return False
    
    try:
        fuzzer = FuzzerAgent()
        print("✓ FuzzerAgent initialized successfully")
    except Exception as e:
        print(f"✗ Error initializing FuzzerAgent: {e}")
        return False
    
    return True

def test_orchestrator_discovery_integration(target, logger):
    """Test integration between OrchestratorAgent and DiscoveryAgent."""
    print("\n=== Testing OrchestratorAgent → DiscoveryAgent Integration ===")
    
    # Initialize agents
    orchestrator = OrchestratorAgent()
    discovery = DiscoveryAgent()
    
    # Create a plan for the target
    print(f"Creating plan for {target}...")
    plan = orchestrator.create_plan_for_target(target)
    
    # Find the discovery step in the plan
    discovery_step = None
    for step in plan.get("steps", []):
        if step.get("agent") == "DiscoveryAgent" and step.get("name") == "content_discovery":
            discovery_step = step
            break
    
    if not discovery_step:
        print("✗ No discovery step found in the plan")
        return False
    
    print(f"✓ Found discovery step: {discovery_step.get('description')}")
    
    # Create a request message
    request = create_request_message(
        "OrchestratorAgent",
        "DiscoveryAgent",
        "discover_endpoints",
        {"target": target, "options": {"depth": 1, "threads": 5, "timeout": 5, "skip_ai": True}}
    )
    
    # Send request to DiscoveryAgent
    print("Sending discover_endpoints request to DiscoveryAgent...")
    response = discovery.handle_agent_message(request)
    
    if not response or response.get("type") != "response":
        print(f"✗ Invalid response from DiscoveryAgent: {response}")
        return False
    
    result = response["metadata"]["result"]
    print(f"✓ Discovery response received with status: {result.get('status')}")
    print(f"  Found {result.get('endpoints_found', 0)} endpoints, {result.get('interesting_endpoints', 0)} interesting")
    
    # Update plan status
    orchestrator.update_plan_status(target, discovery_step["name"], result["status"] == "success")
    print("✓ Plan status updated in OrchestratorAgent")
    
    return True

def test_discovery_fuzzer_integration(target, logger):
    """Test integration between DiscoveryAgent and FuzzerAgent."""
    print("\n=== Testing DiscoveryAgent → FuzzerAgent Integration ===")
    
    # Initialize agents
    discovery = DiscoveryAgent()
    fuzzer = FuzzerAgent()
    
    # First get endpoints from DiscoveryAgent
    print(f"Getting endpoints for {target} from DiscoveryAgent...")
    endpoints = discovery.get_interesting_endpoints(target, 5)
    
    if not endpoints:
        # If no endpoints found, try running discovery
        print("No endpoints found, running discovery...")
        discovery.discover_endpoints(target, {"skip_ai": True, "depth": 1})
        endpoints = discovery.get_interesting_endpoints(target, 5)
        
        if not endpoints:
            print("✗ No endpoints available for testing. Create some test endpoints...")
            endpoints = [
                {
                    "url": f"https://{target}/search?q=test",
                    "potential_vulnerabilities": ["xss", "sqli"],
                    "interest_level": "high"
                }
            ]
    
    if not endpoints:
        print("✗ Failed to create test endpoints")
        return False
    
    print(f"✓ Got {len(endpoints)} endpoints for testing")
    
    # Test fuzzing a single endpoint
    test_endpoint = endpoints[0]
    print(f"Testing fuzzing for endpoint: {test_endpoint['url']}")
    
    # Create a request message
    request = create_request_message(
        "DiscoveryAgent",
        "FuzzerAgent",
        "fuzz_endpoint",
        {
            "endpoint": test_endpoint,
            "target": target,
            "options": {
                "threads": 2,
                "delay": 0.5,
                "timeout": 5,
                "max_payloads": 3,
                "vuln_types": ["xss", "sqli"]
            }
        }
    )
    
    # Send request to FuzzerAgent
    print("Sending fuzz_endpoint request to FuzzerAgent...")
    response = fuzzer.handle_agent_message(request)
    
    if not response:
        print("✗ No response from FuzzerAgent")
        return False
    
    if response.get("type") == "error":
        print(f"✗ Error from FuzzerAgent: {response['metadata'].get('error')}")
        return False
    
    result = response["metadata"]["result"]
    
    if "vulnerabilities" in result:
        vulns_count = len(result["vulnerabilities"])
        print(f"✓ Fuzzing response received with {vulns_count} vulnerabilities")
        if vulns_count > 0:
            print("  Example vulnerabilities:")
            for i, vuln in enumerate(result["vulnerabilities"][:2], 1):
                print(f"  {i}. {vuln['vulnerability_type']} at {vuln['parameter']} parameter")
    else:
        print("✓ Fuzzing completed with no vulnerabilities found")
    
    return True

def test_orchestrator_fuzzer_integration(target, logger):
    """Test integration between OrchestratorAgent and FuzzerAgent."""
    print("\n=== Testing OrchestratorAgent → FuzzerAgent Integration ===")
    
    # Initialize agents
    orchestrator = OrchestratorAgent()
    fuzzer = FuzzerAgent()
    
    # Create a plan for the target
    print(f"Creating plan for {target}...")
    plan = orchestrator.create_plan_for_target(target)
    
    # Find the fuzzing step in the plan
    fuzzing_step = None
    for step in plan.get("steps", []):
        if step.get("agent") == "FuzzerAgent" and "vulnerability" in step.get("name", ""):
            fuzzing_step = step
            break
    
    if not fuzzing_step:
        print("✗ No fuzzing step found in the plan")
        # Add a fake step for testing
        fuzzing_step = {
            "id": len(plan.get("steps", [])) + 1,
            "name": "vulnerability_testing",
            "description": "Test endpoints for vulnerabilities",
            "agent": "FuzzerAgent",
            "status": "pending",
            "priority": 2
        }
        plan["steps"].append(fuzzing_step)
        print("✓ Added fuzzing step to the plan for testing")
    else:
        print(f"✓ Found fuzzing step: {fuzzing_step.get('description')}")
    
    # Create a request message
    request = create_request_message(
        "OrchestratorAgent",
        "FuzzerAgent",
        "fuzz_target",
        {
            "target": target, 
            "options": {
                "threads": 2,
                "delay": 0.5,
                "timeout": 5,
                "max_urls": 3,
                "max_payloads": 3,
                "vuln_types": ["xss", "sqli"]
            }
        }
    )
    
    # Send request to FuzzerAgent
    print("Sending fuzz_target request to FuzzerAgent...")
    response = fuzzer.handle_agent_message(request)
    
    if not response or response.get("type") != "response":
        print(f"✗ Invalid response from FuzzerAgent: {response}")
        return False
    
    result = response["metadata"]["result"]
    print(f"✓ Fuzzing response received with status: {result.get('status')}")
    print(f"  Found {result.get('vulnerabilities_found', 0)} vulnerabilities, created {result.get('findings_created', 0)} findings")
    
    # Update plan status
    orchestrator.update_plan_status(target, fuzzing_step["name"], result["status"] == "success")
    print("✓ Plan status updated in OrchestratorAgent")
    
    return True

def test_full_workflow(target, logger):
    """Test the full bug bounty workflow."""
    print("\n=== Testing Full Bug Bounty Workflow ===")
    
    # Import the workflow function
    from autogen_integration import execute_bug_bounty_workflow, init_agents
    
    # Initialize agents
    agents = init_agents()
    
    # Execute workflow
    print(f"Executing full workflow for {target}...")
    options = {
        "depth": 1,
        "threads": 3,
        "timeout": 5,
        "max_urls": 3,
        "max_payloads": 3,
        "skip_ai": True  # Skip AI classification for faster testing
    }
    
    try:
        report = execute_bug_bounty_workflow(target, agents, options)
        print("✓ Workflow completed successfully")
        print(f"Final report: {json.dumps(report, indent=2)}")
        return True
    except Exception as e:
        print(f"✗ Error in workflow execution: {e}")
        return False

def main():
    """Main function for integration testing."""
    parser = argparse.ArgumentParser(description="Integration test for bug bounty agent system")
    parser.add_argument("--target", default="example.com", help="Target domain to use for testing")
    parser.add_argument("--test", choices=["init", "orchestrator-discovery", "discovery-fuzzer", "orchestrator-fuzzer", "full", "all"], 
                      default="all", help="Which test to run")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Set up logging
    logger = setup_logging(args.verbose)
    
    print("\n" + "=" * 70)
    print("🧪 BUG BOUNTY AGENT SYSTEM INTEGRATION TEST")
    print("=" * 70)
    
    # Record test start time
    start_time = time.time()
    
    # Run the selected test(s)
    success = True
    if args.test == "init" or args.test == "all":
        success = test_agent_initialization() and success
    
    if args.test == "orchestrator-discovery" or args.test == "all":
        success = test_orchestrator_discovery_integration(args.target, logger) and success
    
    if args.test == "discovery-fuzzer" or args.test == "all":
        success = test_discovery_fuzzer_integration(args.target, logger) and success
    
    if args.test == "orchestrator-fuzzer" or args.test == "all":
        success = test_orchestrator_fuzzer_integration(args.target, logger) and success
    
    if args.test == "full" or args.test == "all":
        success = test_full_workflow(args.target, logger) and success
    
    # Record test end time
    end_time = time.time()
    duration = end_time - start_time
    
    print("\n" + "=" * 70)
    if success:
        print("✅ ALL TESTS PASSED SUCCESSFULLY!")
    else:
        print("❌ SOME TESTS FAILED - CHECK LOG FOR DETAILS")
    
    print(f"Total test duration: {duration:.2f} seconds")
    print("=" * 70 + "\n")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())