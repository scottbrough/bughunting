# In test_orchestrator.py
import os
import json
from agents.orchestrator import OrchestratorAgent
from utils.message_utils import create_request_message

def test_orchestrator():
    """Test the OrchestratorAgent functionality."""
    # Create the OrchestratorAgent
    orchestrator = OrchestratorAgent()
    
    # Test plan creation
    print("\n=== Testing Plan Creation ===")
    test_target = "example.com"
    plan = orchestrator.create_plan_for_target(test_target)
    print(f"Created plan for {test_target}:")
    print(json.dumps(plan, indent=2))
    
    # Test message handling
    print("\n=== Testing Message Handling ===")
    request_message = create_request_message(
        "TestAgent",
        "OrchestratorAgent",
        "create_plan",
        {"target": test_target}
    )
    response = orchestrator.handle_agent_message(request_message)
    print("Response:")
    print(json.dumps(response, indent=2))
    
    # Test progress reporting
    print("\n=== Testing Progress Reporting ===")
    report = orchestrator.generate_progress_report(test_target)
    
    # Test autonomous cycle
    print("\n=== Testing Autonomous Cycle ===")
    orchestrator.run_autonomous_cycle(max_targets=1)
    
    print("\nAll tests completed!")

if __name__ == "__main__":
    test_orchestrator()
