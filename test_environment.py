# In test_environment.py
import os
import sys
import json
from dotenv import load_dotenv

# Ensure environment variables are loaded
load_dotenv()

from agents.orchestrator import OrchestratorAgent
from agents.discovery import DiscoveryAgent

def test_orchestrator_agent():
    """Test that the OrchestratorAgent can be created."""
    orchestrator = OrchestratorAgent()
    plan = orchestrator.create_plan_for_target("example.com")
    
    print("Orchestrator Agent Test:")
    print(json.dumps(plan, indent=2))
    print("\n")
    
    return orchestrator

def test_discovery_agent():
    """Test that the DiscoveryAgent can be created."""
    discovery = DiscoveryAgent()
    result = discovery.discover_endpoints("example.com")
    
    print("Discovery Agent Test:")
    print(json.dumps(result, indent=2))
    print("\n")
    
    return discovery

def test_simple_conversation(orchestrator, discovery):
    """Test a simple conversation between agents."""
    # This would normally use Autogen's group chat functionality
    # but we'll just simulate a conversation for testing
    
    print("Agent Conversation Test:")
    plan = orchestrator.create_plan_for_target("example.com")
    
    # Get the first step (which should be content discovery)
    first_step = next((step for step in plan["steps"] if step["agent"] == "DiscoveryAgent"), None)
    
    if first_step:
        print(f"Orchestrator: Please execute the '{first_step['name']}' step for example.com")
        
        # Discovery agent performs the action
        result = discovery.discover_endpoints("example.com")
        
        print(f"Discovery Agent: Completed {first_step['name']}. Found {result['endpoints_found']} endpoints.")
        print("\n")

if __name__ == "__main__":
    print("Testing Autogen Environment Setup...\n")
    
    # Test individual agents
    orchestrator = test_orchestrator_agent()
    discovery = test_discovery_agent()
    
    # Test a simple conversation
    test_simple_conversation(orchestrator, discovery)
    
    print("All tests completed successfully!")
