#!/usr/bin/env python3
# test_discovery.py - Test script for the DiscoveryAgent

import os
import json
import sys
from datetime import datetime
from dotenv import load_dotenv

# Ensure environment variables are loaded
load_dotenv()

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import agents
from agents.discovery import DiscoveryAgent
from utils.message_utils import create_request_message

def test_discovery():
    """Test the DiscoveryAgent functionality."""
    print("\n" + "=" * 60)
    print("🔍 Testing DiscoveryAgent functionality")
    print("=" * 60)
    
    # Create the DiscoveryAgent
    discovery = DiscoveryAgent()
    
    # Test endpoint discovery
    print("\n=== Testing Endpoint Discovery ===")
    test_target = input("Enter a target domain to test (default: example.com): ") or "example.com"
    
    print(f"Starting content discovery for {test_target}...")
    result = discovery.discover_endpoints(test_target)
    print(f"Discovery result for {test_target}:")
    print(json.dumps({k: v for k, v in result.items() if k != 'endpoints'}, indent=2))
    print(f"Found {result.get('endpoints_found', 0)} endpoints, {result.get('interesting_endpoints', 0)} interesting")
    
    # Test message handling
    print("\n=== Testing Message Handling ===")
    request_message = create_request_message(
        "TestAgent",
        "DiscoveryAgent",
        "discover_endpoints",
        {"target": test_target}
    )
    print(f"Sending request message: {request_message['content']}")
    response = discovery.handle_agent_message(request_message)
    print(f"Response type: {response['type']}")
    print(f"Response status: {response['metadata']['result']['status']}")
    
    # Test endpoint classification
    print("\n=== Testing Endpoint Classification ===")
    # Create some sample endpoints
    sample_endpoints = [
        {"url": f"https://{test_target}/admin", "status_code": 200},
        {"url": f"https://{test_target}/login", "status_code": 200},
        {"url": f"https://{test_target}/api/v1/users", "status_code": 200},
        {"url": f"https://{test_target}/backup.zip", "status_code": 403}
    ]
    print(f"Classifying sample endpoints for {test_target}...")
    try:
        classified = discovery.classify_endpoints(sample_endpoints, test_target)
        print("Classified endpoints:")
        for endpoint in classified:
            interest = endpoint.get("interest_level", "unknown")
            vulnerabilities = ", ".join(endpoint.get("potential_vulnerabilities", []))
            print(f"- {endpoint['url']} - Interest: {interest} - Vulns: {vulnerabilities or 'None'}")
    except Exception as e:
        print(f"Error classifying endpoints: {e}")
        print("Using default classification instead.")
        for endpoint in sample_endpoints:
            endpoint["interest_level"] = "medium" if "admin" in endpoint["url"] or "backup" in endpoint["url"] else "low"
            endpoint["potential_vulnerabilities"] = []
            if "admin" in endpoint["url"]:
                endpoint["potential_vulnerabilities"] = ["Authorization Bypass"]
            elif "backup" in endpoint["url"]:
                endpoint["potential_vulnerabilities"] = ["Information Disclosure"]
            print(f"- {endpoint['url']} - Interest: {endpoint['interest_level']} - Vulns: {', '.join(endpoint['potential_vulnerabilities']) or 'None'}")
    
    
    print("\n=== All tests completed! ===\n")

if __name__ == "__main__":
    test_discovery()