#!/usr/bin/env python3
# test_fuzzer.py - Test script for the FuzzerAgent

import os
import json
import sys
from datetime import datetime

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Try to load environment variables, but continue if dotenv is not installed
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Warning: dotenv package not installed. Using environment variables as is.")

# Import agents with error handling
try:
    from agents.fuzzer import FuzzerAgent
    from utils.message_utils import create_request_message
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure you have the correct directory structure and all modules are available.")
    print("Current sys.path:", sys.path)
    sys.exit(1)

def test_fuzzer():
    """Test the FuzzerAgent functionality."""
    print("\n" + "=" * 60)
    print("🔍 Testing FuzzerAgent functionality")
    print("=" * 60)
    
    # Create the FuzzerAgent
    fuzzer = FuzzerAgent()
    
    # Test endpoint fuzzing
    print("\n=== Testing Endpoint Fuzzing ===")
    test_target = input("Enter a target domain to test (default: example.com): ") or "example.com"
    
    # First get or create test endpoints
    test_endpoints = get_test_endpoints(test_target)
    if not test_endpoints:
        print(f"No endpoints available for {test_target}. Creating test endpoints...")
        test_endpoints = create_test_endpoints(test_target)
    
    if not test_endpoints:
        print("Failed to create test endpoints. Exiting.")
        return
    
    print(f"Found {len(test_endpoints)} endpoints for testing.")
    
    # Test a single endpoint
    test_single_endpoint(fuzzer, test_endpoints[0], test_target)
    
    # Test message handling
    test_message_handling(fuzzer, test_target, test_endpoints[0])
    
    print("\n=== All tests completed! ===\n")

def get_test_endpoints(target):
    """Get test endpoints from the database."""
    import sqlite3
    
    try:
        conn = sqlite3.connect("bugbounty.db")
        c = conn.cursor()
        
        # Check if endpoints table exists
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='endpoints'")
        if not c.fetchone():
            print("Endpoints table doesn't exist in the database")
            conn.close()
            return []
        
        # Get interesting endpoints
        c.execute("""
            SELECT url FROM endpoints 
            WHERE target = ? AND interesting = 1
            LIMIT 5
        """, (target,))
        
        endpoints = [{"url": row[0], "potential_vulnerabilities": ["xss", "sqli"]} for row in c.fetchall()]
        conn.close()
        
        return endpoints
    
    except Exception as e:
        print(f"Error loading endpoints from database: {e}")
        return []

def create_test_endpoints(target):
    """Create test endpoints for fuzzing."""
    return [
        {
            "url": f"https://{target}/search?q=test",
            "potential_vulnerabilities": ["xss", "sqli"],
            "interest_level": "high"
        },
        {
            "url": f"https://{target}/admin",
            "potential_vulnerabilities": ["idor"],
            "interest_level": "high"
        },
        {
            "url": f"https://{target}/api/user/1",
            "potential_vulnerabilities": ["idor", "sqli"],
            "interest_level": "medium"
        }
    ]

def test_single_endpoint(fuzzer, endpoint, target):
    """Test fuzzing a single endpoint."""
    print(f"\nTesting endpoint: {endpoint['url']}")
    
    options = {
        "threads": 2,
        "delay": 0.5,
        "timeout": 5,
        "max_payloads": 3,
        "vuln_types": ["xss", "sqli"],
        "verbose": True
    }
    
    try:
        result = fuzzer.fuzz_endpoint(endpoint, target, options)
        
        if result and "vulnerabilities" in result:
            print(f"Found {len(result['vulnerabilities'])} potential vulnerabilities:")
            for vuln in result["vulnerabilities"]:
                print(f"- {vuln['vulnerability_type']} at {vuln['parameter']} parameter")
                print(f"  Payload: {vuln['payload']}")
                print(f"  Evidence: {vuln['evidence']}")
                print(f"  Confidence: {vuln['confidence']}")
        else:
            print("No vulnerabilities found or error occurred.")
    except Exception as e:
        print(f"Error testing endpoint: {e}")

def test_message_handling(fuzzer, target, endpoint):
    """Test message handling between agents."""
    print("\n=== Testing Message Handling ===")
    
    # Test fuzzing via message
    request_message = create_request_message(
        "TestAgent",
        "FuzzerAgent",
        "fuzz_endpoint",
        {
            "endpoint": endpoint,
            "target": target,
            "options": {
                "vuln_types": ["xss"],
                "max_payloads": 2
            }
        }
    )
    
    print(f"Sending request message: {request_message['content']}")
    try:
        response = fuzzer.handle_agent_message(request_message)
        if response:
            print(f"Response type: {response['type']}")
            if response['type'] == 'response':
                result = response['metadata']['result']
                if "vulnerabilities" in result:
                    print(f"Found {len(result['vulnerabilities'])} vulnerabilities via message")
            elif response['type'] == 'error':
                print(f"Error: {response['metadata']['error']}")
        else:
            print("No response received")
    except Exception as e:
        print(f"Error in message handling: {e}")

if __name__ == "__main__":
    test_fuzzer()