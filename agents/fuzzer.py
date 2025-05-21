#!/usr/bin/env python3
# fuzzer.py - FuzzerAgent for the bug bounty automation framework

import os
import sys
import json
import sqlite3
import requests
import logging
import pathlib
import time
import re
import base64
import urllib.parse
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from autogen import ConversableAgent

# Disable SSL warnings globally
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add parent directory to path to access utilities
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.config_loader import get_model_config
from utils.message_utils import (
    create_standard_message, create_request_message,
    create_response_message, create_error_message, create_result_message,
    message_to_string, message_to_chat_message
)

class FuzzerAgent:
    """
    Specialized agent for vulnerability fuzzing in the bug bounty process.
    Tests endpoints for security vulnerabilities using a variety of techniques.
    """
    
    def __init__(self):
        # Get the configuration for the agent
        model_config = get_model_config("gpt-4o") if os.getenv("USE_ENHANCED_MODEL") else get_model_config()
        
        # Create the ConversableAgent
        self.agent = ConversableAgent(
            name="FuzzerAgent",
            system_message="""You are the FuzzerAgent for a bug bounty automation framework.
            Your responsibilities include:
            1. Testing endpoints for security vulnerabilities
            2. Generating payloads for different vulnerability types
            3. Analyzing responses for signs of vulnerability
            4. Creating and documenting findings
            
            You test for vulnerabilities such as XSS, SQL injection, SSRF, LFI/RFI, and more.
            Your goal is to identify security issues while minimizing false positives.""",
            llm_config={
                "config_list": [
                    {
                        "model": model_config["model"],
                        "api_key": model_config["api_key"]
                    }
                ],
                "temperature": 0.4
            }
        )
        
        # Initialize the database connection
        self.db_path = os.getenv("DB_PATH", "bugbounty.db")
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("bugbounty.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("fuzzer_agent")
        
        # Flag for graceful shutdown
        self.running = True
    
    def get_db_connection(self):
        """Create a connection to the SQLite database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    # Core fuzzing methods
    
    def fuzz_target(self, target, options=None):
        """Main method to fuzz endpoints for a target."""
        self.logger.info(f"Starting vulnerability fuzzing for {target}")
        
        # Set default options if none provided
        if options is None:
            options = {
                "threads": 5,
                "delay": 0.2,
                "timeout": 10,
                "max_urls": 25,
                "max_payloads": 15,
                "vuln_types": ["xss", "sqli", "ssrf", "lfi", "rce", "idor"]
            }
        
        # Check if vuln_types is a string and convert to list
        if isinstance(options.get("vuln_types"), str):
            if options["vuln_types"].lower() == "all":
                options["vuln_types"] = ["xss", "sqli", "ssrf", "lfi", "rce", "idor"]
            else:
                options["vuln_types"] = [options["vuln_types"].lower()]
        
        # Get interesting endpoints to test
        endpoints = self.get_interesting_endpoints(target, options.get("max_urls", 25))
        
        if not endpoints:
            self.logger.error(f"No endpoints found for target: {target} even after fallback mechanism")
            return {"status": "error", "message": "No endpoints found to test", "findings": 0}
        
        self.logger.info(f"Found {len(endpoints)} endpoints to test")
        
        # Record run start
        run_id = self.record_run_start(target, f"fuzz_target for {target}")
        
        # Setup vuln table if it doesn't exist
        self.setup_vuln_table()
        
        # Process each endpoint
        vulnerabilities = []
        
        with ThreadPoolExecutor(max_workers=options.get("threads", 5)) as executor:
            future_to_endpoint = {}
            
            for endpoint in endpoints:
                # Skip if we've been told to stop
                if not self.running:
                    break
                
                # Submit the fuzzing task
                future = executor.submit(
                    self.fuzz_endpoint,
                    endpoint,
                    target,
                    options
                )
                future_to_endpoint[future] = endpoint
            
            # Process results as they complete
            for future in as_completed(future_to_endpoint):
                endpoint = future_to_endpoint[future]
                try:
                    result = future.result()
                    if result and "vulnerabilities" in result:
                        vulnerabilities.extend(result["vulnerabilities"])
                except Exception as e:
                    self.logger.error(f"Error fuzzing endpoint {endpoint['url']}: {e}")
        
        # Create findings from vulnerabilities
        findings = []
        for vuln in vulnerabilities:
            finding_id = self.create_finding(vuln, target)
            if finding_id:
                findings.append({**vuln, "finding_id": finding_id})
        
        # Create summary
        summary = {
            "target": target,
            "endpoints_tested": len(endpoints),
            "vulnerabilities_found": len(vulnerabilities),
            "findings_created": len(findings),
            "date": datetime.now().isoformat()
        }
        
        # Save summary
        workspace = pathlib.Path("workspace") / target / "fuzzing"
        workspace.mkdir(parents=True, exist_ok=True)
        
        summary_path = workspace / "fuzzing_summary.json"
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)
        
        vulns_path = workspace / "vulnerabilities.json"
        with open(vulns_path, "w") as f:
            json.dump(vulnerabilities, f, indent=2)
        
        # Record run end
        self.record_run_end(run_id, True, {"summary": summary})
        
        # Notify orchestrator
        self.notify_orchestrator(target, len(vulnerabilities), len(findings))
        
        self.logger.info(f"Fuzzing complete for {target}")
        self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities, created {len(findings)} findings")
        
        return {
            "status": "success",
            "summary": summary,
            "vulnerabilities_found": len(vulnerabilities),
            "findings_created": len(findings),
            "vulnerabilities": vulnerabilities[:10]  # Limit to first 10 for message size
        }
    
    def get_interesting_endpoints(self, target, max_urls=25):
        """Get interesting endpoints from the database."""
        conn = self.get_db_connection()
        c = conn.cursor()
        
        try:
            # Check if endpoints table exists
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='endpoints'")
            if not c.fetchone():
                self.logger.warning("Endpoints table doesn't exist in the database")
                conn.close()
                return self.get_fallback_endpoints(target)
            
            # First try to get interesting endpoints
            c.execute("""
                SELECT url, notes
                FROM endpoints 
                WHERE target = ? AND interesting = 1
                ORDER BY RANDOM()
                LIMIT ?
            """, (target, max_urls))
            
            endpoints = []
            for row in c.fetchall():
                url, notes_json = row
                
                # Parse notes to extract potential vulnerability types
                vuln_types = []
                if notes_json:
                    try:
                        notes = json.loads(notes_json)
                        if "potential_vulnerabilities" in notes:
                            vuln_types = notes["potential_vulnerabilities"]
                        interest_level = notes.get("interest_level", "low")
                    except:
                        interest_level = "low"
                        pass
                else:
                    interest_level = "low"
                
                endpoints.append({
                    "url": url, 
                    "potential_vulnerabilities": vuln_types,
                    "interest_level": interest_level
                })
            
            # If no interesting endpoints found, try to get ANY endpoints
            if not endpoints:
                self.logger.warning("No interesting endpoints found. Trying to fetch any available endpoints.")
                c.execute("""
                    SELECT url, notes
                    FROM endpoints 
                    WHERE target = ?
                    ORDER BY RANDOM()
                    LIMIT ?
                """, (target, max_urls))
                
                for row in c.fetchall():
                    url, notes_json = row
                    
                    # Parse notes
                    vuln_types = []
                    if notes_json:
                        try:
                            notes = json.loads(notes_json)
                            if "potential_vulnerabilities" in notes:
                                vuln_types = notes["potential_vulnerabilities"]
                            interest_level = notes.get("interest_level", "low")
                        except:
                            interest_level = "low"
                    else:
                        interest_level = "low"
                    
                    endpoints.append({
                        "url": url, 
                        "potential_vulnerabilities": vuln_types,
                        "interest_level": interest_level
                    })
            
            # If still no endpoints, use fallback
            if not endpoints:
                self.logger.warning("No endpoints found in database. Using fallback endpoints.")
                endpoints = self.get_fallback_endpoints(target)
            
            conn.close()
            self.logger.info(f"Retrieved {len(endpoints)} endpoints for testing")
            return endpoints
        
        except Exception as e:
            self.logger.error(f"Error loading endpoints: {e}")
            conn.close()
            # Return fallback endpoints if database access fails
            return self.get_fallback_endpoints(target)
    
    def get_fallback_endpoints(self, target):
        """Generate fallback endpoints when none are found in the database."""
        self.logger.info(f"Generating fallback endpoints for {target}")
        
        # Make sure target has proper URL format
        if not target.startswith(('http://', 'https://')):
            target_url = f"https://{target}"
        else:
            target_url = target
        
        # Common paths that are likely to exist and could be vulnerable
        common_paths = [
            "",  # Root path
            "login",
            "register",
            "admin",
            "search",
            "contact",
            "api",
            "blog",
            "account",
            "user"
        ]
        
        # Common parameters for each path
        param_templates = {
            "": [],  # Root path has no parameters
            "login": ["username", "password", "token"],
            "register": ["username", "email", "password"],
            "admin": ["id", "action", "user"],
            "search": ["q", "query", "term", "keyword"],
            "contact": ["name", "email", "message"],
            "api": ["id", "action", "token"],
            "blog": ["id", "category", "tag"],
            "account": ["id", "action"],
            "user": ["id", "name"]
        }
        
        # Generate a list of endpoints
        endpoints = []
        for path in common_paths:
            # Base URL for the path
            base_url = f"{target_url}/{path}" if path else target_url
            
            # Add the base URL as an endpoint
            endpoints.append({
                "url": base_url,
                "potential_vulnerabilities": ["xss", "sqli", "rce"],
                "interest_level": "medium"
            })
            
            # Add URLs with parameters
            for param in param_templates.get(path, []):
                url = f"{base_url}?{param}=test"
                endpoints.append({
                    "url": url,
                    "potential_vulnerabilities": ["xss", "sqli", "idor"],
                    "interest_level": "high"
                })
        
        self.logger.info(f"Generated {len(endpoints)} fallback endpoints for {target}")
        return endpoints
    
    def fuzz_endpoint(self, endpoint, target, options):
        """Fuzz a specific endpoint for vulnerabilities."""
        url = endpoint["url"]
        vuln_types = options.get("vuln_types", ["xss", "sqli", "ssrf", "lfi", "rce", "idor"])
        suggested_vulns = endpoint.get("potential_vulnerabilities", [])
        
        # Prioritize suggested vulnerability types if available
        if suggested_vulns:
            # Convert all to lowercase for comparison
            suggested_vulns = [v.lower() for v in suggested_vulns]
            # Filter to only include valid vuln types
            valid_suggested = [v for v in suggested_vulns if any(vt in v for vt in ["xss", "sql", "ssrf", "lfi", "rfi", "rce", "cmd", "idor", "injection"])]
            
            if valid_suggested:
                # Map suggested vulns to our standard categories
                mapped_vulns = []
                for v in valid_suggested:
                    if any(x in v for x in ["xss", "cross"]):
                        mapped_vulns.append("xss")
                    elif any(x in v for x in ["sql", "sqli"]):
                        mapped_vulns.append("sqli") 
                    elif "ssrf" in v:
                        mapped_vulns.append("ssrf")
                    elif any(x in v for x in ["lfi", "rfi", "path", "traversal", "include"]):
                        mapped_vulns.append("lfi")
                    elif any(x in v for x in ["rce", "cmd", "command", "code", "exec"]):
                        mapped_vulns.append("rce")
                    elif any(x in v for x in ["idor", "insecure direct", "access control"]):
                        mapped_vulns.append("idor")
                
                # Use these vulnerabilities first, then add any missing from the requested types
                prioritized_vulns = list(set(mapped_vulns))
                for vt in vuln_types:
                    if vt not in prioritized_vulns:
                        prioritized_vulns.append(vt)
                
                vuln_types = prioritized_vulns[:len(vuln_types)]  # Keep the same length as original
        
        self.logger.info(f"Fuzzing {url} for vulnerabilities: {', '.join(vuln_types)}")
        
        # Generate payloads for the endpoint
        payloads = self.generate_payloads(url, vuln_types, options.get("max_payloads", 15))
        
        if not payloads:
            self.logger.warning(f"No payloads generated for {url}")
            return None
        
        # Fuzz with all payloads
        results = []
        
        for payload_data in payloads:
            # Skip if we've been told to stop
            if not self.running:
                break
            
            try:
                # Apply the payload
                fuzzed_url = self.apply_payload(url, payload_data)
                
                # Prepare headers
                headers = {
                    "User-Agent": options.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
                }
                
                # Add additional headers if provided
                if options.get("headers"):
                    for header_pair in options.get("headers").split(";"):
                        if ":" in header_pair:
                            name, value = header_pair.split(":", 1)
                            headers[name.strip()] = value.strip()
                
                # Prepare cookies
                cookies = {}
                if options.get("cookies"):
                    for cookie_pair in options.get("cookies").split(";"):
                        if "=" in cookie_pair:
                            name, value = cookie_pair.split("=", 1)
                            cookies[name.strip()] = value.strip()
                
                # Make the request
                if options.get("verbose", False):
                    self.logger.info(f"Testing: {fuzzed_url}")
                
                time.sleep(options.get("delay", 0.2))  # Respect rate limiting
                
                response = requests.get(
                    fuzzed_url,
                    headers=headers,
                    cookies=cookies,
                    timeout=options.get("timeout", 10),
                    allow_redirects=True,
                    verify=False  # Ignore SSL verification
                )
                
                # Check for vulnerabilities
                result = self.check_response_for_vulnerability(response, payload_data)
                
                if result["is_vulnerable"]:
                    self.logger.warning(f"Potential {payload_data['vulnerability_type']} vulnerability found at {fuzzed_url}")
                    
                    # Record the vulnerability
                    vulnerability = {
                        "target": target,
                        "url": url,
                        "fuzzed_url": fuzzed_url,
                        "parameter": payload_data["parameter"],
                        "vulnerability_type": payload_data["vulnerability_type"],
                        "payload": payload_data["payload"],
                        "response_code": response.status_code,
                        "evidence": result["evidence"],
                        "confidence": result["confidence"],
                        "date_discovered": datetime.now().isoformat()
                    }
                    
                    # Record in database
                    self.save_vulnerability(vulnerability)
                    
                    # Add to results
                    results.append(vulnerability)
            
            except Exception as e:
                self.logger.error(f"Error fuzzing {url} with payload {payload_data['payload']}: {e}")
        
        return {"url": url, "vulnerabilities": results}
    
    def generate_payloads(self, url, vuln_types, max_payloads=15):
        """Generate payloads for the URL and vulnerability types."""
        # Parse URL to extract parameters
        url_parts = urllib.parse.urlparse(url)
        path = url_parts.path
        query = url_parts.query
        
        # Parse query parameters
        params = []
        if query:
            for param_pair in query.split("&"):
                if "=" in param_pair:
                    name, value = param_pair.split("=", 1)
                    params.append({"name": name, "value": value})
        
        # Determine parameters to focus on
        target_params = []
        if params:
            # Use all parameters from the URL
            target_params = [p["name"] for p in params]
        else:
            # If no parameters, just use path segments
            path_segments = [seg for seg in path.split("/") if seg]
            if path_segments:
                target_params = ["path"]
        
        # If still no parameters, just target the base URL
        if not target_params:
            target_params = ["base"]
        
        try:
            # Use the OpenAI API to generate payloads
            import openai
            
            # Get API key from environment or config
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key and hasattr(self.agent, "llm_config") and isinstance(self.agent.llm_config, dict):
                config_list = self.agent.llm_config.get("config_list", [])
                if config_list and len(config_list) > 0 and "api_key" in config_list[0]:
                    api_key = config_list[0]["api_key"]
            
            if not api_key:
                raise ValueError("No OpenAI API key found in environment or config")
            
            # Create client with API key
            client = openai.OpenAI(api_key=api_key)
            
            response = client.chat.completions.create(
                model="gpt-4o",  # Use a suitable model
                messages=[
                    {"role": "system", "content": """You are an expert penetration tester specializing in web application security.
                    Generate payloads for testing the specified vulnerabilities in a URL.
                    
                    For each vulnerability type and parameter, generate multiple diverse payloads that:
                    1. Test for the vulnerability in different ways
                    2. Attempt to bypass common filters and WAFs
                    3. Are tailored to the specific parameter name and context
                    4. Include a mixture of basic and advanced techniques
                    
                    Consider the URL structure, parameter names, and potential application context.
                    
                    Return a JSON object with vulnerability types as keys, and for each type:
                    - A list of payloads to try
                    - For each payload, include:
                      * The payload string
                      * Where to inject it (parameter name or path)
                      * A brief explanation of what it tests for
                      * Detection method to identify if it worked
                    """},
                    {"role": "user", "content": f"""Generate penetration testing payloads for this URL:
                    
                    URL: {url}
                    Path: {path}
                    Parameters: {json.dumps(params)}
                    
                    Focus on testing these vulnerability types: {', '.join(vuln_types)}
                    Target these parameters: {', '.join(target_params)}
                    
                    Generate up to {max_payloads} total payloads across all vulnerability types.
                    """}
                ],
                response_format={"type": "json_object"},
                temperature=0.7
            )
            
            payloads_data = json.loads(response.choices[0].message.content)
            
            # Process and flatten payloads
            all_payloads = []
            for vuln_type, payloads in payloads_data.items():
                if not isinstance(payloads, list):
                    # Handle case where the response format is different
                    if "payloads" in payloads:
                        payloads = payloads["payloads"]
                    else:
                        continue
                
                for payload_data in payloads:
                    # Handle different response structures
                    if isinstance(payload_data, dict):
                        payload = payload_data.get("payload", "")
                        param_name = payload_data.get("parameter", payload_data.get("inject_at", ""))
                        explanation = payload_data.get("explanation", "")
                        detection = payload_data.get("detection", payload_data.get("detection_method", ""))
                    elif isinstance(payload_data, str):
                        payload = payload_data
                        param_name = target_params[0] if target_params else ""
                        explanation = ""
                        detection = ""
                    else:
                        continue
                    
                    all_payloads.append({
                        "vulnerability_type": vuln_type,
                        "payload": payload,
                        "parameter": param_name,
                        "explanation": explanation,
                        "detection_method": detection
                    })
            
            self.logger.info(f"Generated {len(all_payloads)} payloads for {url}")
            return all_payloads
        
        except Exception as e:
            self.logger.error(f"Error generating payloads: {e}")
            
            # Fallback to basic payload generation
            self.logger.info("Using fallback payload generation")
            return self.generate_basic_payloads(url, vuln_types, target_params)
    
    def generate_basic_payloads(self, url, vuln_types, target_params):
        """Generate basic payloads when AI generation fails."""
        basic_payloads = []
        
        # Basic payloads for each vulnerability type
        payload_templates = {
            "xss": [
                "<script>alert(1)</script>",
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)"
            ],
            "sqli": [
                "' OR '1'='1",
                "1' OR '1'='1",
                "1 OR 1=1",
                "' OR 1=1--",
                "admin'--"
            ],
            "ssrf": [
                "http://localhost",
                "http://127.0.0.1",
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd",
                "dict://localhost:11211/"
            ],
            "lfi": [
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "/etc/passwd",
                "..\\..\\..\\Windows\\win.ini",
                "file:///etc/passwd"
            ],
            "rce": [
                "$(whoami)",
                "`whoami`",
                "os.popen('whoami').read()",
                ";whoami",
                "|| whoami"
            ],
            "idor": [
                "1",
                "2",
                "admin",
                "0",
                "-1"
            ]
        }
        
        for vuln_type in vuln_types:
            if vuln_type in payload_templates:
                for payload in payload_templates[vuln_type]:
                    for param in target_params:
                        basic_payloads.append({
                            "vulnerability_type": vuln_type,
                            "payload": payload,
                            "parameter": param,
                            "explanation": f"Basic {vuln_type} test",
                            "detection_method": ""
                        })
        
        return basic_payloads[:15]  # Limit to 15 payloads
    
    def apply_payload(self, url, payload_data):
        """Apply a payload to the URL at the specified parameter."""
        payload = payload_data["payload"]
        param_name = payload_data["parameter"]
        
        url_parts = urllib.parse.urlparse(url)
        
        # Handle special "base" parameter (append to base URL)
        if param_name == "base":
            # Add payload to the end of the path
            new_path = url_parts.path
            if not new_path.endswith('/'):
                new_path += '/'
            new_path += payload
            
            new_url = urllib.parse.urlunparse((
                url_parts.scheme,
                url_parts.netloc,
                new_path,
                url_parts.params,
                url_parts.query,
                url_parts.fragment
            ))
            return new_url
        
        # Handle path-based injection
        if param_name == "path" or not param_name:
            path_segments = url_parts.path.split("/")
            # Inject into the last non-empty segment
            for i in range(len(path_segments) - 1, -1, -1):
                if path_segments[i]:
                    path_segments[i] = payload
                    break
            new_path = "/".join(path_segments)
            new_url = urllib.parse.urlunparse((
                url_parts.scheme,
                url_parts.netloc,
                new_path,
                url_parts.params,
                url_parts.query,
                url_parts.fragment
            ))
            return new_url
        
        # Handle query parameter injection
        query_params = {}
        if url_parts.query:
            for param_pair in url_parts.query.split("&"):
                if "=" in param_pair:
                    name, value = param_pair.split("=", 1)
                    query_params[name] = value
        
        # If the parameter exists, replace its value, otherwise add it
        query_params[param_name] = payload
        
        # Rebuild query string
        new_query = "&".join([f"{name}={value}" for name, value in query_params.items()])
        
        # Rebuild URL
        new_url = urllib.parse.urlunparse((
            url_parts.scheme,
            url_parts.netloc,
            url_parts.path,
            url_parts.params,
            new_query,
            url_parts.fragment
        ))
        
        return new_url
    
    def check_response_for_vulnerability(self, response, payload_data):
        """Check if a response indicates a vulnerability."""
        payload = payload_data["payload"]
        vuln_type = payload_data["vulnerability_type"]
        detection_method = payload_data.get("detection_method", "")
        
        # Default values
        is_vulnerable = False
        evidence = ""
        confidence = 0.0
        
        # Check based on vulnerability type
        if vuln_type == "xss":
            # Look for unescaped payload or javascript execution indicators
            if payload in response.text and not payload.replace("<", "&lt;").replace(">", "&gt;") in response.text:
                is_vulnerable = True
                evidence = f"Unescaped XSS payload found in response: {payload}"
                confidence = 0.7
            
            # Check for reflected input with script tags
            if "<script" in payload.lower() and "<script" in response.text.lower():
                script_index = response.text.lower().find("<script")
                script_context = response.text[script_index:script_index+100]
                evidence = f"Script tag found in response: {script_context}"
                is_vulnerable = True
                confidence = 0.8
        
        elif vuln_type == "sqli":
            # Look for SQL error messages
            sql_errors = ["sql syntax", "unclosed quotation", "mysql error", "sql error", "ora-", "postgresql error",
                         "sqlite error", "sqliteexception", "microsoft sql", "syntax error", "unterminated string"]
            
            for error in sql_errors:
                if error in response.text.lower():
                    is_vulnerable = True
                    evidence = f"SQL error found in response: {error}"
                    confidence = 0.7
                    break
            
            # Check for different responses between regular and error-inducing payloads
            if "'--" in payload and response.status_code in (500, 403):
                is_vulnerable = True
                evidence = f"Error status code {response.status_code} when using SQL injection payload"
                confidence = 0.5
        
        elif vuln_type == "ssrf":
            # Look for responses indicating successful connection to internal resources
            if any(term in response.text.lower() for term in ["private address", "internal", "localhost", "127.0.0.1"]):
                is_vulnerable = True
                evidence = "Response contains internal address information"
                confidence = 0.6
            
            # Check for delayed responses with time-based payloads
            if "sleep" in payload.lower() and response.elapsed.total_seconds() > 5:
                is_vulnerable = True
                evidence = f"Time-based SSRF payload caused delay: {response.elapsed.total_seconds()} seconds"
                confidence = 0.7
        
        elif vuln_type == "lfi":
            # Look for file content in response
            file_markers = ["root:x:", "localhost", "etc/passwd", "win.ini", "boot.ini", "windows\\system32"]
            for marker in file_markers:
                if marker in response.text:
                    is_vulnerable = True
                    evidence = f"File content found in response: {marker}"
                    confidence = 0.8
                    break
        
        elif vuln_type == "rce":
            # Look for command output in response
            cmd_markers = ["uid=", "gid=", "drwxr", "total ", "volume ", "directory of ", "system32"]
            for marker in cmd_markers:
                if marker in response.text.lower():
                    is_vulnerable = True
                    evidence = f"Command output found in response: {marker}"
                    confidence = 0.7
                    break
        
        elif vuln_type == "idor":
            # Look for unauthorized access to resources
            if "id=" in payload and 200 <= response.status_code < 300:
                # Check if response contains personal data
                personal_data = ["email", "username", "password", "address", "credit card", "phone", "ssn", "account"]
                for term in personal_data:
                    if term in response.text.lower():
                        is_vulnerable = True
                        evidence = f"Potential personal data found in response: {term}"
                        confidence = 0.5
                        break
        
        # Use any custom detection method provided by AI
        if not is_vulnerable and detection_method:
            detection_terms = [term.strip().lower() for term in detection_method.split(",")]
            for term in detection_terms:
                if term in response.text.lower():
                    is_vulnerable = True
                    evidence = f"Detection term found in response: {term}"
                    confidence = 0.6
                    break
        
        return {
            "is_vulnerable": is_vulnerable,
            "evidence": evidence,
            "confidence": confidence
        }
    
    # Database methods
    
    def setup_vuln_table(self):
        """Set up vulnerabilities table in the database."""
        conn = self.get_db_connection()
        c = conn.cursor()
        
        c.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
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
        """)
        
        conn.commit()
        conn.close()
    
    def save_vulnerability(self, vulnerability):
        """Save a vulnerability to the database."""
        conn = self.get_db_connection()
        c = conn.cursor()
        
        try:
            c.execute("""
                INSERT INTO vulnerabilities 
                (target, url, parameter, vulnerability_type, payload, response_code, evidence, confidence, date_discovered, status, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                vulnerability["target"],
                vulnerability["url"],
                vulnerability["parameter"],
                vulnerability["vulnerability_type"],
                vulnerability["payload"],
                vulnerability["response_code"],
                vulnerability["evidence"],
                vulnerability["confidence"],
                vulnerability["date_discovered"],
                "new",
                ""
            ))
            
            conn.commit()
            self.logger.info(f"Saved vulnerability to database: {vulnerability['vulnerability_type']} in {vulnerability['url']}")
        except Exception as e:
            self.logger.error(f"Error saving vulnerability: {e}")
        finally:
            conn.close()
    
    def create_finding(self, vulnerability, target):
        """Create a finding in the findings table based on a vulnerability."""
        conn = self.get_db_connection()
        c = conn.cursor()
        
        try:
            # Check if findings table exists
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
            if not c.fetchone():
                self.logger.warning("Findings table doesn't exist. Creating vulnerability only.")
                conn.close()
                return None
            
            # Map vulnerability type to severity
            severity_map = {
                "rce": "high",
                "sqli": "high",
                "xss": "medium",
                "ssrf": "high",
                "lfi": "high",
                "idor": "medium"
            }
            
            severity = severity_map.get(vulnerability["vulnerability_type"].lower(), "medium")
            
            # Extract host from URL
            host = vulnerability["url"]
            try:
                parsed = urllib.parse.urlparse(host)
                host = f"{parsed.scheme}://{parsed.netloc}"
            except:
                pass
            
            # Create a user-friendly description
            description = f"{vulnerability['vulnerability_type'].upper()} vulnerability in {vulnerability['parameter']} parameter"
            
            c.execute("""
                INSERT INTO findings 
                (target, host, vulnerability, severity, confidence, date, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                target,
                host,
                description,
                severity,
                vulnerability["confidence"],
                vulnerability["date_discovered"],
                "new"
            ))
            
            finding_id = c.lastrowid
            conn.commit()
            
            self.logger.info(f"Created finding: {description}")
            return finding_id
            
        except Exception as e:
            self.logger.error(f"Error creating finding: {e}")
            return None
        finally:
            conn.close()
    
    def record_run_start(self, target, command):
        """Record the start of a fuzzing run in the database."""
        conn = self.get_db_connection()
        c = conn.cursor()
        run_id = None
        
        try:
            c.execute("""
                INSERT INTO agent_runs (target, module, command, status, start_time)
                VALUES (?, ?, ?, ?, ?)
            """, (
                target,
                "vulnerability_testing",
                command,
                "running",
                datetime.now().isoformat()
            ))
            run_id = c.lastrowid
            conn.commit()
        except Exception as e:
            self.logger.error(f"Error recording run start: {e}")
        finally:
            conn.close()
        
        return run_id
    
    def record_run_end(self, run_id, success, outcome):
        """Record the end of a fuzzing run in the database."""
        if not run_id:
            return
        
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
                json.dumps(outcome),
                run_id
            ))
            conn.commit()
        except Exception as e:
            self.logger.error(f"Error recording run end: {e}")
        finally:
            conn.close()
    
    # Agent communication methods
    
    def handle_agent_message(self, message):
        """Handle a message from another agent."""
        self.logger.info(f"Received message: {message_to_chat_message(message)}")
        
        # Process based on message type
        if message["type"] == "request":
            # Handle request from another agent
            action = message["metadata"]["action"]
            
            if action == "fuzz_target":
                # Extract parameters
                target = message["metadata"]["parameters"].get("target")
                options = message["metadata"]["parameters"].get("options", {})
                
                # Execute fuzzing
                result = self.fuzz_target(target, options)
                
                # Return a response
                return create_response_message(
                    "FuzzerAgent",
                    message["metadata"]["from"],
                    action,
                    result
                )
            
            elif action == "fuzz_endpoint":
                # Extract parameters
                endpoint = message["metadata"]["parameters"].get("endpoint")
                target = message["metadata"]["parameters"].get("target")
                options = message["metadata"]["parameters"].get("options", {})
                
                # Validate endpoint format
                if not isinstance(endpoint, dict) or "url" not in endpoint:
                    return create_error_message(
                        "FuzzerAgent",
                        message["metadata"]["from"],
                        action,
                        "Invalid endpoint format. Requires a dictionary with 'url' key."
                    )
                
                # Fuzz the endpoint
                result = self.fuzz_endpoint(endpoint, target, options)
                
                # Return a response
                return create_response_message(
                    "FuzzerAgent",
                    message["metadata"]["from"],
                    action,
                    result
                )
                
            else:
                # Unknown action
                return create_error_message(
                    "FuzzerAgent",
                    message["metadata"]["from"],
                    action,
                    f"Unknown action: {action}"
                )
        
        elif message["type"] == "response":
            # Process response from an agent
            self.logger.info(f"Received response from {message['metadata']['from']}")
            return None
        
        elif message["type"] == "error":
            # Handle error from an agent
            self.logger.error(f"Error from {message['metadata']['from']}: {message['metadata']['error']}")
            return None
        
        else:
            # Unknown message type
            self.logger.warning(f"Unknown message type: {message['type']}")
            return None
    
    def send_message_to_agent(self, to_agent, message):
        """Send a message to another agent."""
        self.logger.info(f"Sending message: {message_to_chat_message(message)}")
        
        # In a real implementation, this would use Autogen's messaging system
        # For now, we'll implement a simple direct call if the agent is in the same process
        
        # Import locally to avoid circular imports
        from agents.orchestrator import OrchestratorAgent
        from agents.discovery import DiscoveryAgent
        
        if to_agent == "OrchestratorAgent":
            orchestrator = OrchestratorAgent()
            return orchestrator.handle_agent_message(message)
        elif to_agent == "DiscoveryAgent":
            discovery = DiscoveryAgent()
            return discovery.handle_agent_message(message)
        
        # If we can't handle the message locally, log a warning
        self.logger.warning(f"Could not send message to {to_agent}: agent not available locally")
        return None
    
    def notify_orchestrator(self, target, vulnerabilities_found, findings_created):
        """Notify the orchestrator of fuzzing results."""
        message = create_result_message(
            "FuzzerAgent",
            "fuzz_target",
            {
                "target": target,
                "vulnerabilities_found": vulnerabilities_found,
                "findings_created": findings_created,
                "timestamp": datetime.now().isoformat()
            }
        )
        
        return self.send_message_to_agent("OrchestratorAgent", message)