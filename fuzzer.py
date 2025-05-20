#!/usr/bin/env python3
# fuzzer.py - AI-enhanced fuzzing for bug bounty targets

import os
import sys
import argparse
import logging
import json
import sqlite3
import pathlib
import time
import random
import re
import base64
import urllib.parse
import threading
import signal
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import openai

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bugbounty.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("fuzzer")

# Database configuration
DB_PATH = "bugbounty.db"

# OpenAI client
client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Global variables
running = True  # Used for graceful shutdown

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="AI-enhanced fuzzing for bug bounty targets")
    parser.add_argument("target", help="Target domain to fuzz")
    parser.add_argument("--url", help="Specific URL to fuzz (otherwise uses interesting endpoints from database)")
    parser.add_argument("--param", help="Specific parameter to fuzz")
    parser.add_argument("--vuln-type", choices=["xss", "sqli", "ssrf", "lfi", "rce", "idor", "all"], 
                       default="all", help="Vulnerability type to test for")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads (default: 5)")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between requests in seconds (default: 0.2)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--max-urls", type=int, default=25, help="Maximum number of URLs to test (default: 25)")
    parser.add_argument("--max-payloads", type=int, default=15, help="Maximum number of payloads per URL (default: 15)")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    parser.add_argument("--cookies", help="Cookies to include with requests (format: key1=value1;key2=value2)")
    parser.add_argument("--headers", help="Additional headers (format: key1:value1;key2:value2)")
    parser.add_argument("--output", help="Output file for results (JSON)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    return parser.parse_args()

def setup_vuln_table():
    """Set up vulnerabilities table in the database."""
    conn = sqlite3.connect(DB_PATH)
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

def load_interesting_endpoints(target, max_urls=25):
    """Load interesting endpoints from the database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        # Check if endpoints table exists
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='endpoints'")
        if not c.fetchone():
            logger.warning("Endpoints table doesn't exist in the database")
            conn.close()
            return []
        
        # Get interesting endpoints
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
                except:
                    pass
            
            endpoints.append({"url": url, "potential_vulnerabilities": vuln_types})
        
        conn.close()
        return endpoints
    
    except Exception as e:
        logger.error(f"Error loading endpoints: {e}")
        conn.close()
        return []

def ai_generate_payloads(url, param=None, vuln_types=None, max_payloads=15):
    """Use GPT-4o to generate payloads for the given URL and vulnerability types."""
    if not vuln_types or vuln_types == ["all"]:
        vuln_types = ["xss", "sqli", "ssrf", "lfi", "rce", "idor"]
    
    # Prepare URL info for the prompt
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
    if param:
        # If specific parameter is provided, focus on that
        target_params.append(param)
    elif params:
        # Otherwise, use all parameters from the URL
        target_params = [p["name"] for p in params]
    else:
        # If no parameters, just use path segments
        path_segments = [seg for seg in path.split("/") if seg]
        if path_segments:
            target_params = ["path"]
    
    try:
        # Ask GPT-4o for payloads
        response = client.chat.completions.create(
            model="gpt-4o",
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
        
        logger.info(f"Generated {len(all_payloads)} payloads for {url}")
        return all_payloads
    
    except Exception as e:
        logger.error(f"Error generating payloads: {e}")
        return []

def apply_payload(url, payload_data):
    """Apply a payload to the URL at the specified parameter."""
    payload = payload_data["payload"]
    param_name = payload_data["parameter"]
    
    url_parts = urllib.parse.urlparse(url)
    
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

def check_response_for_vulnerability(response, payload_data):
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

def fuzz_url(url, payload_data, args):
    """Fuzz a URL with a specific payload."""
    try:
        # Apply the payload to the URL
        fuzzed_url = apply_payload(url, payload_data)
        
        # Prepare headers
        headers = {}
        
        # Add User-Agent
        if args.user_agent:
            headers["User-Agent"] = args.user_agent
        else:
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        
        # Add additional headers
        if args.headers:
            for header_pair in args.headers.split(";"):
                if ":" in header_pair:
                    name, value = header_pair.split(":", 1)
                    headers[name.strip()] = value.strip()
        
        # Prepare cookies
        cookies = {}
        if args.cookies:
            for cookie_pair in args.cookies.split(";"):
                if "=" in cookie_pair:
                    name, value = cookie_pair.split("=", 1)
                    cookies[name.strip()] = value.strip()
        
        # Make the request
        if args.verbose:
            logger.info(f"Testing: {fuzzed_url}")
        
        time.sleep(args.delay)  # Respect rate limiting
        
        response = requests.get(
            fuzzed_url,
            headers=headers,
            cookies=cookies,
            timeout=args.timeout,
            allow_redirects=True,
            verify=False  # Ignore SSL verification
        )
        
        # Check for vulnerabilities
        result = check_response_for_vulnerability(response, payload_data)
        
        if result["is_vulnerable"]:
            logger.warning(f"Potential {payload_data['vulnerability_type']} vulnerability found at {fuzzed_url}")
            
            # Record the finding
            save_vulnerability(
                target=args.target,
                url=url,
                parameter=payload_data["parameter"],
                vulnerability_type=payload_data["vulnerability_type"],
                payload=payload_data["payload"],
                response_code=response.status_code,
                evidence=result["evidence"],
                confidence=result["confidence"]
            )
            
            return {
                "url": url,
                "fuzzed_url": fuzzed_url,
                "parameter": payload_data["parameter"],
                "vulnerability_type": payload_data["vulnerability_type"],
                "payload": payload_data["payload"],
                "response_code": response.status_code,
                "evidence": result["evidence"],
                "confidence": result["confidence"],
                "is_vulnerable": True
            }
        
        return {
            "url": url,
            "fuzzed_url": fuzzed_url,
            "parameter": payload_data["parameter"],
            "vulnerability_type": payload_data["vulnerability_type"],
            "payload": payload_data["payload"],
            "response_code": response.status_code,
            "is_vulnerable": False
        }
    
    except Exception as e:
        logger.error(f"Error fuzzing {url} with payload {payload_data['payload']}: {e}")
        return {
            "url": url,
            "error": str(e),
            "is_vulnerable": False
        }

def save_vulnerability(target, url, parameter, vulnerability_type, payload, response_code, evidence, confidence):
    """Save a vulnerability to the database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute("""
        INSERT INTO vulnerabilities 
        (target, url, parameter, vulnerability_type, payload, response_code, evidence, confidence, date_discovered, status, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        target,
        url,
        parameter,
        vulnerability_type,
        payload,
        response_code,
        evidence,
        confidence,
        datetime.now().isoformat(),
        "new",
        ""
    ))
    
    conn.commit()
    conn.close()

def create_finding(vulnerability, target):
    """Create a finding in the findings table based on a vulnerability."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Check if findings table exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
    if not c.fetchone():
        logger.warning("Findings table doesn't exist. Creating vulnerability only.")
        conn.close()
        return
    
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
    
    # Create a user-friendly description
    description = f"{vulnerability['vulnerability_type'].upper()} vulnerability in {vulnerability['parameter']} parameter"
    
    c.execute("""
        INSERT INTO findings 
        (target, host, vulnerability, severity, confidence, date, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        target,
        vulnerability["url"],
        description,
        severity,
        vulnerability["confidence"],
        datetime.now().isoformat(),
        "new"
    ))
    
    conn.commit()
    conn.close()
    
    logger.info(f"Created finding: {description}")

def summarize_vulnerabilities(vulnerabilities, target):
    """Create a summary of found vulnerabilities and add them to findings."""
    if not vulnerabilities:
        return "No vulnerabilities found."
    
    # Group by vulnerability type
    vuln_by_type = {}
    for vuln in vulnerabilities:
        v_type = vuln["vulnerability_type"]
        if v_type not in vuln_by_type:
            vuln_by_type[v_type] = []
        vuln_by_type[v_type].append(vuln)
    
    # Count by confidence level
    high_conf = len([v for v in vulnerabilities if v.get("confidence", 0) >= 0.7])
    medium_conf = len([v for v in vulnerabilities if 0.4 <= v.get("confidence", 0) < 0.7])
    low_conf = len([v for v in vulnerabilities if v.get("confidence", 0) < 0.4])
    
    summary = []
    summary.append("\n" + "=" * 80)
    summary.append("🛡️ VULNERABILITY SCAN RESULTS")
    summary.append("=" * 80)
    summary.append(f"\nTarget: {target}")
    summary.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    summary.append(f"Total Vulnerabilities: {len(vulnerabilities)}")
    summary.append(f"Confidence Levels: {high_conf} High, {medium_conf} Medium, {low_conf} Low")
    summary.append("\nVulnerabilities by Type:")
    
    for v_type, vulns in vuln_by_type.items():
        summary.append(f"\n{v_type.upper()} ({len(vulns)})")
        summary.append("-" * 80)
        
        for vuln in sorted(vulns, key=lambda x: x.get("confidence", 0), reverse=True):
            confidence_str = f"{vuln.get('confidence', 0) * 100:.0f}%"
            summary.append(f"URL: {vuln['url']}")
            summary.append(f"Parameter: {vuln['parameter']}")
            summary.append(f"Payload: {vuln['payload']}")
            summary.append(f"Evidence: {vuln['evidence']}")
            summary.append(f"Confidence: {confidence_str}")
            summary.append("")
            
            # Create a finding in the database for high confidence vulnerabilities
            if vuln.get("confidence", 0) >= 0.6:
                create_finding(vuln, target)
    
    summary.append("=" * 80)
    
    return "\n".join(summary)

def handle_signal(signum, frame):
    """Handle interrupt signal for graceful shutdown."""
    global running
    if running:
        print("\nReceived interrupt, stopping gracefully (may take a moment)...")
        running = False
    else:
        print("\nForced exit, may leave some threads running...")
        sys.exit(1)

def main():
    """Main fuzzing function."""
    global running
    
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    
    args = parse_arguments()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Disable SSL warnings
    requests.packages.urllib3.disable_warnings()
    
    # Set up database
    setup_vuln_table()
    
    results = []
    
    if args.url:
        # Fuzz a specific URL
        urls = [{"url": args.url, "potential_vulnerabilities": [args.vuln_type]}]
    else:
        # Load interesting endpoints from database
        urls = load_interesting_endpoints(args.target, args.max_urls)
        
        if not urls:
            logger.error("No interesting endpoints found for target. Run content_discovery.py first or specify a URL.")
            return 1
    
    logger.info(f"Loaded {len(urls)} URLs for fuzzing")
    
    # Process each URL
    with tqdm(total=len(urls), desc="Fuzzing Progress", unit="url") as pbar:
        for url_data in urls:
            if not running:
                break
            
            url = url_data["url"]
            vuln_types = url_data.get("potential_vulnerabilities", [])
            
            # If no vulnerability types specified or "all" is specified, use all types
            if not vuln_types or vuln_types == ["all"]:
                if args.vuln_type != "all":
                    vuln_types = [args.vuln_type]
                else:
                    vuln_types = ["xss", "sqli", "ssrf", "lfi", "rce", "idor"]
            
            # Generate payloads for this URL
            payloads = ai_generate_payloads(
                url,
                args.param,
                vuln_types,
                args.max_payloads
            )
            
            if not payloads:
                logger.warning(f"No payloads generated for {url}")
                pbar.update(1)
                continue
            
            # Fuzz with all payloads
            url_results = []
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = []
                for payload_data in payloads:
                    if not running:
                        break
                    
                    futures.append(executor.submit(
                        fuzz_url,
                        url,
                        payload_data,
                        args
                    ))
                
                # Collect results
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result.get("is_vulnerable", False):
                            url_results.append(result)
                    except Exception as e:
                        logger.error(f"Error processing result: {e}")
            
            results.extend(url_results)
            pbar.update(1)
    
    # Create summary
    summary = summarize_vulnerabilities(results, args.target)
    print(summary)
    
    # Save results to file if specified
    if args.output:
        with open(args.output, "w") as f:
            json.dump({
                "target": args.target,
                "scan_date": datetime.now().isoformat(),
                "total_vulnerabilities": len(results),
                "vulnerabilities": results
            }, f, indent=2)
        
        logger.info(f"Results saved to {args.output}")
    
    logger.info("Fuzzing complete")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("\nFuzzing cancelled by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
