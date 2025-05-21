#!/usr/bin/env python3
# content_discovery.py - Advanced content discovery with AI classification and batch processing

import os
import sys
import argparse
import subprocess
import pathlib
import sqlite3
import json
import logging
import time
import openai
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bugbounty.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("content_discovery")

# Database configuration
DB_PATH = "bugbounty.db"

# OpenAI client
client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Advanced content discovery with AI classification and batch processing")
    parser.add_argument("targets", nargs='+', help="Target domain(s) to scan")
    parser.add_argument("--batch-size", type=int, default=5, help="Number of hosts to process in parallel (default: 5)")
    parser.add_argument("--depth", type=int, default=2, help="Recursion depth (default: 2)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads per host (default: 10)")
    parser.add_argument("--wordlist", help="Custom wordlist for fuzzing")
    parser.add_argument("--extensions", default="php,html,js,txt,json,xml,config,bak,old,backup,sql,env", 
                       help="Extensions to fuzz (default: php,html,js,txt,json,xml,config,bak,old,backup,sql,env)")
    parser.add_argument("--ai-batch-size", type=int, default=100, help="Batch size for AI classification (default: 100)")
    parser.add_argument("--skip-ai", action="store_true", help="Skip AI classification of results")
    parser.add_argument("--output-dir", help="Output directory for results")
    parser.add_argument("--timeout", type=int, default=20, help="Request timeout in seconds (default: 20)")
    parser.add_argument("--max-endpoints", type=int, default=500, help="Maximum endpoints to process per target (default: 500)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    return parser.parse_args()

def get_host_list(target):
    """Get list of hosts for target from database or live_hosts.txt."""
    # Try to get hosts from database first
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute("SELECT DISTINCT host FROM findings WHERE target = ?", (target,))
        hosts = [row[0] for row in c.fetchall()]
        
        if not hosts:
            # If no hosts in database, try endpoints table
            try:
                c.execute("SELECT DISTINCT url FROM endpoints WHERE target = ?", (target,))
                urls = [row[0] for row in c.fetchall()]
                hosts = []
                for url in urls:
                    try:
                        parsed = requests.utils.urlparse(url)
                        host = f"{parsed.scheme}://{parsed.netloc}"
                        if host not in hosts:
                            hosts.append(host)
                    except:
                        pass
            except sqlite3.OperationalError:
                # Endpoints table might not exist yet
                hosts = []
    except sqlite3.OperationalError:
        # Findings table might not exist yet
        hosts = []
    
    conn.close()
    
    # If still no hosts, try live_hosts.txt
    if not hosts:
        workspace = pathlib.Path("workspace") / target
        live_hosts_file = workspace / "live_hosts.txt"
        
        if live_hosts_file.exists():
            with open(live_hosts_file, "r") as f:
                hosts = [line.strip() for line in f if line.strip()]
    
    # If still no hosts, use the target itself
    if not hosts:
        # Check if target has http/https prefix
        if not target.startswith(('http://', 'https://')):
            hosts = [f"https://{target}"]
        else:
            hosts = [target]
    
    return hosts

def select_wordlist(custom_wordlist=None):
    """Select wordlist for content discovery."""
    if custom_wordlist and os.path.exists(custom_wordlist):
        return custom_wordlist
    
    # Common wordlist locations
    common_locations = [
        "~/wordlists/content-discovery-all.txt",
        "~/wordlists/discovery/content_discovery_all.txt",
        "~/wordlists/SecLists/Discovery/Web-Content/common.txt",
        "~/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    ]
    
    # Try to find a wordlist
    for location in common_locations:
        expanded_path = os.path.expanduser(location)
        if os.path.exists(expanded_path):
            logger.info(f"Using wordlist: {expanded_path}")
            return expanded_path
    
    # If no wordlist found, use a small built-in one
    logger.warning("No wordlist found. Using built-in mini wordlist.")
    mini_wordlist = pathlib.Path("mini_wordlist.txt")
    
    with open(mini_wordlist, "w") as f:
        f.write("""admin
login
api
backup
config
dashboard
dev
development
docs
download
images
js
media
profiles
scripts
static
test
tmp
upload
uploads
users
wp-admin
wp-content
.git
.env
.svn
robots.txt
sitemap.xml
""")
    
    return str(mini_wordlist)

def run_ffuf(host, wordlist, extensions, output_file, threads=10, depth=2, timeout=20):
    """Run ffuf on a host with optimized settings and overall timeout."""
    # Create output directory
    output_dir = output_file.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Format extensions for ffuf
    ext_param = ""
    if extensions:
        ext_param = f"-e {extensions}"
    
    # Determine recursion parameters
    recursion_params = ""
    if depth > 0:
        recursion_params = f"-recursion -recursion-depth {depth}"
    
    # Build ffuf command with additional rate-limiting and optimization parameters
    ffuf_cmd = (
        f"ffuf -u {host}/FUZZ -w {wordlist} {ext_param} "
        f"-mc 200,201,202,203,204,301,302,307,401,403,405 "
        f"-t {threads} {recursion_params} "
        f"-timeout {timeout} "
        f"-rate 10 "  # Add rate limiting to avoid triggering WAF/rate limits
        f"-maxtime 300 "  # Add maximum runtime of 5 minutes
        f"-o {output_file} -of json"
    )
    
    logger.info(f"Running: {ffuf_cmd}")
    
    try:
        # Run ffuf with a global timeout
        process = subprocess.run(
            ffuf_cmd, 
            shell=True, 
            timeout=360,  # Force kill after 6 minutes regardless
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        logger.info(f"Completed ffuf scan on {host}")
        return process.returncode == 0
    except subprocess.TimeoutExpired:
        logger.warning(f"ffuf scan on {host} timed out after max allowed time")
        return False
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running ffuf on {host}: {e}")
        return False
def run_httpx(host, output_file):
    """Run httpx on a host for header analysis with optimized settings."""
    # Create output directory
    output_dir = output_file.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Build httpx command with optimized settings
    httpx_cmd = (
        f"httpx -u {host} -silent -tech-detect -title -status-code "
        f"-follow-redirects -no-color -json -o {output_file} -timeout 10"
    )
    
    logger.info(f"Running: {httpx_cmd}")
    
    try:
        # Run httpx with a timeout
        process = subprocess.run(
            httpx_cmd, 
            shell=True, 
            timeout=300,  # 5 minutes timeout
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        logger.info(f"Completed httpx scan on {host}")
        return process.returncode == 0
    except subprocess.TimeoutExpired:
        logger.warning(f"httpx scan on {host} timed out after 5 minutes")
        return False
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running httpx on {host}: {e}")
        return False

def check_common_vulnerabilities(host, output_file, timeout=10):
    """Check for common vulnerabilities and misconfigurations with optimized settings."""
    # Create output directory
    output_dir = output_file.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # List of common vulnerability checks
    checks = [
        f"{host}/.git/HEAD",
        f"{host}/.env",
        f"{host}/.gitlab-ci.yml",
        f"{host}/wp-config.php",
        f"{host}/config.php",
        f"{host}/server-status",
        f"{host}/phpinfo.php",
        f"{host}/info.php",
        f"{host}/.svn/entries",
        f"{host}/.DS_Store",
        f"{host}/backup.zip",
        f"{host}/dump.sql",
        f"{host}/api/swagger",
        f"{host}/api/docs",
    ]
    
    # Use a thread pool to check multiple endpoints in parallel
    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {executor.submit(check_url, url, timeout): url for url in checks}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                if result:
                    results.append(result)
                    logger.info(f"Found interesting endpoint: {url} [{result['status_code']}]")
            except Exception as e:
                logger.debug(f"Error checking {url}: {e}")
    
    # Save results
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"Completed vulnerability checks on {host}, found {len(results)} potentially interesting endpoints")
    return True

def check_url(url, timeout=10):
    """Check a single URL for vulnerabilities."""
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
        if response.status_code in (200, 403, 401):
            return {
                "url": url,
                "status_code": response.status_code,
                "content_length": len(response.content),
                "content_type": response.headers.get("Content-Type", ""),
                "interesting": True
            }
        return None
    except Exception:
        return None

def parse_ffuf_results(result_file):
    """Parse ffuf JSON results."""
    if not os.path.exists(result_file):
        logger.warning(f"Result file not found: {result_file}")
        return []
    
    try:
        with open(result_file, "r") as f:
            results = json.load(f)
        
        # Extract relevant data
        endpoints = []
        for result in results.get("results", []):
            url = result.get("url", "")
            status = result.get("status", 0)
            content_length = result.get("length", 0)
            content_type = result.get("content_type", "")
            words = result.get("words", 0)
            
            # Enhanced check for "interestingness"
            interesting = False
            interesting_reason = "Default interesting marking"
            
            # Check for specific interesting patterns
            if any(ext in url.lower() for ext in [".php", ".js", ".xml", ".json", ".sql", ".bak", ".config", ".env"]):
                interesting = True
                interesting_reason = f"Special file extension found in URL: {url}"
            elif status in (401, 403):
                interesting = True
                interesting_reason = f"Protected resource (status {status}): {url}"
            elif any(word in url.lower() for word in ["admin", "config", "backup", "api", "test", "dev", "upload", "user"]):
                interesting = True
                interesting_reason = f"Sensitive path component found: {url}"
            
            logger.info(f"Adding endpoint {url} (Interesting: {interesting}, Reason: {interesting_reason})")
            
            endpoints.append({
                "url": url,
                "status_code": status,
                "content_length": content_length,
                "content_type": content_type,
                "words": words,
                "interesting": interesting,
                "interesting_reason": interesting_reason,
                "interest_level": "medium" if interesting else "low"
            })
        
        logger.info(f"Parsed {len(endpoints)} endpoints from ffuf results")
        return endpoints
    except Exception as e:
        logger.error(f"Error parsing ffuf results: {e}")
        return []

def batch_ai_classify_endpoints(all_endpoints, target, batch_size=100, skip_ai=False):
    """Classify endpoints in batches using AI."""
    if skip_ai or not all_endpoints:
        logger.info("Skipping AI classification as requested or no endpoints to classify")
        for endpoint in all_endpoints:
            if endpoint.get("interesting", False):
                endpoint["interest_level"] = "medium"
                endpoint["potential_vulnerabilities"] = []
            else:
                endpoint["interest_level"] = "low"
                endpoint["potential_vulnerabilities"] = []
        return all_endpoints
    
    logger.info(f"Starting batch AI classification for {len(all_endpoints)} endpoints")
    
    # Divide endpoints into batches
    batches = [all_endpoints[i:i+batch_size] for i in range(0, len(all_endpoints), batch_size)]
    classified_endpoints = []
    
    # Process each batch
    for i, batch in enumerate(batches):
        logger.info(f"Processing batch {i+1}/{len(batches)} ({len(batch)} endpoints)")
        try:
            # Use OpenAI to classify the batch
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": """You are an expert bug bounty hunter analyzing web endpoints.
                    Classify each endpoint by security interest level and potential vulnerabilities.
                    
                    For each endpoint, provide:
                    1. interest_level: "high", "medium", or "low"
                    2. potential_vulnerabilities: array of vulnerability types that might be present
                    
                    Focus on endpoints that might expose:
                    - Admin/management interfaces
                    - File upload/download capabilities
                    - API endpoints with parameters
                    - Authentication mechanisms
                    - Configuration files
                    - Development artifacts
                    - Legacy functionality
                    
                    Return a JSON array of endpoints with these classifications added.
                    """},
                    {"role": "user", "content": f"""Here are {len(batch)} endpoints from target {target} to classify:
                    
                    {json.dumps(batch, indent=2)}
                    
                    Classify each by security interest and potential vulnerabilities.
                    """}
                ],
                response_format={"type": "json_object"},
                temperature=0.2
            )
            
            result = json.loads(response.choices[0].message.content)
            
            # Extract the classified endpoints from the response
            batch_result = result.get("endpoints", [])
            if not batch_result and isinstance(result, list):
                batch_result = result
            if not batch_result and "classified_endpoints" in result:
                batch_result = result.get("classified_endpoints", [])
            
            # If still no results, apply default classifications
            if not batch_result:
                logger.warning(f"AI classification returned unexpected format for batch {i+1}, using defaults")
                for endpoint in batch:
                    if endpoint.get("interesting", False):
                        endpoint["interest_level"] = "medium"
                        endpoint["potential_vulnerabilities"] = []
                    else:
                        endpoint["interest_level"] = "low"
                        endpoint["potential_vulnerabilities"] = []
                classified_endpoints.extend(batch)
            else:
                classified_endpoints.extend(batch_result)
            
        except Exception as e:
            logger.error(f"Error in AI classification for batch {i+1}: {e}")
            # Apply default classifications on error
            for endpoint in batch:
                if endpoint.get("interesting", False):
                    endpoint["interest_level"] = "medium"
                    endpoint["potential_vulnerabilities"] = []
                else:
                    endpoint["interest_level"] = "low"
                    endpoint["potential_vulnerabilities"] = []
            classified_endpoints.extend(batch)
        
        # Add a small delay between batches to avoid rate limits
        if i < len(batches) - 1:
            time.sleep(2)
    
    # Ensure interesting flag is set based on interest_level
    for endpoint in classified_endpoints:
        if endpoint.get("interest_level") in ["high", "medium"]:
            endpoint["interesting"] = True
    
    logger.info(f"Completed AI classification for {len(classified_endpoints)} endpoints")
    return classified_endpoints

def save_endpoints_to_db(endpoints, target):
    """Save discovered endpoints to database in batches."""
    if not endpoints:
        logger.warning(f"No endpoints to save for target {target}")
        return 0
    
    # First check if endpoints table exists
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='endpoints'")
        if not c.fetchone():
            # Create endpoints table if it doesn't exist
            c.execute("""
            CREATE TABLE endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                url TEXT UNIQUE,
                status_code INTEGER,
                content_type TEXT,
                interesting BOOLEAN DEFAULT 0,
                notes TEXT,
                date_discovered TEXT
            )
            """)
            logger.info("Created endpoints table in database")
    except Exception as e:
        logger.error(f"Error checking/creating endpoints table: {e}")
        conn.close()
        return 0
    
    # Insert endpoints in batches
    conn.close()  # Close and reopen for batch operations
    
    # Use bulk insert with executemany for better performance
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    conn.execute("BEGIN TRANSACTION")
    
    new_count = 0
    updated_count = 0
    
    try:
        # Process in batches of 100
        batch_size = 100
        for i in range(0, len(endpoints), batch_size):
            batch = endpoints[i:i+batch_size]
            
            # First check which endpoints already exist
            for endpoint in batch:
                c.execute("SELECT id, interesting FROM endpoints WHERE target=? AND url=?", 
                         (target, endpoint["url"]))
                existing = c.fetchone()
                
                # Always ensure interesting is set appropriately
                is_interesting = 1 if endpoint.get("interesting", False) else 0
                
                # Prepare notes JSON
                notes_data = {
                    "interest_level": endpoint.get("interest_level", "low"),
                    "potential_vulnerabilities": endpoint.get("potential_vulnerabilities", []),
                    "content_length": endpoint.get("content_length", 0),
                    "words": endpoint.get("words", 0),
                    "interesting_reason": endpoint.get("interesting_reason", "")
                }
                
                if existing:
                    # Only update if the existing endpoint is not already marked as interesting
                    # or if the new one is interesting
                    existing_id, existing_interesting = existing
                    
                    # If current is not interesting but new one is, or we have new data, update
                    if not existing_interesting or is_interesting:
                        c.execute("""
                        UPDATE endpoints 
                        SET status_code=?, content_type=?, interesting=?, 
                            notes=?, date_discovered=?
                        WHERE id=?
                        """, (
                            endpoint.get("status_code", 0),
                            endpoint.get("content_type", ""),
                            is_interesting,
                            json.dumps(notes_data),
                            datetime.now().isoformat(),
                            existing_id
                        ))
                        updated_count += 1
                else:
                    # Insert new endpoint
                    c.execute("""
                    INSERT INTO endpoints (target, url, status_code, content_type, interesting, notes, date_discovered)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        target,
                        endpoint["url"],
                        endpoint.get("status_code", 0),
                        endpoint.get("content_type", ""),
                        is_interesting,
                        json.dumps(notes_data),
                        datetime.now().isoformat()
                    ))
                    new_count += 1
                    
        conn.commit()
        logger.info(f"Saved {new_count} new endpoints and updated {updated_count} existing endpoints in database")
    except Exception as e:
        conn.rollback()
        logger.error(f"Error batch saving endpoints: {e}")
    finally:
        conn.close()
    
    return new_count

def process_host(args, host, target, wordlist):
    """Process a single host with all discovery methods."""
    host_start_time = time.time()
    logger.info(f"Starting discovery on {host} for target {target}")
    
    # Create workspace directory
    workspace = pathlib.Path("workspace") / target / "content_discovery"
    workspace.mkdir(parents=True, exist_ok=True)
    
    # Clean host name for filenames
    host_clean = host.replace("https://", "").replace("http://", "").replace("/", "_")
    
    all_endpoints = []
    
    try:
        # Run ffuf for content discovery
        ffuf_output = workspace / f"{host_clean}_ffuf.json"
        ffuf_success = run_ffuf(
            host, 
            wordlist, 
            args.extensions, 
            ffuf_output, 
            args.threads, 
            args.depth, 
            args.timeout
        )
        
        # Run httpx for server info and tech detection
        httpx_output = workspace / f"{host_clean}_httpx.json"
        httpx_success = run_httpx(host, httpx_output)
        
        # Check common vulnerabilities
        vulns_output = workspace / f"{host_clean}_vulns.json"
        vulns_success = check_common_vulnerabilities(host, vulns_output, args.timeout)
        
        # Parse ffuf results
        if ffuf_success:
            ffuf_endpoints = parse_ffuf_results(ffuf_output)
            all_endpoints.extend(ffuf_endpoints)
        
        # Parse vulnerability check results
        if vulns_success and os.path.exists(vulns_output):
            try:
                with open(vulns_output, 'r') as f:
                    vuln_endpoints = json.load(f)
                    all_endpoints.extend(vuln_endpoints)
            except Exception as e:
                logger.error(f"Error parsing vulnerability results: {e}")
        
        # Create summary
        summary = {
            "host": host,
            "total_endpoints": len(all_endpoints),
            "interesting_endpoints": sum(1 for e in all_endpoints if e.get("interesting", False)),
            "endpoints": all_endpoints
        }
        
        # Save host summary
        summary_file = workspace / f"{host_clean}_summary.json"
        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2)
        
        host_end_time = time.time()
        logger.info(f"Completed discovery on {host} in {host_end_time - host_start_time:.2f} seconds")
        
        return summary
    
    except Exception as e:
        logger.error(f"Error processing host {host}: {e}")
        host_end_time = time.time()
        logger.info(f"Failed discovery on {host} after {host_end_time - host_start_time:.2f} seconds")
        
        return {
            "host": host,
            "total_endpoints": len(all_endpoints),
            "interesting_endpoints": sum(1 for e in all_endpoints if e.get("interesting", False)),
            "endpoints": all_endpoints,
            "error": str(e)
        }

def process_target(args, target):
    """Process a single target with parallel host processing."""
    target_start_time = time.time()
    logger.info(f"Starting content discovery for {target}")
    
    # Get hosts to scan
    hosts = get_host_list(target)
    if not hosts:
        logger.error(f"No hosts found for target: {target}")
        return {"status": "error", "message": "No hosts found", "endpoints_found": 0}
    
    logger.info(f"Found {len(hosts)} hosts to scan for {target}")
    
    # Select wordlist
    wordlist = select_wordlist(args.wordlist)
    
    # Create workspace directory
    workspace = pathlib.Path("workspace") / target / "content_discovery"
    workspace.mkdir(parents=True, exist_ok=True)
    
    # Process hosts in parallel
    all_endpoints = []
    summaries = []
    
    with ThreadPoolExecutor(max_workers=args.batch_size) as executor:
        future_to_host = {executor.submit(process_host, args, host, target, wordlist): host for host in hosts}
        
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                summary = future.result()
                summaries.append(summary)
                all_endpoints.extend(summary.get("endpoints", []))
                logger.info(f"Processed {host} for {target}: found {summary.get('total_endpoints', 0)} endpoints")
            except Exception as e:
                logger.error(f"Error processing host {host} for {target}: {e}")
    
    # Limit the number of endpoints to classify
    if args.max_endpoints and len(all_endpoints) > args.max_endpoints:
        logger.warning(f"Limiting endpoints for classification to {args.max_endpoints} (from {len(all_endpoints)})")
        # Prioritize interesting endpoints
        interesting = [e for e in all_endpoints if e.get("interesting", False)]
        non_interesting = [e for e in all_endpoints if not e.get("interesting", False)]
        
        if len(interesting) > args.max_endpoints:
            all_endpoints = interesting[:args.max_endpoints]
        else:
            remaining = args.max_endpoints - len(interesting)
            all_endpoints = interesting + non_interesting[:remaining]
    
    # Batch classify endpoints using AI
    classified_endpoints = batch_ai_classify_endpoints(
        all_endpoints, 
        target, 
        args.ai_batch_size, 
        args.skip_ai
    )
    
    # Save classified endpoints to database
    save_endpoints_to_db(classified_endpoints, target)
    
    # Create summary statistics
    high_interest = sum(1 for e in classified_endpoints if e.get("interest_level") == "high")
    medium_interest = sum(1 for e in classified_endpoints if e.get("interest_level") == "medium")
    low_interest = sum(1 for e in classified_endpoints if e.get("interest_level") == "low")
    
    # Count status codes
    status_codes = {}
    for endpoint in classified_endpoints:
        status = endpoint.get("status_code", 0)
        status_codes[status] = status_codes.get(status, 0) + 1
    
    # Count vulnerabilities by type
    vuln_counter = {}
    for endpoint in classified_endpoints:
        for vuln in endpoint.get("potential_vulnerabilities", []):
            vuln_counter[vuln] = vuln_counter.get(vuln, 0) + 1
    
    # Get top vulnerabilities
    top_vulnerabilities = sorted(
        [{"type": k, "count": v} for k, v in vuln_counter.items()],
        key=lambda x: x["count"],
        reverse=True
    )[:5]
    
    # Create overall summary
    total_summary = {
        "target": target,
        "hosts_scanned": len(hosts),
        "total_endpoints": len(classified_endpoints),
        "interesting_endpoints": sum(1 for e in classified_endpoints if e.get("interesting", False)),
        "high_interest": high_interest,
        "medium_interest": medium_interest,
        "low_interest": low_interest,
        "host_summaries": summaries,
        "status_codes": status_codes,
        "top_vulnerabilities": top_vulnerabilities,
        "date": datetime.now().isoformat()
    }
    
    # Save overall summary
    summary_path = workspace / "summary.json"
    with open(summary_path, "w") as f:
        json.dump(total_summary, f, indent=2)
    
    target_end_time = time.time()
    total_time = target_end_time - target_start_time
    logger.info(f"Content discovery complete for {target} in {total_time:.2f} seconds")
    logger.info(f"Found {total_summary['total_endpoints']} total endpoints, {total_summary['interesting_endpoints']} marked as interesting")
    
    return {
        "status": "success",
        "summary": total_summary,
        "runtime_seconds": total_time,
        "endpoints_found": total_summary['total_endpoints'],
        "interesting_endpoints": total_summary['interesting_endpoints']
    }

def main():
    """Main content discovery function with batch processing."""
    args = parse_arguments()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    start_time = time.time()
    logger.info(f"Starting batch content discovery for {len(args.targets)} targets")
    
    # Process each target sequentially
    results = {}
    for target in args.targets:
        try:
            result = process_target(args, target)
            results[target] = result
        except Exception as e:
            logger.error(f"Error processing target {target}: {e}")
            results[target] = {"status": "error", "message": str(e)}
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # Output summary
    print("\n" + "=" * 70)
    print(f"CONTENT DISCOVERY COMPLETE - {len(args.targets)} targets in {total_time:.2f} seconds")
    print("=" * 70)
    
    for target, result in results.items():
        status = result.get("status", "unknown")
        endpoints = result.get("endpoints_found", 0)
        interesting = result.get("interesting_endpoints", 0)
        runtime = result.get("runtime_seconds", 0)
        
        print(f"{target}: {status} - {endpoints} endpoints ({interesting} interesting) in {runtime:.2f}s")
    
    print("=" * 70)
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("\nContent discovery cancelled by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)