#!/usr/bin/env python3
# content_discovery.py - Advanced content discovery with AI classification

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
    parser = argparse.ArgumentParser(description="Advanced content discovery with AI classification")
    parser.add_argument("target", help="Target domain to scan")
    parser.add_argument("--depth", type=int, default=2, help="Recursion depth (default: 2)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--wordlist", help="Custom wordlist for fuzzing")
    parser.add_argument("--extensions", default="php,html,js,txt,json,xml,config,bak,old,backup,sql,env", 
                       help="Extensions to fuzz (default: php,html,js,txt,json,xml,config,bak,old,backup,sql,env)")
    parser.add_argument("--skip-ai", action="store_true", help="Skip AI classification of results")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
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
                hosts = [row[0] for row in c.fetchall()]
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

def run_ffuf(host, wordlist, extensions, output_file, threads=10, depth=2, timeout=30):
    """Run ffuf on a host."""
    # Create output directory
    output_dir = pathlib.Path("workspace") / output_file.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Format extensions for ffuf
    ext_param = ""
    if extensions:
        ext_param = f"-e {extensions}"
    
    # Determine recursion parameters
    recursion_params = ""
    if depth > 1:
        recursion_params = f"-recursion -recursion-depth {depth}"
    
    # Build ffuf command
    ffuf_cmd = (
        f"ffuf -u {host}/FUZZ -w {wordlist} {ext_param} "
        f"-mc 200,201,202,203,204,301,302,307,401,403,405 "
        f"-t {threads} {recursion_params} "
        f"-timeout {timeout} "
        f"-o {output_file} -of json"
    )
    
    logger.info(f"Running: {ffuf_cmd}")
    
    try:
        # Run ffuf
        subprocess.run(ffuf_cmd, shell=True, check=True)
        logger.info(f"Completed ffuf scan on {host}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running ffuf on {host}: {e}")
        return False

def run_httpx(host, output_file):
    """Run httpx on a host for header analysis."""
    # Create output directory
    output_dir = pathlib.Path("workspace") / output_file.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Build httpx command
    httpx_cmd = (
        f"httpx -u {host} -silent -tech-detect -title -status-code "
        f"-follow-redirects -no-color -json -o {output_file}"
    )
    
    logger.info(f"Running: {httpx_cmd}")
    
    try:
        # Run httpx
        subprocess.run(httpx_cmd, shell=True, check=True)
        logger.info(f"Completed httpx scan on {host}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running httpx on {host}: {e}")
        return False

def check_common_vulnerabilities(host, output_file):
    """Check for common vulnerabilities and misconfigurations."""
    # Create output directory
    output_dir = pathlib.Path("workspace") / output_file.parent
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
    
    results = []
    for url in checks:
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            if response.status_code in (200, 403, 401):
                results.append({
                    "url": url,
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "content_type": response.headers.get("Content-Type", ""),
                    "interesting": True
                })
                logger.info(f"Found interesting endpoint: {url} [{response.status_code}]")
        except Exception as e:
            logger.debug(f"Error checking {url}: {e}")
    
    # Save results
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"Completed vulnerability checks on {host}, found {len(results)} potentially interesting endpoints")
    return True

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
            
            # Simple check for "interestingness"
            interesting = False
            if any(ext in url.lower() for ext in [".php", ".js", ".xml", ".json", ".sql", ".bak", ".config", ".env"]):
                interesting = True
            elif status in (401, 403):
                interesting = True
            elif any(word in url.lower() for word in ["admin", "config", "backup", "api", "test", "dev", "upload", "user"]):
                interesting = True
            
            endpoints.append({
                "url": url,
                "status_code": status,
                "content_length": content_length,
                "content_type": content_type,
                "words": words,
                "interesting": interesting
            })
        
        return endpoints
    except Exception as e:
        logger.error(f"Error parsing ffuf results: {e}")
        return []

def ai_classify_endpoints(endpoints, target):
    """Use GPT-4o to classify which endpoints are most interesting for bug bounty."""
    if not endpoints or len(endpoints) == 0:
        return endpoints
    
    # Limit to max 50 endpoints per batch for GPT context
    batches = [endpoints[i:i+50] for i in range(0, len(endpoints), 50)]
    all_classified = []
    
    for batch in batches:
        try:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": """You are an expert bug bounty hunter specializing in web application security.
                    Analyze the list of URLs/endpoints discovered during content discovery and classify them by security interest.
                    
                    For each endpoint, determine:
                    1. How interesting it is for security testing (high/medium/low)
                    2. What potential vulnerabilities it might have
                    3. What specific tests should be prioritized
                    
                    Use these security-focused criteria:
                    - Endpoints with admin/management functionality
                    - File upload/download capabilities
                    - API endpoints, especially with parameters
                    - Authentication/authorization endpoints
                    - Database/backup files
                    - Configuration files
                    - Development artifacts (.git, etc)
                    - Legacy/deprecated functionality
                    
                    Return a JSON array with the original properties plus these additional ones:
                    - interest_level: "high", "medium", or "low"
                    - potential_vulnerabilities: array of vulnerability types
                    - testing_notes: specific test suggestions
                    """},
                    {"role": "user", "content": f"""Here are endpoints discovered for {target}:
                    
                    {json.dumps(batch, indent=2)}
                    
                    Classify them by security interest and suggest testing approaches.
                    """}
                ],
                response_format={"type": "json_object"},
                temperature=0.7
            )
            
            result = json.loads(response.choices[0].message.content)
            classified_endpoints = result.get("endpoints", result.get("classified_endpoints", []))
            
            # If GPT's response doesn't match expected format, handle it
            if not classified_endpoints and "results" in result:
                classified_endpoints = result.get("results", [])
            
            # If still can't find endpoints in the response, just add interest_level to original batch
            if not classified_endpoints:
                logger.warning("AI classification returned unexpected format, using fallback")
                classified_endpoints = batch
                for endpoint in classified_endpoints:
                    # Add default classifications
                    endpoint["interest_level"] = "medium" if endpoint.get("interesting", False) else "low"
                    endpoint["potential_vulnerabilities"] = []
                    endpoint["testing_notes"] = ""
            
            all_classified.extend(classified_endpoints)
            
        except Exception as e:
            logger.error(f"Error in AI classification: {e}")
            # On error, return original batch with default values
            for endpoint in batch:
                endpoint["interest_level"] = "medium" if endpoint.get("interesting", False) else "low"
                endpoint["potential_vulnerabilities"] = []
                endpoint["testing_notes"] = ""
            all_classified.extend(batch)
    
    # Convert interest_level to boolean interesting flag for database compatibility
    for endpoint in all_classified:
        if endpoint.get("interest_level") in ["high", "medium"]:
            endpoint["interesting"] = True
        
    return all_classified

def save_to_database(endpoints, target):
    """Save discovered endpoints to database."""
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
                url TEXT,
                status_code INTEGER,
                content_type TEXT,
                interesting BOOLEAN DEFAULT 0,
                notes TEXT,
                date_discovered TEXT
            )
            """)
    except Exception as e:
        logger.error(f"Error checking/creating endpoints table: {e}")
        conn.close()
        return 0
    
    # Insert endpoints
    count = 0
    for endpoint in endpoints:
        try:
            # First check if endpoint already exists
            c.execute("SELECT id FROM endpoints WHERE target=? AND url=?", 
                     (target, endpoint["url"]))
            existing = c.fetchone()
            
            if existing:
                # Update existing endpoint
                c.execute("""
                UPDATE endpoints 
                SET status_code=?, content_type=?, interesting=?, 
                    notes=?, date_discovered=?
                WHERE id=?
                """, (
                    endpoint.get("status_code", 0),
                    endpoint.get("content_type", ""),
                    1 if endpoint.get("interesting", False) else 0,
                    json.dumps({
                        "interest_level": endpoint.get("interest_level", "low"),
                        "potential_vulnerabilities": endpoint.get("potential_vulnerabilities", []),
                        "testing_notes": endpoint.get("testing_notes", ""),
                        "content_length": endpoint.get("content_length", 0),
                        "words": endpoint.get("words", 0)
                    }),
                    datetime.now().isoformat(),
                    existing[0]
                ))
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
                    1 if endpoint.get("interesting", False) else 0,
                    json.dumps({
                        "interest_level": endpoint.get("interest_level", "low"),
                        "potential_vulnerabilities": endpoint.get("potential_vulnerabilities", []),
                        "testing_notes": endpoint.get("testing_notes", ""),
                        "content_length": endpoint.get("content_length", 0),
                        "words": endpoint.get("words", 0)
                    }),
                    datetime.now().isoformat()
                ))
                count += 1
        except Exception as e:
            logger.error(f"Error saving endpoint {endpoint.get('url', 'unknown')}: {e}")
    
    conn.commit()
    conn.close()
    
    logger.info(f"Saved {count} new endpoints to database")
    return count

def process_single_host(host, target, wordlist, extensions, depth, threads, timeout, skip_ai):
    """Process a single host with all discovery methods."""
    # Create workspace directory
    workspace = pathlib.Path("workspace") / target / "content_discovery"
    workspace.mkdir(parents=True, exist_ok=True)
    
    # Clean host name for filenames
    host_clean = host.replace("https://", "").replace("http://", "").replace("/", "_")
    
    # Run ffuf for content discovery
    ffuf_output = workspace / f"{host_clean}_ffuf.json"
    ffuf_success = run_ffuf(host, wordlist, extensions, ffuf_output, threads, depth, timeout)
    
    # Run httpx for server info and tech detection
    httpx_output = workspace / f"{host_clean}_httpx.json"
    httpx_success = run_httpx(host, httpx_output)
    
    # Check common vulnerabilities
    vulns_output = workspace / f"{host_clean}_vulns.json"
    vulns_success = check_common_vulnerabilities(host, vulns_output)
    
    # Parse ffuf results
    all_endpoints = []
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
    
    # Classify endpoints using AI
    if not skip_ai and all_endpoints:
        all_endpoints = ai_classify_endpoints(all_endpoints, target)
    
    # Save to database
    save_count = save_to_database(all_endpoints, target)
    
    # Create summary
    summary = {
        "host": host,
        "total_endpoints": len(all_endpoints),
        "interesting_endpoints": sum(1 for e in all_endpoints if e.get("interesting", False)),
        "high_interest": sum(1 for e in all_endpoints if e.get("interest_level") == "high"),
        "medium_interest": sum(1 for e in all_endpoints if e.get("interest_level") == "medium"),
        "low_interest": sum(1 for e in all_endpoints if e.get("interest_level") == "low"),
        "status_codes": {},
        "top_vulnerabilities": []
    }
    
    # Count status codes
    for endpoint in all_endpoints:
        status = endpoint.get("status_code", 0)
        summary["status_codes"][status] = summary["status_codes"].get(status, 0) + 1
    
    # Count vulnerability types
    vuln_counter = {}
    for endpoint in all_endpoints:
        for vuln in endpoint.get("potential_vulnerabilities", []):
            vuln_counter[vuln] = vuln_counter.get(vuln, 0) + 1
    
    # Get top 5 vulnerabilities
    summary["top_vulnerabilities"] = sorted(
        [{"type": k, "count": v} for k, v in vuln_counter.items()],
        key=lambda x: x["count"],
        reverse=True
    )[:5]
    
    # Save summary
    summary_file = workspace / f"{host_clean}_summary.json"
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)
    
    return summary

def main():
    """Main content discovery function."""
    args = parse_arguments()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    logger.info(f"Starting content discovery for {args.target}")
    
    # Get hosts to scan
    hosts = get_host_list(args.target)
    if not hosts:
        logger.error(f"No hosts found for target: {args.target}")
        return 1
    
    logger.info(f"Found {len(hosts)} hosts to scan")
    
    # Select wordlist
    wordlist = select_wordlist(args.wordlist)
    
    # Process each host
    summaries = []
    with ThreadPoolExecutor(max_workers=min(len(hosts), 5)) as executor:
        futures = []
        for host in hosts:
            future = executor.submit(
                process_single_host,
                host,
                args.target,
                wordlist,
                args.extensions,
                args.depth,
                args.threads,
                args.timeout,
                args.skip_ai
            )
            futures.append(future)
        
        # Collect results
        for future in as_completed(futures):
            try:
                summary = future.result()
                summaries.append(summary)
            except Exception as e:
                logger.error(f"Error processing host: {e}")
    
    # Create overall summary
    total_summary = {
        "target": args.target,
        "hosts_scanned": len(hosts),
        "total_endpoints": sum(s["total_endpoints"] for s in summaries),
        "interesting_endpoints": sum(s["interesting_endpoints"] for s in summaries),
        "high_interest": sum(s["high_interest"] for s in summaries),
        "medium_interest": sum(s["medium_interest"] for s in summaries),
        "low_interest": sum(s["low_interest"] for s in summaries),
        "host_summaries": summaries,
        "date": datetime.now().isoformat()
    }
    
    # Save overall summary
    summary_path = pathlib.Path("workspace") / args.target / "content_discovery" / "summary.json"
    with open(summary_path, "w") as f:
        json.dump(total_summary, f, indent=2)
    
    logger.info(f"Content discovery complete for {args.target}")
    logger.info(f"Found {total_summary['total_endpoints']} total endpoints, {total_summary['interesting_endpoints']} marked as interesting")
    logger.info(f"Summary saved to {summary_path}")
    
    # Output to custom file if specified
    if args.output:
        with open(args.output, "w") as f:
            json.dump(total_summary, f, indent=2)
        logger.info(f"Summary also saved to {args.output}")
    
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
