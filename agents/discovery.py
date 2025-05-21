#!/usr/bin/env python3
# discovery.py - DiscoveryAgent for the bug bounty automation framework

import os
import sys
import json
import sqlite3
import subprocess
import logging
import pathlib
import time
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from autogen import ConversableAgent

# Add parent directory to path to access utilities
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.config_loader import get_model_config
from utils.message_utils import (
    create_standard_message, create_request_message,
    create_response_message, create_error_message, create_result_message,
    message_to_string, message_to_chat_message
)

class DiscoveryAgent:
    """
    Specialized agent for content discovery and endpoint analysis in the bug bounty process.
    Discovers and classifies endpoints, APIs, and potential attack vectors for a target.
    """
    
    def __init__(self):
        # Get the configuration for the agent
        model_config = get_model_config("gpt-4o") if os.getenv("USE_ENHANCED_MODEL") else get_model_config()
        
        # Create the ConversableAgent
        self.agent = ConversableAgent(
            name="DiscoveryAgent",
            system_message="""You are the DiscoveryAgent for a bug bounty automation framework.
            Your responsibilities include:
            1. Discovering web endpoints, APIs, and content
            2. Analyzing and classifying discovered endpoints
            3. Identifying potentially vulnerable endpoints
            4. Reporting findings to the OrchestratorAgent
            
            You have access to tools like ffuf, httpx, and other reconnaissance utilities.
            Use them effectively to discover security-relevant endpoints.""",
            llm_config={
                "config_list": [
                    {
                        "model": model_config["model"],
                        "api_key": model_config["api_key"]
                    }
                ],
                "temperature": 0.3
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
        self.logger = logging.getLogger("discovery_agent")
    
    def get_db_connection(self):
        """Create a connection to the SQLite database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
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
                interest_level = "low"
                
                if notes_json:
                    try:
                        notes = json.loads(notes_json)
                        if "potential_vulnerabilities" in notes:
                            vuln_types = notes["potential_vulnerabilities"]
                        interest_level = notes.get("interest_level", "low")
                    except:
                        pass
                
                endpoints.append({
                    "url": url, 
                    "potential_vulnerabilities": vuln_types,
                    "interest_level": interest_level
                })
            
            conn.close()
            return endpoints
        
        except Exception as e:
            self.logger.error(f"Error loading endpoints: {e}")
            conn.close()
            return []
    
    # Core content discovery methods
    
    def discover_endpoints(self, target, options=None):
        """Main method to discover endpoints for a target."""
        self.logger.info(f"Starting content discovery for {target}")
        
        # Set default options if none provided
        if options is None:
            options = {
                "depth": 2,
                "threads": 10,
                "extensions": "php,html,js,txt,json,xml,config,bak,old,backup,sql,env",
                "timeout": 30,
                "skip_ai": False
            }
        
        # Get hosts to scan
        hosts = self.get_host_list(target)
        if not hosts:
            self.logger.error(f"No hosts found for target: {target}")
            return {"status": "error", "message": "No hosts found", "endpoints_found": 0}
        
        self.logger.info(f"Found {len(hosts)} hosts to scan")
        
        # Select wordlist
        wordlist = self.select_wordlist()
        
        # Record run start
        run_id = self.record_run_start(target, f"discover_endpoints for {target}")
        
        # Process each host
        total_endpoints = 0
        interesting_endpoints = 0
        all_endpoints = []
        
        for host in hosts:
            try:
                # Run content discovery tools
                host_results = self.process_single_host(
                    host, 
                    target, 
                    wordlist, 
                    options.get("extensions", "php,html,js,txt,json,xml,config,bak,old,backup,sql,env"), 
                    options.get("depth", 2), 
                    options.get("threads", 10), 
                    options.get("timeout", 30),
                    options.get("skip_ai", False)
                )
                
                if host_results and "endpoints" in host_results:
                    all_endpoints.extend(host_results["endpoints"])
                    total_endpoints += len(host_results["endpoints"])
                    interesting_endpoints += sum(1 for e in host_results["endpoints"] if e.get("interesting", False))
            except Exception as e:
                self.logger.error(f"Error processing host {host}: {e}")
        
        # Save all endpoints to database
        if all_endpoints:
            self.save_endpoints_to_db(all_endpoints, target)
        
        # Create summary
        summary = {
            "target": target,
            "hosts_scanned": len(hosts),
            "total_endpoints": total_endpoints,
            "interesting_endpoints": interesting_endpoints,
            "date": datetime.now().isoformat()
        }
        
        # Save summary
        summary_path = pathlib.Path("workspace") / target / "content_discovery" / "summary.json"
        summary_dir = summary_path.parent
        summary_dir.mkdir(parents=True, exist_ok=True)
        
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)
        
        # Record run end
        self.record_run_end(run_id, True, {"summary": summary})
        
        # Notify orchestrator
        self.notify_orchestrator(target, total_endpoints, interesting_endpoints)
        
        self.logger.info(f"Content discovery complete for {target}")
        self.logger.info(f"Found {total_endpoints} total endpoints, {interesting_endpoints} marked as interesting")
        
        return {
            "status": "success",
            "summary": summary,
            "endpoints_found": total_endpoints,
            "interesting_endpoints": interesting_endpoints,
            "endpoints": all_endpoints[:100]  # Limit to first 100 for message size
        }
    
    def get_host_list(self, target):
        """Get list of hosts for target from database or local files."""
        # Try to get hosts from database first
        conn = self.get_db_connection()
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
    
    def select_wordlist(self, custom_wordlist=None):
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
                self.logger.info(f"Using wordlist: {expanded_path}")
                return expanded_path
        
        # If no wordlist found, use a small built-in one
        self.logger.warning("No wordlist found. Using built-in mini wordlist.")
        mini_wordlist = pathlib.Path("mini_wordlist.txt")
        
        with open(mini_wordlist, "w") as f:
            f.write("""admin
login
api
backup
config
dashboard
dev
docs
download
images
js
media
static
test
uploads
users
wp-admin
.git
.env
robots.txt
sitemap.xml
""")
        
        return str(mini_wordlist)
    
    def process_single_host(self, host, target, wordlist, extensions, depth, threads, timeout, skip_ai):
        """Process a single host with all discovery methods."""
        # Create workspace directory
        workspace = pathlib.Path("workspace") / target / "content_discovery"
        workspace.mkdir(parents=True, exist_ok=True)
        
        # Clean host name for filenames
        host_clean = host.replace("https://", "").replace("http://", "").replace("/", "_")
        
        try:
            # Run ffuf for content discovery
            ffuf_output = workspace / f"{host_clean}_ffuf.json"
            ffuf_success = self.run_ffuf(host, wordlist, extensions, ffuf_output, threads, depth, timeout)
            
            # Run httpx for server info and tech detection
            httpx_output = workspace / f"{host_clean}_httpx.json"
            httpx_success = self.run_httpx(host, httpx_output)
            
            # Check common vulnerabilities
            vulns_output = workspace / f"{host_clean}_vulns.json"
            vulns_success = self.check_common_vulnerabilities(host, vulns_output)
            
            # Parse ffuf results
            all_endpoints = []
            if ffuf_success:
                ffuf_endpoints = self.parse_ffuf_results(ffuf_output)
                all_endpoints.extend(ffuf_endpoints)
            
            # Parse vulnerability check results
            if vulns_success and os.path.exists(vulns_output):
                try:
                    with open(vulns_output, 'r') as f:
                        vuln_endpoints = json.load(f)
                        all_endpoints.extend(vuln_endpoints)
                except Exception as e:
                    self.logger.error(f"Error parsing vulnerability results: {e}")
            
            # Classify endpoints using AI
            if not skip_ai and all_endpoints:
                all_endpoints = self.classify_endpoints(all_endpoints, target)
            
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
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error processing host {host}: {e}")
            return {"host": host, "total_endpoints": 0, "interesting_endpoints": 0, "endpoints": [], "error": str(e)}
    
    def run_ffuf(self, host, wordlist, extensions, output_file, threads=10, depth=2, timeout=30):
        """Run ffuf on a host."""
        # Create output directory
        output_dir = output_file.parent
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
        
        self.logger.info(f"Running: {ffuf_cmd}")
        
        try:
            # Run ffuf
            subprocess.run(ffuf_cmd, shell=True, check=True)
            self.logger.info(f"Completed ffuf scan on {host}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error running ffuf on {host}: {e}")
            return False
    
    def run_httpx(self, host, output_file):
        """Run httpx on a host for header analysis."""
        # Create output directory
        output_dir = output_file.parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Build httpx command - note the URL is passed directly without -u flag
        httpx_cmd = (
            f"httpx {host} -silent -tech-detect -title -status-code "
            f"-follow-redirects -no-color -json -o {output_file}"
        )
        
        self.logger.info(f"Running: {httpx_cmd}")
        
        try:
            # Run httpx
            subprocess.run(httpx_cmd, shell=True, check=True)
            self.logger.info(f"Completed httpx scan on {host}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error running httpx on {host}: {e}")
            return False
    
    def check_common_vulnerabilities(self, host, output_file):
        """Check for common vulnerabilities and misconfigurations."""
        # Create output directory
        output_dir = output_file.parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
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
                response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
                if response.status_code in (200, 403, 401):
                    results.append({
                        "url": url,
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "content_type": response.headers.get("Content-Type", ""),
                        "interesting": True
                    })
                    self.logger.info(f"Found interesting endpoint: {url} [{response.status_code}]")
            except Exception as e:
                self.logger.debug(f"Error checking {url}: {e}")
        
        # Save results
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Completed vulnerability checks on {host}, found {len(results)} potentially interesting endpoints")
        return True
    
    def parse_ffuf_results(self, result_file):
        """Parse ffuf JSON results."""
        if not os.path.exists(result_file):
            self.logger.warning(f"Result file not found: {result_file}")
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
                
                # Enhanced check for "interestingness" - MORE AGGRESSIVE MARKING
                interesting = True  # Default to True to ensure we have endpoints to test
                
                # Add detailed reason for being interesting
                interesting_reason = "Default interesting marking"
                
                # Check for specific interesting patterns
                if any(ext in url.lower() for ext in [".php", ".js", ".xml", ".json", ".sql", ".bak", ".config", ".env"]):
                    interesting_reason = f"Special file extension found in URL: {url}"
                elif status in (401, 403):
                    interesting_reason = f"Protected resource (status {status}): {url}"
                elif any(word in url.lower() for word in ["admin", "config", "backup", "api", "test", "dev", "upload", "user"]):
                    interesting_reason = f"Sensitive path component found: {url}"
                
                self.logger.info(f"Adding endpoint {url} (Interesting: {interesting}, Reason: {interesting_reason})")
                
                endpoints.append({
                    "url": url,
                    "status_code": status,
                    "content_length": content_length,
                    "content_type": content_type,
                    "words": words,
                    "interesting": interesting,
                    "interesting_reason": interesting_reason,
                    "interest_level": "medium"  # Default to medium to ensure testing
                })
            
            self.logger.info(f"Parsed {len(endpoints)} endpoints from ffuf results")
            return endpoints
        except Exception as e:
            self.logger.error(f"Error parsing ffuf results: {e}")
            return []
    
    # AI-powered endpoint classification
    
    def classify_endpoints(self, endpoints, target):
        """Use AI to classify which endpoints are most interesting for bug bounty."""
        if not endpoints or len(endpoints) == 0:
            return endpoints
        
        # Limit to max 50 endpoints per batch for GPT context
        batches = [endpoints[i:i+50] for i in range(0, len(endpoints), 50)]
        all_classified = []
        
        for batch in batches:
            try:
                # Use OpenAI API directly instead of trying to access it through Autogen
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
                    temperature=0.3
                )
                
                result = json.loads(response.choices[0].message.content)
                
                # Extract the classified endpoints
                classified_endpoints = result.get("endpoints", result.get("classified_endpoints", []))
                
                # If GPT's response doesn't match expected format, handle it
                if not classified_endpoints and "results" in result:
                    classified_endpoints = result.get("results", [])
                
                # If still can't find endpoints in the response, just add interest_level to original batch
                if not classified_endpoints:
                    self.logger.warning("AI classification returned unexpected format, using fallback")
                    classified_endpoints = batch
                    for endpoint in classified_endpoints:
                        # Add default classifications
                        endpoint["interest_level"] = "medium" if endpoint.get("interesting", False) else "low"
                        endpoint["potential_vulnerabilities"] = []
                        endpoint["testing_notes"] = ""
                
                all_classified.extend(classified_endpoints)
                
            except Exception as e:
                self.logger.error(f"Error in AI classification: {e}")
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
    
    # Database methods
    
    def save_endpoints_to_db(self, endpoints, target):
        """Save discovered endpoints to database."""
        # First check if endpoints table exists
        conn = self.get_db_connection()
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
                self.logger.info("Created endpoints table in database")
        except Exception as e:
            self.logger.error(f"Error checking/creating endpoints table: {e}")
            conn.close()
            return 0
        
        # Insert endpoints
        count = 0
        updated = 0
        for endpoint in endpoints:
            try:
                # First check if endpoint already exists
                c.execute("SELECT id, interesting FROM endpoints WHERE target=? AND url=?", 
                         (target, endpoint["url"]))
                existing = c.fetchone()
                
                # Always ensure interesting is set appropriately (default to True for testing)
                is_interesting = 1 if endpoint.get("interesting", True) else 0
                
                # Add debug logging
                self.logger.debug(f"Processing endpoint: {endpoint['url']}, interesting: {is_interesting}")
                
                # Prepare notes JSON
                notes_data = {
                    "interest_level": endpoint.get("interest_level", "medium"),
                    "potential_vulnerabilities": endpoint.get("potential_vulnerabilities", []),
                    "testing_notes": endpoint.get("testing_notes", ""),
                    "content_length": endpoint.get("content_length", 0),
                    "words": endpoint.get("words", 0),
                    "interesting_reason": endpoint.get("interesting_reason", "No specific reason")
                }
                
                if existing:
                    # Only update if the existing endpoint is not already marked as interesting
                    # or if we have more information now
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
                        updated += 1
                        self.logger.debug(f"Updated endpoint in database: {endpoint['url']}")
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
                    count += 1
                    self.logger.debug(f"Inserted new endpoint in database: {endpoint['url']}")
            except Exception as e:
                self.logger.error(f"Error saving endpoint {endpoint.get('url', 'unknown')}: {e}")
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Saved {count} new endpoints and updated {updated} existing endpoints in database")
        return count
    
    def record_run_start(self, target, command):
        """Record the start of a discovery run in the database."""
        conn = self.get_db_connection()
        c = conn.cursor()
        run_id = None
        
        try:
            c.execute("""
                INSERT INTO agent_runs (target, module, command, status, start_time)
                VALUES (?, ?, ?, ?, ?)
            """, (
                target,
                "content_discovery",
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
        """Record the end of a discovery run in the database."""
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
            
            if action == "discover_endpoints":
                # Extract parameters
                target = message["metadata"]["parameters"].get("target")
                options = message["metadata"]["parameters"].get("options", {})
                
                # Execute endpoint discovery
                result = self.discover_endpoints(target, options)
                
                # Return a response
                return create_response_message(
                    "DiscoveryAgent",
                    message["metadata"]["from"],
                    action,
                    result
                )
            
            elif action == "classify_endpoints":
                # Extract parameters
                target = message["metadata"]["parameters"].get("target")
                endpoints = message["metadata"]["parameters"].get("endpoints", [])
                
                # Classify endpoints
                classified = self.classify_endpoints(endpoints, target)
                
                # Return a response
                return create_response_message(
                    "DiscoveryAgent",
                    message["metadata"]["from"],
                    action,
                    {"classified_endpoints": classified}
                )
                
            else:
                # Unknown action
                return create_error_message(
                    "DiscoveryAgent",
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
        
        if to_agent == "OrchestratorAgent":
            orchestrator = OrchestratorAgent()
            return orchestrator.handle_agent_message(message)
        
        # If we can't handle the message locally, log a warning
        self.logger.warning(f"Could not send message to {to_agent}: agent not available locally")
        return None
    
    def notify_orchestrator(self, target, endpoints_found, interesting_endpoints):
        """Notify the orchestrator of discovery results."""
        message = create_result_message(
            "DiscoveryAgent",
            "discover_endpoints",
            {
                "target": target,
                "endpoints_found": endpoints_found,
                "interesting_endpoints": interesting_endpoints,
                "timestamp": datetime.now().isoformat()
            }
        )
        
        return self.send_message_to_agent("OrchestratorAgent", message)