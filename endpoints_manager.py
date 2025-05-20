#!/usr/bin/env python3
# endpoints_manager.py - Creates and manages endpoints database for bugbounty agent

import sqlite3
import pathlib
import sys
import os
import logging
import re
import argparse
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bugbounty.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("endpoints_manager")

# Database configuration
DB_PATH = "bugbounty.db"

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Manage endpoints for bug bounty targets")
    parser.add_argument("target", help="Target domain to process")
    parser.add_argument("--import", dest="import_file", help="Import endpoints from file")
    parser.add_argument("--mark-interesting", help="Mark endpoints as interesting based on pattern")
    parser.add_argument("--list", action="store_true", help="List endpoints for target")
    parser.add_argument("--only-interesting", action="store_true", help="List only interesting endpoints")
    parser.add_argument("--export", help="Export endpoints to file")
    return parser.parse_args()

def setup_endpoints_table():
    """Set up endpoints table in database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute("""
    CREATE TABLE IF NOT EXISTS endpoints (
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
    
    conn.commit()
    conn.close()
    logger.info("Endpoints table set up successfully")

def import_endpoints_from_file(target, filepath):
    """Import endpoints from a file."""
    if not os.path.exists(filepath):
        logger.error(f"File not found: {filepath}")
        return 0
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    with open(filepath, 'r') as f:
        endpoints = [line.strip() for line in f if line.strip()]
    
    count = 0
    for endpoint in endpoints:
        # Try to extract status code from formats like "http://example.com [200]"
        status_match = re.search(r'\[(\d+)\]$', endpoint)
        if status_match:
            status_code = int(status_match.group(1))
            url = endpoint.split(' [')[0]
        else:
            status_code = None
            url = endpoint
        
        # Simple content type detection based on extension
        content_type = None
        if '.' in url.split('/')[-1]:
            ext = url.split('/')[-1].split('.')[-1].lower()
            if ext in ['html', 'htm']:
                content_type = 'text/html'
            elif ext in ['js']:
                content_type = 'application/javascript'
            elif ext in ['css']:
                content_type = 'text/css'
            elif ext in ['json']:
                content_type = 'application/json'
            elif ext in ['xml']:
                content_type = 'application/xml'
            elif ext in ['pdf']:
                content_type = 'application/pdf'
            elif ext in ['jpg', 'jpeg', 'png', 'gif']:
                content_type = f'image/{ext}'
        
        try:
            c.execute("""
                INSERT INTO endpoints (target, url, status_code, content_type, date_discovered)
                VALUES (?, ?, ?, ?, ?)
            """, (
                target,
                url,
                status_code,
                content_type,
                datetime.now().isoformat()
            ))
            count += 1
        except sqlite3.IntegrityError:
            # Handle potential duplicates
            pass
    
    conn.commit()
    conn.close()
    
    logger.info(f"Imported {count} endpoints for {target}")
    return count

def mark_interesting_endpoints(target, pattern):
    """Mark endpoints as interesting based on pattern."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    pattern_sql = f"%{pattern}%"
    c.execute("""
        UPDATE endpoints
        SET interesting = 1
        WHERE target = ? AND url LIKE ?
    """, (target, pattern_sql))
    
    count = c.rowcount
    conn.commit()
    conn.close()
    
    logger.info(f"Marked {count} endpoints as interesting for pattern '{pattern}'")
    return count

def list_endpoints(target, only_interesting=False):
    """List endpoints for a target."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    if only_interesting:
        c.execute("""
            SELECT url, status_code, interesting, date_discovered
            FROM endpoints
            WHERE target = ? AND interesting = 1
            ORDER BY date_discovered DESC
        """, (target,))
    else:
        c.execute("""
            SELECT url, status_code, interesting, date_discovered
            FROM endpoints
            WHERE target = ?
            ORDER BY date_discovered DESC
        """, (target,))
    
    endpoints = c.fetchall()
    conn.close()
    
    print(f"\nEndpoints for {target} ({'Interesting Only' if only_interesting else 'All'}):")
    print("-" * 100)
    for endpoint in endpoints:
        url, status, interesting, date = endpoint
        status_str = f"[{status}]" if status else ""
        interesting_str = "⭐" if interesting else ""
        print(f"{url} {status_str} {interesting_str}")
    print("-" * 100)
    print(f"Total: {len(endpoints)} endpoints")
    
    return endpoints

def export_endpoints(target, filepath, only_interesting=False):
    """Export endpoints to a file."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    if only_interesting:
        c.execute("""
            SELECT url, status_code
            FROM endpoints
            WHERE target = ? AND interesting = 1
            ORDER BY date_discovered DESC
        """, (target,))
    else:
        c.execute("""
            SELECT url, status_code
            FROM endpoints
            WHERE target = ?
            ORDER BY date_discovered DESC
        """, (target,))
    
    endpoints = c.fetchall()
    conn.close()
    
    with open(filepath, 'w') as f:
        for endpoint in endpoints:
            url, status = endpoint
            if status:
                f.write(f"{url} [{status}]\n")
            else:
                f.write(f"{url}\n")
    
    logger.info(f"Exported {len(endpoints)} endpoints to {filepath}")
    return len(endpoints)

def auto_mark_interesting_endpoints(target):
    """Automatically mark potentially interesting endpoints based on common patterns."""
    interesting_patterns = [
        "admin", "login", "auth", "dashboard", "api", "upload", "config", 
        "setting", "backup", "dev", "test", "beta", "staging", "proxy",
        "redirect", "return", "file", "download", "token", "debug", "cmd",
        "exec", "sql", "db", "database", "password", "user", "account",
        "profile", "private", "secret", "internal", ".git", ".env", ".svn",
        "graphql", "console", "admin-console", "phpinfo", "server-status",
        "server-info", ".php", ".jsp", ".asp", "oauth", "jwt", "xml", "json"
    ]
    
    total_marked = 0
    for pattern in interesting_patterns:
        count = mark_interesting_endpoints(target, pattern)
        total_marked += count
    
    return total_marked

def main():
    args = parse_arguments()
    
    # Set up database
    setup_endpoints_table()
    
    # Process commands
    if args.import_file:
        import_endpoints_from_file(args.target, args.import_file)
    
    if args.mark_interesting:
        mark_interesting_endpoints(args.target, args.mark_interesting)
    
    if args.list or (not args.import_file and not args.mark_interesting and not args.export):
        list_endpoints(args.target, args.only_interesting)
    
    if args.export:
        export_endpoints(args.target, args.export, args.only_interesting)
    
    # If no specific action was requested, run an auto-mark pass
    if not args.import_file and not args.mark_interesting and not args.list and not args.export:
        count = auto_mark_interesting_endpoints(args.target)
        logger.info(f"Auto-marked {count} interesting endpoints for {args.target}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
