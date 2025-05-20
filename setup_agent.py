#!/usr/bin/env python3
# setup_agent.py - Initialize the AI bug bounty agent system

import os
import sys
import sqlite3
import subprocess
import argparse
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("setup.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("setup_agent")

# Database configuration
DB_PATH = "bugbounty.db"

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Set up the AI bug bounty agent system")
    parser.add_argument("--full", action="store_true", help="Perform a full setup including dependencies")
    parser.add_argument("--db-only", action="store_true", help="Set up database only")
    parser.add_argument("--dir-only", action="store_true", help="Set up directory structure only")
    parser.add_argument("--openai-key", help="OpenAI API key to set")
    parser.add_argument("--reset", action="store_true", help="Reset existing database")
    return parser.parse_args()

def check_python_dependencies():
    """Check and install required Python dependencies."""
    logger.info("Checking Python dependencies...")
    requirements = [
        "openai>=1.0.0",
        "flask>=2.0.0",
        "sqlalchemy",
        "tqdm",
        "requests",
        "python-dotenv"
    ]
    
    try:
        # Check if pip is installed
        subprocess.run([sys.executable, "-m", "pip", "--version"], 
                      check=True, 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE)
        
        # Install requirements
        cmd = [sys.executable, "-m", "pip", "install"] + requirements
        subprocess.run(cmd, check=True)
        logger.info("Python dependencies installed successfully.")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install Python dependencies: {e}")
        return False

def check_external_tools():
    """Check if required external tools are installed."""
    tools = {
        "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "amass": "sudo apt install amass -y",
        "ffuf": "sudo apt install ffuf -y",
        "dnsx": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "assetfinder": "go install github.com/tomnomnom/assetfinder@latest"
    }
    
    missing_tools = []
    for tool, install_cmd in tools.items():
        try:
            subprocess.run(["which", tool], 
                          check=True, 
                          stdout=subprocess.PIPE, 
                          stderr=subprocess.PIPE)
            logger.info(f"✓ {tool} is installed")
        except subprocess.CalledProcessError:
            missing_tools.append((tool, install_cmd))
            logger.warning(f"✗ {tool} is not installed")
    
    if missing_tools:
        logger.warning("The following tools are missing:")
        for tool, cmd in missing_tools:
            logger.warning(f"  - {tool} (install with: {cmd})")
        
        logger.info("Attempting to install Go tools...")
        for tool, cmd in missing_tools:
            if "go install" in cmd:
                try:
                    subprocess.run(cmd, shell=True, check=True)
                    logger.info(f"Successfully installed {tool}")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to install {tool}: {e}")
        
        logger.info("For apt packages, please run the following commands manually:")
        for tool, cmd in missing_tools:
            if "apt install" in cmd:
                logger.info(f"  {cmd}")
    
    return len(missing_tools) == 0

def setup_database(reset=False):
    """Set up the SQLite database."""
    logger.info("Setting up database...")
    
    if reset and os.path.exists(DB_PATH):
        logger.warning(f"Resetting existing database: {DB_PATH}")
        os.remove(DB_PATH)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Create findings table
    c.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        host TEXT,
        vulnerability TEXT,
        severity TEXT,
        confidence REAL,
        date TEXT,
        status TEXT,
        time_spent REAL,
        payout REAL,
        hourly_rate REAL
    )
    """)
    
    # Create endpoints table
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
    
    # Create chains table
    c.execute("""
    CREATE TABLE IF NOT EXISTS chains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        host TEXT,
        name TEXT,
        description TEXT,
        finding_ids TEXT,
        original_severities TEXT,
        combined_severity TEXT,
        technical_details TEXT,
        business_impact TEXT,
        evidence_requirements TEXT,
        date_identified TEXT
    )
    """)
    
    # Create agent_plans table
    c.execute("""
    CREATE TABLE IF NOT EXISTS agent_plans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        plan TEXT,
        status TEXT,
        created_at TEXT,
        updated_at TEXT
    )
    """)
    
    # Create agent_runs table
    c.execute("""
    CREATE TABLE IF NOT EXISTS agent_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        module TEXT,
        command TEXT,
        status TEXT,
        start_time TEXT,
        end_time TEXT,
        outcome TEXT
    )
    """)
    
    # Create agent_learnings table
    c.execute("""
    CREATE TABLE IF NOT EXISTS agent_learnings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        module TEXT,
        success BOOLEAN,
        insight TEXT,
        date_added TEXT
    )
    """)
    
    conn.commit()
    conn.close()
    
    logger.info("Database setup complete.")
    return True

def setup_directory_structure():
    """Set up the directory structure for the agent."""
    logger.info("Setting up directory structure...")
    
    # Create workspace directory
    workspace = Path("workspace")
    workspace.mkdir(exist_ok=True)
    
    # Create dashboard directory
    dashboard = Path("dashboard")
    dashboard.mkdir(exist_ok=True)
    
    logger.info("Directory structure setup complete.")
    return True

def set_openai_key(api_key):
    """Set the OpenAI API key in environment variable."""
    if not api_key:
        logger.warning("No OpenAI API key provided.")
        return False
    
    logger.info("Setting OpenAI API key...")
    
    # Set environment variable for current session
    os.environ["OPENAI_API_KEY"] = api_key
    
    # Add to .env file
    with open(".env", "w") as f:
        f.write(f"OPENAI_API_KEY={api_key}\n")
    
    # Check if using bash or zsh
    shell_rc = None
    if os.path.exists(os.path.expanduser("~/.zshrc")):
        shell_rc = os.path.expanduser("~/.zshrc")
    elif os.path.exists(os.path.expanduser("~/.bashrc")):
        shell_rc = os.path.expanduser("~/.bashrc")
    
    if shell_rc:
        # Check if already in shell config
        with open(shell_rc, "r") as f:
            content = f.read()
            if f"OPENAI_API_KEY={api_key}" not in content:
                logger.info(f"Adding OPENAI_API_KEY to {shell_rc}")
                with open(shell_rc, "a") as f:
                    f.write(f'\nexport OPENAI_API_KEY="{api_key}"\n')
    
    logger.info("OpenAI API key set successfully.")
    return True

def print_setup_complete():
    """Print setup complete message."""
    logger.info("\n" + "=" * 60)
    logger.info("🚀 AI Bug Bounty Agent Setup Complete!")
    logger.info("=" * 60)
    logger.info("\nYour agent system is ready to use. Here are some common commands:")
    logger.info("\n1. Run the agent in autonomous mode on a target:")
    logger.info("   python bugbounty_agent.py --target example.com --auto")
    logger.info("\n2. Create a plan for a target:")
    logger.info("   python bugbounty_agent.py --target example.com --mode plan")
    logger.info("\n3. Execute the plan:")
    logger.info("   python bugbounty_agent.py --target example.com --mode execute")
    logger.info("\n4. Analyze findings:")
    logger.info("   python bugbounty_agent.py --target example.com --mode analyze")
    logger.info("\n5. Start the dashboard:")
    logger.info("   python agent_dashboard.py")
    logger.info("\n6. Manage endpoints:")
    logger.info("   python endpoints_manager.py example.com --import live_hosts.txt")
    logger.info("\nHappy Hunting! 🔍")
    logger.info("=" * 60)

def main():
    """Main setup function."""
    args = parse_arguments()
    success = True
    
    print("\n" + "=" * 60)
    print("🛠️  AI Bug Bounty Agent System Setup")
    print("=" * 60 + "\n")
    
    if args.full or not (args.db_only or args.dir_only):
        # Check Python dependencies
        success = check_python_dependencies() and success
        
        # Check external tools
        tool_status = check_external_tools()
        success = success and tool_status
        
        # Set OpenAI key if provided
        if args.openai_key:
            key_status = set_openai_key(args.openai_key)
            success = success and key_status
    
    if args.full or args.db_only or not (args.dir_only):
        # Set up database
        db_status = setup_database(args.reset)
        success = success and db_status
    
    if args.full or args.dir_only or not (args.db_only):
        # Set up directory structure
        dir_status = setup_directory_structure()
        success = success and dir_status
    
    if success:
        print_setup_complete()
        return 0
    else:
        logger.error("Setup completed with errors. Please check the logs.")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("\nSetup cancelled by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error during setup: {e}")
        sys.exit(1)
