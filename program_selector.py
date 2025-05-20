#!/usr/bin/env python3
# program_selector.py - AI-powered bug bounty program selection

import os
import sys
import argparse
import logging
import json
import sqlite3
import pathlib
import requests
import csv
import time
from datetime import datetime, timedelta
import openai
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bugbounty.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("program_selector")

# Database configuration
DB_PATH = "bugbounty.db"

# OpenAI client
client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="AI-powered bug bounty program selection")
    parser.add_argument("--update", action="store_true", help="Update program data from sources")
    parser.add_argument("--recommend", type=int, default=5, help="Recommend top N programs (default: 5)")
    parser.add_argument("--platform", choices=["all", "hackerone", "bugcrowd", "intigriti", "yeswehack"], 
                      default="all", help="Filter by platform")
    parser.add_argument("--min-payout", type=float, help="Minimum average payout")
    parser.add_argument("--output", help="Output file for recommendations (CSV)")
    parser.add_argument("--profile", choices=["high_reward", "quick_wins", "learning", "custom"], 
                      default="high_reward", help="Profile for recommendations")
    parser.add_argument("--skills", help="Comma-separated list of your skills/focuses")
    parser.add_argument("--filter", help="Filter programs by keyword")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    return parser.parse_args()

def setup_database():
    """Set up the database tables for program data."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Create programs table if it doesn't exist
    c.execute("""
    CREATE TABLE IF NOT EXISTS programs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        platform TEXT,
        name TEXT,
        url TEXT,
        scope TEXT,
        avg_payout REAL,
        response_time REAL,
        last_updated TEXT,
        vdp_only BOOLEAN,
        data JSON
    )
    """)
    
    # Create program_history table if it doesn't exist
    c.execute("""
    CREATE TABLE IF NOT EXISTS program_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_id INTEGER,
        date TEXT,
        note TEXT,
        data JSON,
        FOREIGN KEY(program_id) REFERENCES programs(id)
    )
    """)
    
    # Create program_recommendations table if it doesn't exist
    c.execute("""
    CREATE TABLE IF NOT EXISTS program_recommendations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT,
        profile TEXT,
        programs TEXT,
        reasoning TEXT
    )
    """)
    
    conn.commit()
    conn.close()

def fetch_hackerone_programs():
    """Fetch program data from HackerOne."""
    logger.info("Fetching HackerOne programs...")
    
    try:
        url = "https://hackerone.com/programs/search"
        headers = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        params = {
            "query": "type:hackerone",
            "sort": "published_at:descending",
            "page": 1,
            "per_page": 100
        }
        
        all_programs = []
        page = 1
        
        while True:
            params["page"] = page
            response = requests.get(url, headers=headers, params=params)
            
            if response.status_code != 200:
                logger.error(f"Error fetching HackerOne programs: {response.status_code}")
                break
            
            data = response.json()
            programs = data.get("results", [])
            
            if not programs:
                break
            
            all_programs.extend(programs)
            logger.info(f"Fetched {len(all_programs)} HackerOne programs so far")
            
            # Check if there are more pages
            if len(programs) < params["per_page"]:
                break
            
            page += 1
            # Rate limiting
            time.sleep(2)
        
        # Process and normalize the data
        processed_programs = []
        for program in all_programs:
            # Calculate average payout if available
            avg_payout = 0
            if "structured_scopes" in program:
                bounty_scopes = [s for s in program.get("structured_scopes", []) if s.get("eligible_for_bounty")]
                if bounty_scopes:
                    # Extract bounty amounts when available
                    bounty_amounts = []
                    for scope in bounty_scopes:
                        if "bounties" in scope and scope["bounties"]:
                            min_bounty = scope["bounties"].get("min")
                            max_bounty = scope["bounties"].get("max")
                            if min_bounty and max_bounty:
                                bounty_amounts.append((min_bounty + max_bounty) / 2)
                    
                    if bounty_amounts:
                        avg_payout = sum(bounty_amounts) / len(bounty_amounts)
            
            # Determine if VDP only
            vdp_only = True
            if "offers_bounties" in program and program["offers_bounties"]:
                vdp_only = False
            
            # Get response time in days
            response_time = 0
            if "average_time_to_first_response" in program:
                response_time = program.get("average_time_to_first_response", 0) / (24 * 60 * 60)  # Convert seconds to days
            
            processed_programs.append({
                "platform": "hackerone",
                "name": program.get("name", "Unknown"),
                "url": f"https://hackerone.com/{program.get('handle', '')}",
                "scope": json.dumps([s.get("asset_identifier", "") for s in program.get("structured_scopes", []) if s.get("eligible_for_submission")]),
                "avg_payout": avg_payout,
                "response_time": response_time,
                "vdp_only": vdp_only,
                "data": json.dumps(program)
            })
        
        logger.info(f"Processed {len(processed_programs)} HackerOne programs")
        return processed_programs
    
    except Exception as e:
        logger.error(f"Error fetching HackerOne programs: {e}")
        return []

def fetch_bugcrowd_programs():
    """Fetch program data from Bugcrowd."""
    logger.info("Fetching Bugcrowd programs...")
    
    try:
        url = "https://bugcrowd.com/programs.json"
        headers = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            logger.error(f"Error fetching Bugcrowd programs: {response.status_code}")
            return []
        
        data = response.json()
        programs = data.get("programs", [])
        
        # Process and normalize the data
        processed_programs = []
        for program in programs:
            # Calculate average payout if available
            avg_payout = 0
            if "reward_range" in program:
                reward_range = program.get("reward_range", "")
                if reward_range:
                    # Parse reward range like "$100-$1000"
                    try:
                        parts = reward_range.replace("$", "").replace(",", "").split("-")
                        if len(parts) == 2:
                            min_bounty = float(parts[0])
                            max_bounty = float(parts[1])
                            avg_payout = (min_bounty + max_bounty) / 2
                    except:
                        pass
            
            # Determine if VDP only
            vdp_only = True
            if program.get("pays_rewards", False):
                vdp_only = False
            
            # Get response time (estimated, as Bugcrowd doesn't provide this directly)
            response_time = 7  # Default to 7 days
            
            processed_programs.append({
                "platform": "bugcrowd",
                "name": program.get("name", "Unknown"),
                "url": f"https://bugcrowd.com{program.get('program_url', '')}",
                "scope": json.dumps(program.get("targets", [])),
                "avg_payout": avg_payout,
                "response_time": response_time,
                "vdp_only": vdp_only,
                "data": json.dumps(program)
            })
        
        logger.info(f"Processed {len(processed_programs)} Bugcrowd programs")
        return processed_programs
    
    except Exception as e:
        logger.error(f"Error fetching Bugcrowd programs: {e}")
        return []

def save_programs_to_db(programs):
    """Save or update program data in the database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    added = 0
    updated = 0
    
    for program in programs:
        # Check if program already exists
        c.execute("SELECT id FROM programs WHERE platform=? AND name=?", 
                 (program["platform"], program["name"]))
        result = c.fetchone()
        
        if result:
            # Update existing program
            program_id = result[0]
            
            # First, create a history record
            c.execute("SELECT data FROM programs WHERE id=?", (program_id,))
            old_data = c.fetchone()[0]
            
            c.execute("""
                INSERT INTO program_history (program_id, date, note, data)
                VALUES (?, ?, ?, ?)
            """, (
                program_id,
                datetime.now().isoformat(),
                "Automatic update",
                old_data
            ))
            
            # Then update the program
            c.execute("""
                UPDATE programs
                SET url=?, scope=?, avg_payout=?, response_time=?, 
                    last_updated=?, vdp_only=?, data=?
                WHERE id=?
            """, (
                program["url"],
                program["scope"],
                program["avg_payout"],
                program["response_time"],
                datetime.now().isoformat(),
                program["vdp_only"],
                program["data"],
                program_id
            ))
            
            updated += 1
            
        else:
            # Insert new program
            c.execute("""
                INSERT INTO programs (platform, name, url, scope, avg_payout, 
                                    response_time, last_updated, vdp_only, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                program["platform"],
                program["name"],
                program["url"],
                program["scope"],
                program["avg_payout"],
                program["response_time"],
                datetime.now().isoformat(),
                program["vdp_only"],
                program["data"]
            ))
            
            added += 1
    
    conn.commit()
    conn.close()
    
    logger.info(f"Added {added} new programs, updated {updated} existing programs")

def update_program_data():
    """Update all program data from various sources."""
    # Set up database if needed
    setup_database()
    
    # Fetch and save HackerOne programs
    h1_programs = fetch_hackerone_programs()
    if h1_programs:
        save_programs_to_db(h1_programs)
    
    # Fetch and save Bugcrowd programs
    bc_programs = fetch_bugcrowd_programs()
    if bc_programs:
        save_programs_to_db(bc_programs)
    
    # TODO: Add more platforms (Intigriti, YesWeHack) as needed
    
    logger.info("Program data update complete")

def get_programs_from_db(platform="all", min_payout=None, filter_keyword=None):
    """Get programs from database with optional filtering."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    query = "SELECT id, platform, name, url, scope, avg_payout, response_time, last_updated, vdp_only, data FROM programs"
    params = []
    
    where_clauses = []
    
    if platform != "all":
        where_clauses.append("platform = ?")
        params.append(platform)
    
    if min_payout is not None:
        where_clauses.append("avg_payout >= ?")
        params.append(min_payout)
    
    if filter_keyword:
        where_clauses.append("(name LIKE ? OR data LIKE ?)")
        keyword_param = f"%{filter_keyword}%"
        params.extend([keyword_param, keyword_param])
    
    if where_clauses:
        query += " WHERE " + " AND ".join(where_clauses)
    
    c.execute(query, params)
    rows = c.fetchall()
    
    programs = []
    for row in rows:
        program = {
            "id": row[0],
            "platform": row[1],
            "name": row[2],
            "url": row[3],
            "scope": json.loads(row[4]) if row[4] else [],
            "avg_payout": row[5],
            "response_time": row[6],
            "last_updated": row[7],
            "vdp_only": bool(row[8]),
            "data": json.loads(row[9]) if row[9] else {}
        }
        programs.append(program)
    
    conn.close()
    return programs

def ai_recommend_programs(programs, profile, skills=None, top_n=5):
    """Use GPT-4o to recommend programs based on profile and skills."""
    if not programs:
        logger.warning("No programs to analyze")
        return []
    
    # Prepare profile description
    profile_descriptions = {
        "high_reward": "Focus on programs with high payouts and reasonable response times. Prioritize quality over quantity.",
        "quick_wins": "Focus on programs with fast response times and lower competition. Good for steady, frequent rewards.",
        "learning": "Focus on programs that are beginner-friendly with clear scope and documentation. Good for building experience."
    }
    
    profile_desc = profile_descriptions.get(profile, "Custom profile based on specified skills and preferences.")
    
    # Limit to max 100 programs to fit in context
    if len(programs) > 100:
        # Pre-filter: for high_reward prioritize high payouts, for quick_wins prioritize fast response
        if profile == "high_reward":
            programs.sort(key=lambda x: x.get("avg_payout", 0), reverse=True)
        elif profile == "quick_wins":
            programs.sort(key=lambda x: x.get("response_time", 999))
        programs = programs[:100]
    
    # Format skills for the prompt
    skills_text = ""
    if skills:
        skills_text = f"The researcher has the following skills and focus areas: {skills}."
    
    # Prepare program data for the prompt
    program_data = []
    for p in programs:
        # Extract key information for each program
        scope_summary = "Unknown scope"
        if isinstance(p["scope"], list) and p["scope"]:
            scope_types = []
            for item in p["scope"]:
                if isinstance(item, str):
                    if "api" in item.lower():
                        scope_types.append("API")
                    elif "android" in item.lower():
                        scope_types.append("Android")
                    elif "ios" in item.lower():
                        scope_types.append("iOS")
                    elif any(web in item.lower() for web in ["web", "http", ".com", ".org", ".net"]):
                        scope_types.append("Web")
                    elif any(network in item.lower() for network in ["network", "ip", "vpn", "ssh"]):
                        scope_types.append("Network")
            if scope_types:
                scope_summary = ", ".join(set(scope_types))
        
        # Get VDP or bounty status
        program_type = "VDP (no bounties)" if p["vdp_only"] else f"Bounty (avg ~${p['avg_payout']:.2f})"
        
        # Add to program data
        program_data.append({
            "id": p["id"],
            "name": p["name"],
            "platform": p["platform"],
            "url": p["url"],
            "program_type": program_type,
            "avg_payout": p["avg_payout"],
            "response_time": f"{p['response_time']:.1f} days",
            "scope_summary": scope_summary
        })
    
    try:
        # Ask GPT-4o for recommendations
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": f"""You are an expert bug bounty advisor that helps researchers find the most suitable programs.
                
                Profile: {profile} - {profile_desc}
                {skills_text}
                
                Analyze the provided bug bounty programs and recommend the top {top_n} most suitable programs for this profile.
                For each recommended program, explain why it's a good fit based on:
                1. Alignment with the researcher's profile and skills
                2. Expected reward potential
                3. Program reputation and response time
                4. Scope and opportunity assessment
                
                Return your recommendations in JSON format with:
                - An intro overview of your recommendation strategy
                - The top {top_n} recommended programs with explanations
                - A brief conclusion with additional advice
                """},
                {"role": "user", "content": f"""Here are {len(program_data)} bug bounty programs to analyze:
                
                {json.dumps(program_data, indent=2)}
                
                Based on my {profile} profile{' and these skills: ' + skills if skills else ''}, which {top_n} programs would you recommend?
                """}
            ],
            response_format={"type": "json_object"},
            temperature=0.7
        )
        
        recommendations = json.loads(response.choices[0].message.content)
        
        # Save recommendation to database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        c.execute("""
            INSERT INTO program_recommendations (date, profile, programs, reasoning)
            VALUES (?, ?, ?, ?)
        """, (
            datetime.now().isoformat(),
            profile,
            json.dumps(recommendations.get("recommended_programs", [])),
            json.dumps({
                "overview": recommendations.get("overview", ""),
                "conclusion": recommendations.get("conclusion", ""),
                "profile": profile,
                "skills": skills
            })
        ))
        
        conn.commit()
        conn.close()
        
        return recommendations
        
    except Exception as e:
        logger.error(f"Error getting AI recommendations: {e}")
        return {"overview": "Error generating recommendations", "recommended_programs": [], "conclusion": ""}

def format_recommendations(recommendations, programs_dict):
    """Format recommendations for display."""
    if not recommendations:
        return "No recommendations available."
    
    overview = recommendations.get("overview", recommendations.get("intro", ""))
    recommended_programs = recommendations.get("recommended_programs", [])
    
    # If recommended_programs is empty, check for other possible keys
    if not recommended_programs and isinstance(recommendations, dict):
        for key in recommendations:
            if isinstance(recommendations[key], list) and len(recommendations[key]) > 0:
                recommended_programs = recommendations[key]
                break
    
    conclusion = recommendations.get("conclusion", "")
    
    output = []
    output.append("\n" + "=" * 80)
    output.append("🎯 BUG BOUNTY PROGRAM RECOMMENDATIONS")
    output.append("=" * 80)
    
    if overview:
        output.append(f"\n{overview}\n")
    
    output.append("TOP RECOMMENDED PROGRAMS:")
    output.append("-" * 80)
    
    if not recommended_programs:
        output.append("Could not parse specific program recommendations.")
    else:
        for i, rec in enumerate(recommended_programs, 1):
            # Handle different recommendation formats
            if isinstance(rec, dict):
                program_name = rec.get("name", "Unknown Program")
                program_url = rec.get("url", "#")
                
                # Set platform explicitly based on the command-line argument
                platform = "HACKERONE"  # hardcode since we're querying hackerone
                
                # Check if program has explanation, if not provide default based on the program name
                explanation = rec.get("explanation", "")
                if not explanation and "rationale" in rec:
                    explanation = rec.get("rationale", "")
                if not explanation and "reason" in rec:
                    explanation = rec.get("reason", "")
                if not explanation:
                    explanation = f"{program_name} is recommended for beginners due to its clear scope and documentation."
                
                output.append(f"{i}. [{platform}] {program_name}")
                output.append(f"   URL: {program_url}")
                
                # Look up more details from programs_dict by matching URL or name
                program = None
                for p in programs_dict.values():
                    if p.get("url") == program_url or p.get("name") == program_name:
                        program = p
                        break
                
                if program:
                    if "avg_payout" in program and program["avg_payout"] > 0:
                        output.append(f"   Avg. Payout: ${program['avg_payout']:.2f}")
                    
                    if "response_time" in program and program["response_time"] > 0:
                        output.append(f"   Avg. Response Time: {program['response_time']:.1f} days")
                    
                    if "vdp_only" in program:
                        output.append(f"   VDP Only: {'Yes' if program['vdp_only'] else 'No'}")
                
                output.append(f"   Recommendation: {explanation}")
            else:
                # If rec is just a string
                output.append(f"{i}. [HACKERONE] {rec}")
            
            output.append("")
    
    output.append("-" * 80)
    output.append(f"{conclusion}")
    output.append("=" * 80)
    
    return "\n".join(output)

def save_recommendations_to_csv(recommendations, programs_dict, output_file):
    """Save recommendations to a CSV file."""
    if not recommendations:
        logger.warning("No recommendations to save")
        return False
    
    try:
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['Rank', 'Platform', 'Name', 'URL', 'Avg Payout', 'Response Time', 'VDP Only', 'Explanation']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for i, rec in enumerate(recommendations.get("recommended_programs", []), 1):
                program_id = rec.get("id")
                program = programs_dict.get(program_id, {})
                
                writer.writerow({
                    'Rank': i,
                    'Platform': program.get("platform", rec.get("platform", "Unknown")).upper(),
                    'Name': rec.get('name'),
                    'URL': rec.get('url'),
                    'Avg Payout': f"${program.get('avg_payout', 0):.2f}",
                    'Response Time': f"{program.get('response_time', 0):.1f} days",
                    'VDP Only': "Yes" if program.get("vdp_only", True) else "No",
                    'Explanation': rec.get('explanation', '')
                })
        
        logger.info(f"Recommendations saved to {output_file}")
        return True
    
    except Exception as e:
        logger.error(f"Error saving recommendations to CSV: {e}")
        return False

def main():
    """Main function."""
    args = parse_arguments()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Set up database
    setup_database()
    
    # Update program data if requested
    if args.update:
        update_program_data()
    
    # Check if database has data
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM programs")
    count = c.fetchone()[0]
    conn.close()
    
    if count == 0:
        logger.warning("No programs in database. Running update automatically.")
        update_program_data()
    
    # Get programs from database
    programs = get_programs_from_db(args.platform, args.min_payout, args.filter)
    
    if not programs:
        logger.error("No programs found matching the criteria")
        return 1
    
    logger.info(f"Found {len(programs)} programs matching the criteria")
    
    # Create a dict for quick lookup
    programs_dict = {p["id"]: p for p in programs}
    
    # Get recommendations
    recommendations = ai_recommend_programs(
        programs, 
        args.profile, 
        args.skills, 
        args.recommend
    )
    
    # Format and display recommendations
    formatted_recommendations = format_recommendations(recommendations, programs_dict)
    print(formatted_recommendations)
    
    # Save to CSV if requested
    if args.output:
        save_recommendations_to_csv(recommendations, programs_dict, args.output)
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("\nProgram selector cancelled by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
