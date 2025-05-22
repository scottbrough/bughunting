#!/usr/bin/env python3
"""
Personal Bug Bounty Assistant
A streamlined, AI-powered bug bounty automation tool for individual hunters.
One target, one report, maximum efficiency.
"""

import os
import sys
import json
import time
import subprocess
import argparse
import requests
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import openai

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"bb_hunt_{datetime.now().strftime('%Y%m%d')}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("bb_assistant")

class BugBountyAssistant:
    """Personal Bug Bounty Assistant - AI-powered hunting workflow"""
    
    def __init__(self, api_key: str):
        self.client = openai.OpenAI(api_key=api_key)
        self.target = None
        self.workspace = None
        self.findings = []
        self.chains = []
        self.session_data = {}
        
    def initialize_hunt(self, target: str, program_info: str = ""):
        """Initialize a new bug bounty hunt session"""
        self.target = target
        self.workspace = Path(f"hunt_{target.replace('.', '_').replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.workspace.mkdir(exist_ok=True)
        
        logger.info(f"🎯 Starting hunt on {target}")
        logger.info(f"📁 Workspace: {self.workspace}")
        
        # Save session metadata
        self.session_data = {
            "target": target,
            "program_info": program_info,
            "start_time": datetime.now().isoformat(),
            "workspace": str(self.workspace),
            "findings": [],
            "chains": [],
            "reports": []
        }
        self._save_session()
        
    def ai_target_analysis(self) -> Dict:
        """AI-powered target analysis and attack planning"""
        logger.info("🧠 Analyzing target with AI...")
        
        prompt = f"""
        You are an expert bug bounty hunter analyzing a new target: {self.target}
        
        Provide a comprehensive analysis including:
        1. Technology stack predictions based on domain/subdomain patterns
        2. Likely attack vectors to prioritize
        3. Common vulnerabilities for this type of target
        4. Recon strategy recommendations
        5. Areas most likely to yield high-severity findings
        6. Specific endpoints/features to target first
        
        Return your analysis as a JSON object with structured recommendations.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.7
            )
            
            analysis = json.loads(response.choices[0].message.content)
            
            # Save analysis
            analysis_file = self.workspace / "ai_analysis.json"
            with open(analysis_file, 'w') as f:
                json.dump(analysis, f, indent=2)
                
            logger.info("✅ Target analysis complete")
            return analysis
            
        except Exception as e:
            logger.error(f"❌ AI analysis failed: {e}")
            return {"error": str(e)}
    
    def intelligent_recon(self) -> Dict:
        """AI-guided reconnaissance phase"""
        logger.info("🔍 Starting intelligent reconnaissance...")
        
        recon_results = {
            "subdomains": [],
            "endpoints": [],
            "technologies": [],
            "interesting_findings": []
        }
        
        # Subdomain enumeration
        logger.info("Finding subdomains...")
        subdomains = self._find_subdomains()
        recon_results["subdomains"] = subdomains
        
        # Content discovery on main target and top subdomains
        logger.info("Discovering content...")
        top_targets = [self.target] + subdomains[:5]  # Limit to prevent overload
        
        for target in top_targets:
            endpoints = self._discover_content(target)
            recon_results["endpoints"].extend(endpoints)
            
        # AI-powered endpoint analysis
        logger.info("🧠 AI analyzing discovered endpoints...")
        interesting_endpoints = self._ai_classify_endpoints(recon_results["endpoints"])
        recon_results["interesting_findings"] = interesting_endpoints
        
        # Save recon results
        recon_file = self.workspace / "recon_results.json"
        with open(recon_file, 'w') as f:
            json.dump(recon_results, f, indent=2)
            
        logger.info(f"✅ Recon complete: {len(recon_results['endpoints'])} endpoints, {len(interesting_endpoints)} interesting")
        return recon_results
    
    def ai_vulnerability_hunting(self, recon_data: Dict) -> List[Dict]:
        """AI-powered vulnerability testing"""
        logger.info("🎯 Starting AI-guided vulnerability hunting...")
        
        findings = []
        interesting_endpoints = recon_data.get("interesting_findings", [])
        
        for endpoint in interesting_endpoints[:20]:  # Limit for focused testing
            logger.info(f"Testing: {endpoint['url']}")
            
            # Generate AI-powered test payloads
            payloads = self._generate_ai_payloads(endpoint)
            
            # Test each payload
            for payload_data in payloads:
                result = self._test_payload(endpoint['url'], payload_data)
                if result.get('vulnerable'):
                    findings.append(result)
                    logger.info(f"🚨 Potential vulnerability found: {result['type']} in {endpoint['url']}")
        
        self.findings = findings
        
        # Save findings
        findings_file = self.workspace / "findings.json"
        with open(findings_file, 'w') as f:
            json.dump(findings, f, indent=2)
            
        logger.info(f"✅ Vulnerability hunting complete: {len(findings)} potential issues found")
        return findings
    
    def ai_chain_detection(self) -> List[Dict]:
        """AI-powered vulnerability chaining analysis"""
        if not self.findings:
            logger.info("No findings to chain")
            return []
            
        logger.info("🔗 Analyzing vulnerability chains with AI...")
        
        prompt = f"""
        You are an expert bug bounty hunter analyzing vulnerabilities for potential chaining.
        
        Target: {self.target}
        Findings: {json.dumps(self.findings, indent=2)}
        
        Analyze these findings and identify:
        1. Potential attack chains that combine multiple vulnerabilities
        2. Privilege escalation paths
        3. Data exfiltration scenarios
        4. Account takeover possibilities
        5. Business logic abuse chains
        
        For each chain, provide:
        - Chain name and description
        - Step-by-step attack path
        - Impact assessment
        - Proof of concept outline
        - CVSS score estimation
        
        Return as JSON array of chains.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.7
            )
            
            result = json.loads(response.choices[0].message.content)
            chains = result.get("chains", [])
            self.chains = chains
            
            # Save chains
            chains_file = self.workspace / "vulnerability_chains.json"
            with open(chains_file, 'w') as f:
                json.dump(chains, f, indent=2)
                
            logger.info(f"✅ Chain analysis complete: {len(chains)} chains identified")
            return chains
            
        except Exception as e:
            logger.error(f"❌ Chain analysis failed: {e}")
            return []
    
    def ai_exploit_generation(self) -> Dict:
        """AI-powered exploit and PoC generation"""
        logger.info("💥 Generating exploits and PoCs with AI...")
        
        exploits = {
            "individual_exploits": [],
            "chain_exploits": [],
            "poc_scripts": []
        }
        
        # Generate exploits for individual findings
        for finding in self.findings:
            exploit = self._generate_exploit(finding)
            if exploit:
                exploits["individual_exploits"].append(exploit)
        
        # Generate exploits for chains
        for chain in self.chains:
            chain_exploit = self._generate_chain_exploit(chain)
            if chain_exploit:
                exploits["chain_exploits"].append(chain_exploit)
        
        # Save exploits
        exploits_file = self.workspace / "exploits.json"
        with open(exploits_file, 'w') as f:
            json.dump(exploits, f, indent=2)
            
        # Generate PoC scripts
        self._generate_poc_scripts(exploits)
        
        logger.info(f"✅ Exploit generation complete")
        return exploits
    
    def ai_report_generation(self) -> str:
        """AI-powered professional report generation"""
        logger.info("📝 Generating professional report with AI...")
        
        # Gather all data
        report_data = {
            "target": self.target,
            "findings": self.findings,
            "chains": self.chains,
            "session_data": self.session_data
        }
        
        # Generate executive summary
        exec_summary = self._generate_executive_summary(report_data)
        
        # Generate technical details for each finding
        detailed_findings = []
        for finding in self.findings:
            detailed = self._generate_detailed_finding(finding)
            detailed_findings.append(detailed)
        
        # Generate markdown report
        report_md = self._generate_markdown_report(exec_summary, detailed_findings)
        
        # Generate HTML report
        report_html = self._generate_html_report(exec_summary, detailed_findings)
        
        # Save reports
        md_file = self.workspace / f"bug_bounty_report_{self.target}.md"
        html_file = self.workspace / f"bug_bounty_report_{self.target}.html"
        
        with open(md_file, 'w') as f:
            f.write(report_md)
        with open(html_file, 'w') as f:
            f.write(report_html)
            
        logger.info(f"✅ Reports generated: {md_file}, {html_file}")
        return str(md_file)
    
    def run_full_hunt(self, target: str, program_info: str = "") -> str:
        """Run the complete bug bounty hunting workflow"""
        start_time = time.time()
        
        try:
            # Initialize
            self.initialize_hunt(target, program_info)
            
            # Phase 1: AI Analysis
            analysis = self.ai_target_analysis()
            print(f"\n🎯 Target Analysis Complete")
            print(f"   Recommended focus areas: {', '.join(analysis.get('priority_areas', [])[:3])}")
            
            # Phase 2: Intelligent Recon
            recon_data = self.intelligent_recon()
            print(f"\n🔍 Reconnaissance Complete")
            print(f"   Subdomains found: {len(recon_data['subdomains'])}")
            print(f"   Endpoints discovered: {len(recon_data['endpoints'])}")
            print(f"   Interesting targets: {len(recon_data['interesting_findings'])}")
            
            # Phase 3: Vulnerability Hunting
            findings = self.ai_vulnerability_hunting(recon_data)
            print(f"\n🎯 Vulnerability Hunting Complete")
            print(f"   Potential vulnerabilities: {len(findings)}")
            
            # Phase 4: Chain Detection
            chains = self.ai_chain_detection()
            print(f"\n🔗 Chain Analysis Complete")
            print(f"   Attack chains identified: {len(chains)}")
            
            # Phase 5: Exploit Generation
            exploits = self.ai_exploit_generation()
            print(f"\n💥 Exploit Generation Complete")
            print(f"   Individual exploits: {len(exploits['individual_exploits'])}")
            print(f"   Chain exploits: {len(exploits['chain_exploits'])}")
            
            # Phase 6: Report Generation
            report_file = self.ai_report_generation()
            
            # Final summary
            duration = time.time() - start_time
            print(f"\n🎉 Hunt Complete!")
            print(f"   Duration: {duration/60:.1f} minutes")
            print(f"   Findings: {len(findings)} vulnerabilities, {len(chains)} chains")
            print(f"   Report: {report_file}")
            print(f"   Workspace: {self.workspace}")
            
            return report_file
            
        except Exception as e:
            logger.error(f"❌ Hunt failed: {e}")
            raise
    
    # Helper methods
    def _find_subdomains(self) -> List[str]:
        """Find subdomains using multiple techniques"""
        subdomains = set()
        
        # Using subfinder if available
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.target, "-silent"],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                subdomains.update(result.stdout.strip().split('\n'))
        except:
            pass
        
        # Using amass if available
        try:
            result = subprocess.run(
                ["amass", "enum", "-passive", "-d", self.target],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                subdomains.update(result.stdout.strip().split('\n'))
        except:
            pass
        
        # DNS bruteforce with common subdomains
        common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'test', 'dev', 'staging']
        for sub in common_subs:
            try:
                import socket
                socket.gethostbyname(f"{sub}.{self.target}")
                subdomains.add(f"{sub}.{self.target}")
            except:
                pass
        
        return list(subdomains)[:20]  # Limit results
    
    def _discover_content(self, target: str) -> List[Dict]:
        """Discover content on target"""
        endpoints = []
        
        # Basic directory discovery
        common_paths = [
            '/', '/admin', '/api', '/login', '/dashboard', '/config',
            '/backup', '/test', '/dev', '/staging', '/uploads',
            '/files', '/docs', '/swagger', '/graphql', '/robots.txt',
            '/sitemap.xml', '/.env', '/.git', '/wp-admin'
        ]
        
        for path in common_paths:
            url = f"https://{target}{path}"
            try:
                response = requests.get(url, timeout=10, verify=False)
                endpoints.append({
                    "url": url,
                    "status": response.status_code,
                    "length": len(response.content),
                    "title": self._extract_title(response.text)
                })
            except:
                pass
        
        return endpoints
    
    def _ai_classify_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        """Use AI to classify interesting endpoints"""
        if not endpoints:
            return []
            
        prompt = f"""
        Analyze these discovered endpoints and identify the most interesting ones for bug bounty hunting:
        
        {json.dumps(endpoints[:50], indent=2)}
        
        Return the top 10 most interesting endpoints with:
        - vulnerability types likely to be found
        - attack vectors to try
        - priority level (1-10)
        
        Focus on admin panels, APIs, file uploads, authentication, etc.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.5
            )
            
            result = json.loads(response.choices[0].message.content)
            return result.get("interesting_endpoints", [])
            
        except Exception as e:
            logger.error(f"AI endpoint classification failed: {e}")
            return endpoints[:10]  # Fallback to first 10
    
    def _generate_ai_payloads(self, endpoint: Dict) -> List[Dict]:
        """Generate AI-powered test payloads for an endpoint"""
        prompt = f"""
        Generate test payloads for this endpoint:
        URL: {endpoint['url']}
        Status: {endpoint.get('status')}
        Context: {endpoint.get('title', '')}
        
        Generate 5-10 targeted payloads for:
        - XSS (reflected, stored, DOM)
        - SQL injection 
        - Command injection
        - Path traversal
        - SSRF
        - Authentication bypass
        
        Return JSON array of payloads with type, parameter, and payload.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.8
            )
            
            result = json.loads(response.choices[0].message.content)
            return result.get("payloads", [])
            
        except Exception as e:
            logger.error(f"AI payload generation failed: {e}")
            return []
    
    def _test_payload(self, url: str, payload_data: Dict) -> Dict:
        """Test a payload against an endpoint"""
        # This is a simplified implementation
        # In practice, you'd want more sophisticated testing
        try:
            # Basic XSS test
            if payload_data.get('type') == 'xss':
                test_url = f"{url}?{payload_data.get('parameter', 'q')}={payload_data.get('payload')}"
                response = requests.get(test_url, timeout=10, verify=False)
                if payload_data.get('payload') in response.text:
                    return {
                        "vulnerable": True,
                        "type": "XSS",
                        "url": test_url,
                        "parameter": payload_data.get('parameter'),
                        "payload": payload_data.get('payload'),
                        "evidence": response.text[:500]
                    }
            
            # Add more payload testing logic here
            
        except Exception as e:
            logger.debug(f"Payload test failed: {e}")
        
        return {"vulnerable": False}
    
    def _generate_exploit(self, finding: Dict) -> Dict:
        """Generate exploit for a finding"""
        prompt = f"""
        Generate a professional exploit/PoC for this vulnerability:
        {json.dumps(finding, indent=2)}
        
        Include:
        - Exploit code/script
        - Step-by-step reproduction
        - Impact assessment
        - Remediation advice
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.5
            )
            
            return {
                "finding_id": finding.get("url"),
                "exploit_code": response.choices[0].message.content,
                "type": finding.get("type")
            }
            
        except Exception as e:
            logger.error(f"Exploit generation failed: {e}")
            return {}
    
    def _generate_chain_exploit(self, chain: Dict) -> Dict:
        """Generate exploit for a vulnerability chain"""
        # Similar to _generate_exploit but for chains
        return {}
    
    def _generate_poc_scripts(self, exploits: Dict):
        """Generate actual PoC scripts"""
        poc_dir = self.workspace / "poc_scripts"
        poc_dir.mkdir(exist_ok=True)
        
        for i, exploit in enumerate(exploits.get("individual_exploits", [])):
            script_file = poc_dir / f"exploit_{i+1}.py"
            with open(script_file, 'w') as f:
                f.write(f"#!/usr/bin/env python3\n")
                f.write(f"# PoC for {exploit.get('type')} vulnerability\n\n")
                f.write(exploit.get("exploit_code", "# Exploit code here"))
    
    def _generate_executive_summary(self, report_data: Dict) -> str:
        """Generate executive summary with AI"""
        prompt = f"""
        Generate a professional executive summary for this bug bounty report:
        
        Target: {report_data['target']}
        Findings: {len(report_data['findings'])} vulnerabilities
        Chains: {len(report_data['chains'])} attack chains
        
        Key findings:
        {json.dumps(report_data['findings'][:5], indent=2)}
        
        Write a concise, professional executive summary suitable for a bug bounty report.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.5
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            return "Executive summary generation failed."
    
    def _generate_detailed_finding(self, finding: Dict) -> Dict:
        """Generate detailed finding report with AI"""
        prompt = f"""
        Generate a detailed, professional bug bounty finding report for:
        {json.dumps(finding, indent=2)}
        
        Include:
        - Title and severity
        - Detailed description
        - Impact assessment
        - Reproduction steps
        - Remediation recommendations
        - CVSS score estimation
        
        Format for bug bounty platform submission.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3
            )
            
            return {
                "raw_finding": finding,
                "detailed_report": response.choices[0].message.content
            }
            
        except Exception as e:
            logger.error(f"Detailed finding generation failed: {e}")
            return {"raw_finding": finding, "detailed_report": "Failed to generate detailed report"}
    
    def _generate_markdown_report(self, exec_summary: str, findings: List[Dict]) -> str:
        """Generate markdown report"""
        md = f"""# Bug Bounty Report: {self.target}

**Date:** {datetime.now().strftime('%Y-%m-%d')}  
**Target:** {self.target}  
**Findings:** {len(findings)} vulnerabilities  

## Executive Summary

{exec_summary}

## Findings

"""
        for i, finding in enumerate(findings, 1):
            md += f"\n### Finding {i}\n\n"
            md += finding.get("detailed_report", "No details available")
            md += "\n\n---\n"
        
        return md
    
    def _generate_html_report(self, exec_summary: str, findings: List[Dict]) -> str:
        """Generate HTML report"""
        # Simplified HTML generation - you might want to use a template engine
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Bug Bounty Report: {self.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
        .finding {{ border: 1px solid #ddd; margin: 20px 0; padding: 15px; }}
        .severity-high {{ border-left: 5px solid #ff4444; }}
        .severity-medium {{ border-left: 5px solid #ffaa00; }}
        .severity-low {{ border-left: 5px solid #44ff44; }}
    </style>
</head>
<body>
    <h1>Bug Bounty Report: {self.target}</h1>
    <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d')}</p>
    <p><strong>Findings:</strong> {len(findings)} vulnerabilities</p>
    
    <h2>Executive Summary</h2>
    <p>{exec_summary}</p>
    
    <h2>Findings</h2>
"""
        
        for i, finding in enumerate(findings, 1):
            severity = finding.get("raw_finding", {}).get("severity", "medium")
            html += f"""
    <div class="finding severity-{severity}">
        <h3>Finding {i}</h3>
        <pre>{finding.get("detailed_report", "No details available")}</pre>
    </div>
"""
        
        html += "</body></html>"
        return html
    
    def _extract_title(self, html: str) -> str:
        """Extract title from HTML"""
        try:
            import re
            match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
            return match.group(1) if match else ""
        except:
            return ""
    
    def _save_session(self):
        """Save session data"""
        session_file = self.workspace / "session.json"
        with open(session_file, 'w') as f:
            json.dump(self.session_data, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description="Personal Bug Bounty Assistant")
    parser.add_argument("target", help="Target domain to hunt")
    parser.add_argument("--api-key", help="OpenAI API key (or set OPENAI_API_KEY env var)")
    parser.add_argument("--program-info", help="Bug bounty program information")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Get API key
    api_key = args.api_key or os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("❌ OpenAI API key required. Set OPENAI_API_KEY env var or use --api-key")
        sys.exit(1)
    
    # Initialize assistant
    assistant = BugBountyAssistant(api_key)
    
    try:
        # Run the hunt
        report_file = assistant.run_full_hunt(args.target, args.program_info or "")
        
        print(f"\n🎉 Hunt completed successfully!")
        print(f"📋 Report: {report_file}")
        print(f"📁 All files: {assistant.workspace}")
        
    except KeyboardInterrupt:
        print("\n⚠️ Hunt interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Hunt failed: {e}")
        logger.exception("Hunt failed with exception")
        sys.exit(1)

if __name__ == "__main__":
    main()
