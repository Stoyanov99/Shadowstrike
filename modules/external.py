"""
External Tools Integration — Wraps AutoRecon, SpiderFoot, BBOT as ShadowStrike modules.
These are the GitHub open-source tools connected into our pipeline.
"""
import os
import sys
from .base import BaseModule, ModuleResult, Finding, Severity


class AutoReconModule(BaseModule):
    """
    AutoRecon Integration — Smart multi-threaded service enumeration.
    Source: https://github.com/Tib3rius/AutoRecon
    
    AutoRecon automatically detects services and runs appropriate
    enumeration tools (e.g. nikto for HTTP, enum4linux for SMB).
    """
    name = "autorecon"
    description = "AutoRecon Service Enumeration"
    icon = "🤖"
    
    def check_requirements(self) -> bool:
        # Check if autorecon is installed as a command
        return self._tool_available("autorecon")
    
    def run(self) -> ModuleResult:
        findings = []
        
        output_path = os.path.join(self.output_dir, "autorecon")
        os.makedirs(output_path, exist_ok=True)
        
        result = self.runner.run(
            f"autorecon {self.target} -o {output_path} --single-target --no-port-dirs",
            tool_name="autorecon",
            timeout=600,  # 10 min — autorecon is thorough
            retry_commands=[
                f"autorecon {self.target} -o {output_path} --single-target --no-port-dirs -p 80,443",
            ],
        )
        
        if result.success:
            # Parse autorecon results directory for findings
            results_dir = os.path.join(output_path, self.target)
            if os.path.exists(results_dir):
                for root, dirs, files in os.walk(results_dir):
                    for f in files:
                        if f.endswith(".txt"):
                            filepath = os.path.join(root, f)
                            try:
                                with open(filepath) as fh:
                                    content = fh.read()
                                if content.strip():
                                    findings.append(Finding(
                                        title=f"AutoRecon: {f}",
                                        severity=Severity.INFO,
                                        description=f"Results in: {filepath}",
                                        evidence=content[:500],
                                        module=self.name,
                                    ))
                            except Exception:
                                pass
        
        return ModuleResult(
            module_name=self.name,
            success=result.success,
            findings=findings,
            raw_output=result.stdout,
            duration=result.duration,
            data={"output_dir": output_path},
        )


class SpiderFootModule(BaseModule):
    """
    SpiderFoot Integration — OSINT scanner with 200+ modules.
    Source: https://github.com/smicallef/spiderfoot
    
    Queries public data sources for emails, IPs, subdomains,
    data breaches, social media, and more.
    """
    name = "spiderfoot"
    description = "SpiderFoot OSINT"
    icon = "🕷️"
    
    SPIDERFOOT_PATH = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "tools", "SpiderFoot"
    )
    
    def check_requirements(self) -> bool:
        return os.path.exists(os.path.join(self.SPIDERFOOT_PATH, "sf.py"))
    
    def run(self) -> ModuleResult:
        findings = []
        
        python = sys.executable
        sf_script = os.path.join(self.SPIDERFOOT_PATH, "sf.py")
        
        # Run SpiderFoot CLI scan
        result = self.runner.run(
            f"{python} {sf_script} -s {self.target} -t INTERNET_NAME,IP_ADDRESS,EMAILADDR -q",
            tool_name="spiderfoot",
            timeout=300,
        )
        
        if result.success and result.stdout.strip():
            lines = result.stdout.strip().split("\n")
            
            emails = []
            ips = []
            subdomains = []
            
            for line in lines:
                line_lower = line.lower()
                if "@" in line and "email" in line_lower:
                    emails.append(line.strip())
                elif "internet name" in line_lower:
                    subdomains.append(line.strip())
                elif "ip address" in line_lower:
                    ips.append(line.strip())
            
            if emails:
                findings.append(Finding(
                    title=f"OSINT: {len(emails)} email addresses found",
                    severity=Severity.INFO,
                    description="\n".join(emails[:10]),
                    module=self.name,
                ))
            
            if subdomains:
                findings.append(Finding(
                    title=f"OSINT: {len(subdomains)} hostnames found",
                    severity=Severity.INFO,
                    description="\n".join(subdomains[:10]),
                    module=self.name,
                ))
        
        self.runner.save_output(result, "spiderfoot_osint.txt")
        
        return ModuleResult(
            module_name=self.name,
            success=result.success if result.stdout else True,
            findings=findings,
            raw_output=result.stdout,
            duration=result.duration,
            data={"raw_lines": len(result.stdout.split("\n")) if result.stdout else 0},
        )


class BBOTModule(BaseModule):
    """
    BBOT Integration — Modern recon framework.
    Source: https://github.com/blacklanternsecurity/bbot
    
    Modular event-driven scanner with subdomain enum,
    port scanning, web crawling, and vulnerability detection.
    """
    name = "bbot"
    description = "BBOT Reconnaissance"
    icon = "🐝"
    
    def check_requirements(self) -> bool:
        return self._tool_available("bbot")
    
    def run(self) -> ModuleResult:
        findings = []
        
        result = self.runner.run(
            f"bbot -t {self.target} -f safe -y --silent",
            tool_name="bbot",
            timeout=300,
            retry_commands=[
                f"bbot -t {self.target} -m nmap subfinder -y --silent",
            ],
        )
        
        if result.success and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("["):
                    continue
                
                if "VULNERABILITY" in line.upper():
                    findings.append(Finding(
                        title=f"BBOT: {line[:100]}",
                        severity=Severity.HIGH,
                        description=line,
                        module=self.name,
                    ))
                elif "FINDING" in line.upper():
                    findings.append(Finding(
                        title=f"BBOT: {line[:100]}",
                        severity=Severity.MEDIUM,
                        description=line,
                        module=self.name,
                    ))
        
        self.runner.save_output(result, "bbot_recon.txt")
        
        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=findings,
            raw_output=result.stdout,
            duration=result.duration,
        )


class SSLScanModule(BaseModule):
    """
    SSL/TLS Analysis Module — Uses testssl.sh for deep SSL analysis.
    """
    name = "sslscan"
    description = "SSL/TLS Analysis"
    icon = "🔒"
    
    def check_requirements(self) -> bool:
        return self._tool_available("testssl") or self._tool_available("testssl.sh")
    
    def run(self) -> ModuleResult:
        findings = []
        
        testssl_cmd = "testssl" if self._tool_available("testssl") else "testssl.sh"
        
        result = self.runner.run(
            f"{testssl_cmd} --quiet --color 0 --sneaky https://{self.target}",
            tool_name="testssl",
            timeout=180,
        )
        
        if result.success:
            output = result.stdout
            
            # Parse for vulnerabilities
            vuln_keywords = {
                "VULNERABLE": Severity.HIGH,
                "NOT ok": Severity.MEDIUM,
                "WARN": Severity.MEDIUM,
                "LOW": Severity.LOW,
                "weak": Severity.MEDIUM,
                "expired": Severity.CRITICAL,
            }
            
            for line in output.split("\n"):
                for keyword, severity in vuln_keywords.items():
                    if keyword.lower() in line.lower() and "not vulnerable" not in line.lower():
                        findings.append(Finding(
                            title=f"SSL Issue: {line.strip()[:80]}",
                            severity=severity,
                            description=line.strip(),
                            module=self.name,
                        ))
                        break
        
        self.runner.save_output(result, "ssl_analysis.txt")
        
        return ModuleResult(
            module_name=self.name,
            success=result.success,
            findings=findings,
            raw_output=result.stdout,
            duration=result.duration,
        )
