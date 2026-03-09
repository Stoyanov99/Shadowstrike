"""Subdomain Enumeration Module — Uses subfinder + DNS brute."""
import re
from .base import BaseModule, ModuleResult, Finding, Severity


class SubdomainModule(BaseModule):
    name = "subdomains"
    description = "Subdomain Enumeration"
    icon = "🌐"
    
    def check_requirements(self) -> bool:
        return self._tool_available("subfinder")
    
    def run(self) -> ModuleResult:
        findings = []
        subdomains = set()
        
        # 1. Subfinder
        result = self.runner.run(
            f"subfinder -d {self.target} -silent",
            tool_name="subfinder",
            timeout=120,
        )
        
        if result.success and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line and "." in line:
                    subdomains.add(line)
        
        # 2. Common subdomain check via DNS
        common_subs = ["www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "blog", "shop", "app", "portal", "vpn", "remote", "cdn"]
        for sub in common_subs:
            hostname = f"{sub}.{self.target}"
            dns_result = self.runner.run(
                f"dig +short {hostname} A",
                tool_name="dig",
                timeout=5,
                retry=False,
            )
            if dns_result.success and dns_result.stdout.strip():
                subdomains.add(hostname)
        
        # Generate findings
        if subdomains:
            findings.append(Finding(
                title=f"{len(subdomains)} subdomains discovered",
                severity=Severity.INFO,
                description=f"Found subdomains: {', '.join(sorted(subdomains))}",
                module=self.name,
            ))
        
        self.runner.save_output(result, "subdomains.txt")
        
        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=findings,
            raw_output="\n".join(sorted(subdomains)),
            duration=result.duration,
            data={"subdomains": sorted(subdomains), "count": len(subdomains)},
        )
