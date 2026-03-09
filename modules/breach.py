import httpx
from shadowstrike.modules.base import BaseModule, Finding, Severity, ModuleResult

class BreachScanModule(BaseModule):
    """Searches the Dark Web and public leaks for exposed company data using OSINT."""
    
    @property
    def name(self) -> str:
        return "breach"
        
    @property
    def description(self) -> str:
        return "Checking OSINT databases for exposed metadata & historical records"
        
    @property
    def icon(self) -> str:
        return "📜 "

    def check_requirements(self) -> bool:
        # Requires only standard httpx which is bundled
        return True

    def run(self) -> ModuleResult:
        """Queries crt.sh for historical certificate logs and exposed subdomains."""
        
        result = ModuleResult(module_name=self.name, success=True)
        
        # We use crt.sh (Certificate Transparency Logs) which is 100% free and unauthenticated.
        # It reveals historical infrastructure, staging environments, and internal subdomains
        # that the company thought were hidden.
        url = f"https://crt.sh/?q=%.{self.target}&output=json"
        
        try:
            with httpx.Client(timeout=20.0) as client:
                response = client.get(url)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data and isinstance(data, list) and len(data) > 0:
                        # Extract unique subdomains
                        unique_domains = set()
                        for entry in data:
                            name_value = entry.get("name_value", "")
                            # name_value can contain multiple domains separated by newlines
                            for d in name_value.split('\\n'):
                                d = d.strip().lower()
                                if d and not d.startswith('*'):
                                    unique_domains.add(d)
                                    
                        found_count = len(unique_domains)
                        
                        if found_count > 0:
                            # If we find a massive amount, it's a huge corporate footprint
                            severity = Severity.HIGH if found_count > 50 else Severity.MEDIUM
                            
                            sample_domains = list(unique_domains)[:10]
                            evidence = f"crt.sh exposed {found_count} historical subdomains.\nSample:\n- " + "\n- ".join(sample_domains)
                            
                            result.findings.append(Finding(
                                title=f"OSINT: {found_count} Exposed Historical Subdomains",
                                description=f"The domain {self.target} has extensive historical records in Certificate Transparency logs (crt.sh). Attackers use these logs to find forgotten 'staging', 'dev', or 'vpn' subdomains that bypass the main firewall.",
                                severity=severity,
                                recommendation="Review the exposed subdomains. Decommission any legacy infrastructure. Ensure staging environments are placed behind a VPN or internal network and not exposed to the public internet.",
                                business_impact="If attackers find forgotten staging servers or VPN endpoints, they can bypass your main firewall completely. These forgotten servers rarely have up-to-date security patches, making them the #1 entry point for ransomware gangs.",
                                module=self.name,
                                evidence=evidence
                            ))
                            
                        result.data["historical_records"] = found_count
                    else:
                        result.data["historical_records"] = 0
                        
                else:
                    result.data["historical_records"] = 0
                    
        except httpx.RequestError as e:
            result.success = False
            result.error = str(e)
            result.data["historical_records"] = 0
            
        return result
