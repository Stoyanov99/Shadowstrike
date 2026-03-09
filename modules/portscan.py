"""Port Scanning Module — Uses nmap with rustscan fallback for speed."""
import re
from .base import BaseModule, ModuleResult, Finding, Severity


class PortScanModule(BaseModule):
    name = "portscan"
    description = "Port Scanning"
    icon = "🔍"
    
    def check_requirements(self) -> bool:
        return self._tool_available("nmap")
    
    def run(self) -> ModuleResult:
        findings = []
        ports = []
        
        # Try rustscan first (faster), fallback to nmap
        if self._tool_available("rustscan"):
            result = self.runner.run(
                f"rustscan -a {self.target} --ulimit 5000 -t 3000 -- -sV",
                tool_name="rustscan",
                timeout=120,
                retry_commands=[
                    f"nmap -sV -sC -T4 --top-ports 1000 {self.target}",
                ],
            )
        else:
            result = self.runner.run(
                f"nmap -sV -sC -T4 --top-ports 1000 {self.target}",
                tool_name="nmap",
                timeout=300,
                retry_commands=[
                    f"nmap -sV -T3 --top-ports 100 {self.target}",
                ],
            )
        
        # Parse nmap/rustscan output
        output = result.stdout + result.stderr
        port_pattern = re.compile(r"(\d+)/tcp\s+(open|filtered)\s+(\S+)\s*(.*)")
        
        for match in port_pattern.finditer(output):
            port_num = int(match.group(1))
            state = match.group(2)
            service = match.group(3)
            version = match.group(4).strip()
            
            ports.append({
                "port": port_num,
                "state": state,
                "service": service,
                "version": version,
            })
        
        # Generate findings
        open_ports = [p for p in ports if p["state"] == "open"]
        
        if open_ports:
            findings.append(Finding(
                title=f"{len(open_ports)} open ports found",
                severity=Severity.INFO,
                description="Open ports: " + ", ".join(
                    f"{p['port']}/{p['service']}" for p in open_ports
                ),
                module=self.name,
            ))
            
            # Flag dangerous ports
            dangerous = {21: "FTP", 23: "Telnet", 3389: "RDP", 445: "SMB", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis", 11211: "Memcached"}
            for p in open_ports:
                if p["port"] in dangerous:
                    findings.append(Finding(
                        title=f"Potentially dangerous port: {p['port']} ({dangerous[p['port']]})",
                        severity=Severity.HIGH,
                        description=f"Port {p['port']} ({dangerous[p['port']]}) is open. This service should not be publicly accessible.",
                        recommendation=f"Restrict access to port {p['port']} via firewall rules.",
                        module=self.name,
                    ))
        
        self.runner.save_output(result, "portscan.txt")
        
        return ModuleResult(
            module_name=self.name,
            success=result.success,
            findings=findings,
            raw_output=result.stdout,
            duration=result.duration,
            data={"ports": ports, "open_count": len(open_ports)},
        )
