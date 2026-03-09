"""Vulnerability Scanning Module — Uses nuclei + nikto."""
import re
from .base import BaseModule, ModuleResult, Finding, Severity


class VulnScanModule(BaseModule):
    name = "vulnscan"
    description = "Vulnerability Scanning"
    icon = "🔓"
    
    def check_requirements(self) -> bool:
        return self._tool_available("nuclei") or self._tool_available("nikto")
    
    def run(self) -> ModuleResult:
        findings = []
        
        # 1. Nuclei scan
        if self._tool_available("nuclei"):
            nuclei_result = self.runner.run(
                f"nuclei -u https://{self.target} -severity low,medium,high,critical -silent -jsonl",
                tool_name="nuclei",
                timeout=300,
            )
            
            if nuclei_result.success and nuclei_result.stdout.strip():
                for line in nuclei_result.stdout.strip().split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        import json
                        data = json.loads(line)
                        sev_map = {
                            "critical": Severity.CRITICAL,
                            "high": Severity.HIGH,
                            "medium": Severity.MEDIUM,
                            "low": Severity.LOW,
                            "info": Severity.INFO,
                        }
                        severity = sev_map.get(data.get("info", {}).get("severity", "info"), Severity.INFO)
                        
                        findings.append(Finding(
                            title=data.get("info", {}).get("name", "Unknown vulnerability"),
                            severity=severity,
                            description=data.get("info", {}).get("description", ""),
                            evidence=data.get("matched-at", ""),
                            module=self.name,
                        ))
                    except (json.JSONDecodeError, KeyError):
                        if "[" in line and "]" in line:
                            findings.append(Finding(
                                title=line.strip(),
                                severity=Severity.MEDIUM,
                                description=f"Nuclei finding: {line}",
                                module=self.name,
                            ))
            
            self.runner.save_output(nuclei_result, "nuclei_scan.txt")
        
        # 2. Nikto scan (if web ports detected)
        if self._tool_available("nikto"):
            nikto_result = self.runner.run(
                f"nikto -h https://{self.target} -maxtime 120 -Format txt",
                tool_name="nikto",
                timeout=180,
            )
            
            if nikto_result.success:
                for line in nikto_result.stdout.split("\n"):
                    if line.strip().startswith("+") and "OSVDB" in line:
                        findings.append(Finding(
                            title=line.strip().lstrip("+ "),
                            severity=Severity.MEDIUM,
                            description=f"Nikto finding: {line.strip()}",
                            module=self.name,
                        ))
            
            self.runner.save_output(nikto_result, "nikto_scan.txt")
        
        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=findings,
            data={"vuln_count": len(findings)},
        )
