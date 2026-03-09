"""Directory Brute-force Module — Uses feroxbuster/ffuf to find hidden paths."""
import re
import os
from .base import BaseModule, ModuleResult, Finding, Severity


class DirBruteModule(BaseModule):
    name = "dirbrute"
    description = "Directory Brute-force"
    icon = "📁"
    
    def check_requirements(self) -> bool:
        return self._tool_available("feroxbuster") or self._tool_available("ffuf")
    
    def _get_wordlist(self) -> str:
        """Find the best available wordlist."""
        paths = [
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "wordlists", "common.txt"),
            "/opt/homebrew/share/feroxbuster/raft-medium-directories.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return ""
    
    def run(self) -> ModuleResult:
        findings = []
        wordlist = self._get_wordlist()
        
        if not wordlist:
            return ModuleResult(
                module_name=self.name, success=False,
                error="No wordlist found. Place common.txt in wordlists/ directory.",
            )
        
        # Use feroxbuster (preferred) or ffuf
        if self._tool_available("feroxbuster"):
            result = self.runner.run(
                f"feroxbuster -u https://{self.target} -w {wordlist} -t 20 -s 200,301,302,403 --quiet --no-state -k",
                tool_name="feroxbuster",
                timeout=180,
            )
        else:
            result = self.runner.run(
                f"ffuf -u https://{self.target}/FUZZ -w {wordlist} -mc 200,301,302 -t 20 -s",
                tool_name="ffuf",
                timeout=180,
            )
        
        # Parse results
        interesting_paths = []
        if result.success and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                # Extract status code and path
                status_match = re.search(r'(\d{3})\s+.*?(https?://\S+|/\S+)', line)
                if status_match:
                    status = int(status_match.group(1))
                    path = status_match.group(2)
                    interesting_paths.append({"status": status, "path": path})
                elif line.startswith("/") or line.startswith("http"):
                    interesting_paths.append({"status": 200, "path": line})
        
        # Generate findings for interesting paths
        sensitive_patterns = [
            "admin", "login", "dashboard", "config", "backup", "api", 
            "debug", ".env", ".git", "database", "phpmyadmin", "console",
            "upload", "editor", "panel", "manager",
        ]
        
        for item in interesting_paths:
            path_lower = item["path"].lower()
            is_sensitive = any(s in path_lower for s in sensitive_patterns)
            
            if is_sensitive:
                findings.append(Finding(
                    title=f"Sensitive path found: {item['path']}",
                    severity=Severity.MEDIUM,
                    description=f"HTTP {item['status']} — {item['path']}",
                    recommendation="Verify this path should be publicly accessible.",
                    module=self.name,
                ))
        
        if interesting_paths:
            findings.append(Finding(
                title=f"{len(interesting_paths)} paths discovered",
                severity=Severity.INFO,
                description="Paths: " + ", ".join(p["path"] for p in interesting_paths[:20]),
                module=self.name,
            ))
        
        self.runner.save_output(result, "dirbrute.txt")
        
        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=findings,
            data={"paths": interesting_paths, "count": len(interesting_paths)},
        )
