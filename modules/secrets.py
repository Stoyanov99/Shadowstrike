"""Secret Scanning Module — Finds API keys, tokens, passwords in JS/HTML."""
import re
import urllib.request
import ssl
from .base import BaseModule, ModuleResult, Finding, Severity


class SecretScanModule(BaseModule):
    name = "secrets"
    description = "Secret & API Key Detection"
    icon = "🔑"
    
    SECRET_PATTERNS = {
        "AWS Access Key": r'AKIA[A-Z0-9]{16}',
        "AWS Secret Key": r'(?:aws_secret_access_key|secret_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})',
        "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
        "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
        "Supabase URL": r'https://[a-z0-9]+\.supabase\.(co|in)',
        "Stripe Secret Key": r'sk_(live|test)_[a-zA-Z0-9]{24,}',
        "Stripe Publishable Key": r'pk_(live|test)_[a-zA-Z0-9]{24,}',
        "OpenAI API Key": r'sk-[a-zA-Z0-9]{32,}',
        "GitHub Token": r'gh[pousr]_[A-Za-z0-9_]{36,}',
        "Slack Token": r'xox[bpas]-[a-zA-Z0-9-]+',
        "JWT Token": r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+',
        "Generic API Key": r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']{20,})["\']',
        "Generic Secret": r'(?:secret|token|password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']',
        "Private Key": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        "Database URL": r'(?:mysql|postgres|mongodb|redis)://[^\s"\'<>]+',
    }
    
    def check_requirements(self) -> bool:
        return True  # Pure Python
    
    def run(self) -> ModuleResult:
        findings = []
        
        # Fetch the main page
        url = f"https://{self.target}"
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
            })
            resp = urllib.request.urlopen(req, timeout=15, context=ctx)
            html = resp.read().decode("utf-8", errors="ignore")
        except Exception:
            html = ""
        
        # Find JS file references
        js_files = re.findall(r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', html)
        
        # Fetch and scan JS files
        js_content = html  # Also scan the HTML itself
        for js_file in js_files[:10]:  # Limit to 10 JS files
            js_url = js_file if js_file.startswith("http") else f"https://{self.target}/{js_file.lstrip('/')}"
            try:
                req = urllib.request.Request(js_url, headers={
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
                })
                resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                js_content += "\n" + resp.read().decode("utf-8", errors="ignore")
            except Exception:
                pass
        
        # Scan for secrets
        secrets_found = []
        for name, pattern in self.SECRET_PATTERNS.items():
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            if matches:
                for match in matches[:3]:  # Cap at 3 per type
                    # Mask the secret
                    if isinstance(match, str) and len(match) > 10:
                        masked = match[:6] + "..." + match[-4:]
                    else:
                        masked = str(match)[:10] + "***"
                    
                    secrets_found.append({"type": name, "value": masked})
                    findings.append(Finding(
                        title=f"Exposed {name}",
                        severity=Severity.CRITICAL if "private key" in name.lower() or "secret" in name.lower() else Severity.HIGH,
                        description=f"A {name} was found exposed in client-side code: {masked}",
                        recommendation=f"Immediately rotate this {name} and move it to server-side environment variables.",
                        module=self.name,
                    ))
        
        # Check source maps
        for js_file in js_files[:5]:
            map_url = js_file + ".map"
            if not map_url.startswith("http"):
                map_url = f"https://{self.target}/{map_url.lstrip('/')}"
            try:
                req = urllib.request.Request(map_url, headers={
                    "User-Agent": "Mozilla/5.0"
                })
                resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                if resp.getcode() == 200:
                    findings.append(Finding(
                        title="Source map exposed",
                        severity=Severity.HIGH,
                        description=f"Source map available at {map_url}. Full source code can be reconstructed.",
                        recommendation="Remove source maps from production or restrict access.",
                        module=self.name,
                    ))
            except Exception:
                pass
        
        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=findings,
            data={
                "secrets_found": len(secrets_found),
                "js_files_scanned": len(js_files),
                "secrets": secrets_found,
            },
        )
