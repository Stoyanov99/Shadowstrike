"""Security Headers Module — Analyzes HTTP headers for security issues."""
import re
import urllib.request
import urllib.error
import ssl
from .base import BaseModule, ModuleResult, Finding, Severity


class HeadersModule(BaseModule):
    name = "headers"
    description = "Security Headers Audit"
    icon = "🛡️"
    
    REQUIRED_HEADERS = {
        "X-Frame-Options": {
            "severity": Severity.MEDIUM,
            "description": "Missing X-Frame-Options header. Site can be embedded in iframes, enabling clickjacking attacks.",
            "recommendation": "Add header: X-Frame-Options: DENY",
            "business_impact": "Attackers can trick your visitors into clicking hidden buttons (Clickjacking), potentially leading to unauthorized actions like deleting accounts or transferring funds.",
        },
        "X-Content-Type-Options": {
            "severity": Severity.MEDIUM,
            "description": "Missing X-Content-Type-Options header. Browser may MIME-sniff content, leading to XSS.",
            "recommendation": "Add header: X-Content-Type-Options: nosniff",
            "business_impact": "Malicious user uploads could be interpreted as executable scripts by the browser, leading to full Cross-Site Scripting (XSS) compromises.",
        },
        "Content-Security-Policy": {
            "severity": Severity.MEDIUM,
            "description": "Missing Content-Security-Policy header. No restrictions on script/resource sources.",
            "recommendation": "Add a strict CSP header restricting script-src and other directives.",
            "business_impact": "Attackers can inject malicious scripts (XSS) into the browsers of your users, stealing their session cookies, credit cards, or defacing the website.",
        },
        "Referrer-Policy": {
            "severity": Severity.LOW,
            "description": "Missing Referrer-Policy header. Full URL may leak to third parties.",
            "recommendation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
            "business_impact": "Sensitive tokens or internal tracking IDs in URLs might leak to third-party analytics providers or external links.",
        },
        "Permissions-Policy": {
            "severity": Severity.LOW,
            "description": "Missing Permissions-Policy header. No restrictions on browser features (camera, mic).",
            "recommendation": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            "business_impact": "If compromised, the site might silently request access to the user's camera, microphone, or location without explicit centralized restriction.",
        },
        "Strict-Transport-Security": {
            "severity": Severity.HIGH,
            "description": "Missing HSTS header. Connections may be downgraded from HTTPS to HTTP.",
            "recommendation": "Add header: Strict-Transport-Security: max-age=63072000; includeSubDomains",
            "business_impact": "Attackers on public Wi-Fi can force users to browse via unsecured HTTP, allowing them to trivially intercept user passwords and session cookies (Man-in-the-Middle).",
        },
    }
    
    DANGEROUS_HEADERS = {
        "Server": "Server version disclosed — helps attackers fingerprint the technology.",
        "X-Powered-By": "Technology stack disclosed — helps attackers find known vulnerabilities.",
        "X-AspNet-Version": "ASP.NET version disclosed.",
    }
    
    def check_requirements(self) -> bool:
        return True  # Uses Python stdlib, always available
    
    def run(self) -> ModuleResult:
        findings = []
        headers_data = {}
        
        url = f"https://{self.target}"
        
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            })
            resp = urllib.request.urlopen(req, timeout=15, context=ctx)
            headers_data = dict(resp.headers)
            status_code = resp.getcode()
        except urllib.error.HTTPError as e:
            headers_data = dict(e.headers)
            status_code = e.code
        except Exception as e:
            return ModuleResult(
                module_name=self.name,
                success=False,
                error=f"Could not connect: {str(e)}",
            )
        
        # Check for missing required headers
        present = []
        missing = []
        for header, info in self.REQUIRED_HEADERS.items():
            header_lower = {k.lower(): v for k, v in headers_data.items()}
            if header.lower() in header_lower:
                present.append(header)
            else:
                missing.append(header)
                findings.append(Finding(
                    title=f"Missing header: {header}",
                    severity=info["severity"],
                    description=info["description"],
                    recommendation=info["recommendation"],
                    business_impact=info.get("business_impact", ""),
                    module=self.name,
                ))
        
        # Check for dangerous information disclosure headers
        for header, desc in self.DANGEROUS_HEADERS.items():
            header_lower = {k.lower(): v for k, v in headers_data.items()}
            if header.lower() in header_lower:
                findings.append(Finding(
                    title=f"Information disclosure: {header}",
                    severity=Severity.LOW,
                    description=f"{desc} Value: {header_lower[header.lower()]}",
                    recommendation=f"Remove or hide the {header} response header.",
                    module=self.name,
                ))
        
        # Check CORS
        cors = headers_data.get("Access-Control-Allow-Origin", "")
        if cors == "*":
            findings.append(Finding(
                title="Wildcard CORS policy (Access-Control-Allow-Origin: *)",
                severity=Severity.HIGH,
                description="Any website can make cross-origin requests to your domain. This is dangerous if any authenticated endpoints exist.",
                recommendation="Restrict CORS to specific trusted origins.",
                business_impact="Malicious websites can read sensitive user data (like account details or API keys) directly from the victim's browser session across origins.",
                module=self.name,
            ))
        
        # Build raw output
        raw = f"HTTP Status: {status_code}\n\n"
        raw += "Response Headers:\n"
        for k, v in headers_data.items():
            raw += f"  {k}: {v}\n"
        raw += f"\nPresent security headers: {', '.join(present) or 'none'}\n"
        raw += f"Missing security headers: {', '.join(missing) or 'none'}\n"
        
        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=findings,
            raw_output=raw,
            data={
                "headers": headers_data,
                "present": present,
                "missing": missing,
                "status_code": status_code,
            },
        )
