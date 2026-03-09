"""Email Security Module — Checks SPF, DKIM, DMARC records."""
from .base import BaseModule, ModuleResult, Finding, Severity


class EmailSecModule(BaseModule):
    name = "emailsec"
    description = "Email Security Audit"
    icon = "📧"
    
    def check_requirements(self) -> bool:
        return self._tool_available("dig")
    
    def run(self) -> ModuleResult:
        findings = []
        records = {}
        
        # Check SPF
        spf_result = self.runner.run(
            f"dig +short {self.target} TXT",
            tool_name="dig", timeout=10, retry=False,
        )
        spf_found = False
        if spf_result.success:
            for line in spf_result.stdout.split("\n"):
                if "v=spf1" in line:
                    spf_found = True
                    records["SPF"] = line.strip().strip('"')
                    if "~all" in line:
                        findings.append(Finding(
                            title="SPF uses soft fail (~all)",
                            severity=Severity.LOW,
                            description="SPF record uses ~all (soft fail) instead of -all (hard fail).",
                            recommendation="Change ~all to -all for stricter email authentication.",
                            module=self.name,
                        ))
        
        if not spf_found:
            findings.append(Finding(
                title="Missing SPF record",
                severity=Severity.MEDIUM,
                description="No SPF record found. Attackers can send emails impersonating your domain.",
                recommendation='Add TXT record: v=spf1 include:_spf.google.com ~all',
                business_impact="Scammers can send fake emails pretending to be your CEO or billing department. This often leads to massive financial fraud (Business Email Compromise) and destroys your brand reputation.",
                module=self.name,
            ))
        
        # Check DMARC
        dmarc_result = self.runner.run(
            f"dig +short _dmarc.{self.target} TXT",
            tool_name="dig", timeout=10, retry=False,
        )
        dmarc_found = False
        if dmarc_result.success and "v=DMARC1" in dmarc_result.stdout:
            dmarc_found = True
            records["DMARC"] = dmarc_result.stdout.strip().strip('"')
        
        if not dmarc_found:
            findings.append(Finding(
                title="Missing DMARC record",
                severity=Severity.MEDIUM,
                description="No DMARC record found. Email spoofing attacks are possible.",
                recommendation='Add TXT record for _dmarc: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com',
                business_impact="Without DMARC enforcement, attackers can successfully bypass recipient spam filters when impersonating your executive team, tricking employees or clients into wiring money.",
                module=self.name,
            ))
        
        # Check DKIM (common selectors)
        dkim_found = False
        for selector in ["default", "google", "k1", "selector1", "selector2", "mail", "dkim"]:
            dkim_result = self.runner.run(
                f"dig +short {selector}._domainkey.{self.target} TXT",
                tool_name="dig", timeout=5, retry=False,
            )
            if dkim_result.success and "v=DKIM1" in dkim_result.stdout:
                dkim_found = True
                records["DKIM"] = f"{selector}._domainkey (found)"
                break
        
        if not dkim_found:
            findings.append(Finding(
                title="No DKIM record found (common selectors)",
                severity=Severity.LOW,
                description="DKIM record not found for common selectors. May use a custom selector.",
                recommendation="Ensure DKIM is configured with your email provider.",
                business_impact="Legitimate emails from your company may be marked as spam or rejected by major providers (Gmail, Outlook), disrupting business communications.",
                module=self.name,
            ))
        
        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=findings,
            data={"records": records, "spf": spf_found, "dmarc": dmarc_found, "dkim": dkim_found},
        )
