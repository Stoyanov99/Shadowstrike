"""Tech Detection Module — Identifies technologies used by the target."""
import re
import urllib.request
import ssl
from .base import BaseModule, ModuleResult, Finding, Severity


class TechDetectModule(BaseModule):
    name = "techdetect"
    description = "Technology Detection"
    icon = "🏷️"
    
    TECH_SIGNATURES = {
        # Frontend frameworks
        "React": [r'react\.', r'__NEXT_DATA__', r'_reactRoot', r'data-reactroot'],
        "Vue.js": [r'vue\.js', r'vue\.min\.js', r'__vue__', r'v-app'],
        "Angular": [r'angular\.', r'ng-version', r'ng-app'],
        "Svelte": [r'svelte', r'__svelte'],
        # Build tools
        "Vite": [r'vite\.svg', r'/@vite', r'vite'],
        "Webpack": [r'webpack', r'webpackJsonp', r'bundle\.js'],
        "Next.js": [r'_next/', r'__NEXT', r'next\.js'],
        "Nuxt": [r'_nuxt/', r'__nuxt'],
        # CSS
        "TailwindCSS": [r'tailwindcss', r'tailwind\.'],
        "Bootstrap": [r'bootstrap\.', r'bootstrap\.min'],
        # CMS
        "WordPress": [r'wp-content', r'wp-includes', r'wordpress'],
        "Drupal": [r'drupal\.', r'sites/default'],
        "Joomla": [r'joomla', r'/administrator/'],
        "Shopify": [r'shopify', r'cdn\.shopify'],
        # Server
        "Nginx": [r'nginx'],
        "Apache": [r'apache'],
        "Vercel": [r'vercel', r'x-vercel'],
        "Netlify": [r'netlify'],
        "Cloudflare": [r'cloudflare', r'cf-ray'],
        # JavaScript libraries
        "jQuery": [r'jquery\.', r'jquery\.min\.js'],
        "Lodash": [r'lodash'],
        "Lenis": [r'lenis'],
        "GSAP": [r'gsap\.', r'ScrollTrigger'],
        "Three.js": [r'three\.', r'three\.min\.js'],
    }
    
    def check_requirements(self) -> bool:
        return True  # Uses Python stdlib
    
    def run(self) -> ModuleResult:
        findings = []
        detected = []
        
        url = f"https://{self.target}"
        
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            })
            resp = urllib.request.urlopen(req, timeout=15, context=ctx)
            html = resp.read().decode("utf-8", errors="ignore")
            headers = dict(resp.headers)
        except Exception as e:
            return ModuleResult(
                module_name=self.name, success=False,
                error=f"Could not fetch page: {e}",
            )
        
        # Combine all text to search
        search_text = html + " " + " ".join(f"{k}:{v}" for k, v in headers.items())
        search_text_lower = search_text.lower()
        
        # Check signatures
        for tech, patterns in self.TECH_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, search_text_lower):
                    if tech not in detected:
                        detected.append(tech)
                    break
        
        # Check for WordPress specifically (triggers WPScan)
        is_wordpress = "WordPress" in detected
        
        if detected:
            findings.append(Finding(
                title=f"{len(detected)} technologies detected",
                severity=Severity.INFO,
                description="Technologies: " + ", ".join(detected),
                module=self.name,
            ))
        
        if is_wordpress:
            findings.append(Finding(
                title="WordPress CMS detected",
                severity=Severity.INFO,
                description="WordPress detected. WPScan module should be run for detailed analysis.",
                module=self.name,
            ))
        
        return ModuleResult(
            module_name=self.name,
            success=True,
            findings=findings,
            data={
                "technologies": detected,
                "is_wordpress": is_wordpress,
                "count": len(detected),
            },
        )
