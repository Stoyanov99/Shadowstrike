#!/usr/bin/env python3
"""
ShadowStrike — Automated Penetration Testing Toolkit
Main CLI entry point. This is the brain that orchestrates all modules.

Usage:
    python -m shadowstrike scan <target>
    python -m shadowstrike recon <target>
    python -m shadowstrike vuln <target>
    python -m shadowstrike headers <target>
"""
import sys
import os
import time
import argparse

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shadowstrike.core.runner import Runner
from shadowstrike.core.opsec import check_opsec
from shadowstrike.output.console import ShadowConsole
from shadowstrike.output.report import ReportGenerator
from shadowstrike.output.showtime import ShowtimeDashboard
from shadowstrike.modules.subdomain import SubdomainModule
from shadowstrike.modules.portscan import PortScanModule
from shadowstrike.modules.techdetect import TechDetectModule
from shadowstrike.modules.headers import HeadersModule
from shadowstrike.modules.vulnscan import VulnScanModule
from shadowstrike.modules.secrets import SecretScanModule
from shadowstrike.modules.dirbrute import DirBruteModule
from shadowstrike.modules.emailsec import EmailSecModule
from shadowstrike.modules.breach import BreachScanModule
from shadowstrike.modules.external import AutoReconModule, SpiderFootModule, BBOTModule, SSLScanModule


# Module registry — order matters (smart pipeline)
ALL_MODULES = [
    ("bbot", BBOTModule),
    ("subdomains", SubdomainModule),
    ("spiderfoot", SpiderFootModule),
    ("portscan", PortScanModule),
    ("techdetect", TechDetectModule),
    ("autorecon", AutoReconModule),
    ("headers", HeadersModule),
    ("sslscan", SSLScanModule),
    ("secrets", SecretScanModule),
    ("dirbrute", DirBruteModule),
    ("vulnscan", VulnScanModule),
    ("emailsec", EmailSecModule),
    ("breach", BreachScanModule),
]

SCAN_PROFILES = {
    "scan": ["bbot", "subdomains", "spiderfoot", "portscan", "techdetect", "headers", "sslscan", "secrets", "dirbrute", "vulnscan", "emailsec", "breach"],
    "recon": ["bbot", "subdomains", "spiderfoot", "portscan", "techdetect", "headers", "emailsec", "breach"],
    "vuln": ["headers", "sslscan", "secrets", "vulnscan"],
    "headers": ["headers"],
    "osint": ["spiderfoot", "breach"],
    "deep": ["bbot", "autorecon", "vulnscan", "breach"],
    "quick": ["headers", "techdetect", "secrets", "breach"],
    "showtime": ["subdomains", "portscan", "techdetect", "headers", "secrets", "dirbrute", "vulnscan", "emailsec", "breach"],
}


def run_scan(target: str, profile: str = "scan", output_dir: str = None, notes: str = ""):
    """Main scan orchestrator — runs modules with smart decision-making."""
    
    console = ShadowConsole()
    console.banner()
    
    # Strip protocol if provided
    target = target.replace("https://", "").replace("http://", "").rstrip("/")
    
    # Setup output directory
    if not output_dir:
        output_dir = os.path.join("results", target.replace(".", "_"))
    os.makedirs(output_dir, exist_ok=True)
    
    runner = Runner(output_dir=output_dir)
    console.target_info(target)
    
    # OPSEC CHECK - Warn user about their IP footprint before scanning
    check_opsec(console)
    
    # Get modules for this profile
    module_names = SCAN_PROFILES.get(profile, SCAN_PROFILES["scan"])
    modules_to_run = [(name, cls) for name, cls in ALL_MODULES if name in module_names]
    
    total = len(modules_to_run)
    all_findings = []
    all_results = []
    scan_data = {}  # Shared data between modules
    start_time = time.time()
    
    if profile == "showtime":
        from rich.live import Live
        dashboard = ShowtimeDashboard(target)
        
        with Live(dashboard.get_layout(), refresh_per_second=10) as live:
            for step, (name, ModuleClass) in enumerate(modules_to_run, 1):
                module = ModuleClass(runner=runner, target=target, output_dir=output_dir)
                dashboard.update_state(step, total, module.description)
                live.update(dashboard.get_layout())
                
                if not module.check_requirements():
                    dashboard.add_log(f"[-] Module skipped (missing tools)", "yellow")
                    time.sleep(1) # Visual effect
                    continue
                
                dashboard.add_log(f"[*] Executing payloads...", "cyan")
                try:
                    result = module.run()
                    all_results.append(result)
                    
                    if result.success:
                        dashboard.add_log(f"[+] Payloads executed successfully ({result.duration:.1f}s)", "green")
                        for f in result.findings:
                            dashboard.add_finding(f.severity.value, f.title)
                            all_findings.append(f)
                        
                        # Fake longer processing for fast modules to look cool
                        if result.duration < 1.5:
                            time.sleep(1.5)
                            
                    else:
                        dashboard.add_log(f"[-] Execution failed: {result.error}", "red")
                        time.sleep(1)
                except Exception as e:
                    dashboard.add_log(f"[x] Critical engine failure: {str(e)}", "bold red")
                    time.sleep(2)
                    
            dashboard.update_state(total, total, "REPORT GENERATION")
            dashboard.add_log(f"[*] Compiling intelligence report...", "cyan")
            time.sleep(2)  # Artificial dramatically long report gen
            
            # Generate the true report after all modules
            report_gen = ReportGenerator()
            report_path, pdf_path = report_gen.generate(target, all_findings, all_results, output_dir, notes=notes)
            
            dashboard.add_log(f"[+] HTML Report generated: {report_path}", "bold green")
            if pdf_path:
                dashboard.add_log(f"[+] PDF Report exported to Desktop", "bold yellow")
            time.sleep(2)  # Let client read it
            
        dashboard.stop()
        
        total_duration = time.time() - start_time
        print(f"\n[+] Operation complete in {total_duration:.1f}s. Report: {report_path}")
        return all_findings, report_path

    # Standard Console Logic (for non-showtime profiles)
    for step, (name, ModuleClass) in enumerate(modules_to_run, 1):
        module = ModuleClass(runner=runner, target=target, output_dir=output_dir)
        
        console.module_start(step, total, module.icon, module.description)
        
        # Check requirements
        if not module.check_requirements():
            console.module_skip("tool not installed")
            continue
        
        # Run module
        try:
            result = module.run()
            all_results.append(result)
            
            if result.success:
                # Summary text
                if result.findings:
                    finding_counts = {}
                    for f in result.findings:
                        finding_counts[f.severity.value] = finding_counts.get(f.severity.value, 0) + 1
                    summary_parts = []
                    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                        if sev in finding_counts:
                            summary_parts.append(f"{finding_counts[sev]} {sev.lower()}")
                    summary = ", ".join(summary_parts)
                else:
                    summary = "Clean ✓"
                
                console.module_done(True, summary, result.duration)
                all_findings.extend(result.findings)
                
                # SMART DECISIONS based on results
                if name == "techdetect" and result.data.get("is_wordpress"):
                    console.smart_action("WordPress detected → WPScan recommended")
                
                if name == "portscan":
                    open_ports = result.data.get("ports", [])
                    web_ports = [p for p in open_ports if p["port"] in (80, 443, 8080, 8443)]
                    if not web_ports:
                        console.smart_action("No web ports open → skipping web modules")
                
                # Store data for cross-module intelligence
                scan_data[name] = result.data
                
            else:
                console.module_done(False, result.error, result.duration)
        
        except Exception as e:
            console.module_done(False, str(e))
    
    total_duration = time.time() - start_time
    
    # Display findings
    print()
    console.findings_table(all_findings)
    console.summary(all_findings, total_duration)
    
    # Generate HTML report
    report_gen = ReportGenerator()
    report_path, pdf_path = report_gen.generate(target, all_findings, all_results, output_dir, notes=notes)
    console.report_saved(report_path)
    if pdf_path:
        console.print(f"[bold yellow]💾 PDF Version generated on Desktop:[/] {pdf_path}")
    
    return all_findings, report_path


def interactive_wizard():
    """Interactive Command Center when run without arguments."""
    from rich.prompt import Prompt, Confirm
    import webbrowser
    
    console = ShadowConsole()
    console.banner()
    
    console.print("\n[bold cyan]⚡ SHADOWSTRIKE INTERACTIVE COMMAND CENTER[/]")
    console.print("[dim]Welcome, Operator. Configure the penetration payload.[/]\n")
    
    target = Prompt.ask("[bold yellow]🎯 TARGET[/] (Domain or IP)", default="auravoice.uk")
    if not target:
        console.print("[red]Target is required. Aborting sequence.[/]")
        sys.exit(1)
        
    system_notes = Prompt.ask("[bold yellow]📝 SYSTEM NOTES[/] (e.g. WordPress, Auth API, or client instructions)", default="")
    
    profile_choices = list(SCAN_PROFILES.keys())
    console.print("\n[dim]AVAILABLE PROFILES: " + ", ".join(profile_choices) + "[/]")
    profile = Prompt.ask(
        "[bold yellow]⚙️  INTELLIGENCE LEVEL[/]",
        choices=profile_choices,
        default="quick"
    )
    
    auto_open = Confirm.ask("\n[bold yellow]🌐 AUTO-OPEN FINAL REPORT IN BROWSER?[/]", default=True)
    
    console.print("\n[bold green blink]Initiating Offensive Sequence...[/]\n")
    time.sleep(1)
    
    findings, report_path = run_scan(target=target, profile=profile, notes=system_notes)
    
    if auto_open and report_path:
        console.print(f"\n[bold cyan][*] Transmitting intelligence to browser -> {report_path}[/]")
        try:
            webbrowser.open(f"file://{os.path.abspath(report_path)}")
        except Exception as e:
            console.print(f"[dim]Failed to auto-open browser: {e}[/]")

    # Launch the continuous shell
    interactive_shell(report_path)

def interactive_shell(report_path: str):
    """The continuous slash command interface for AI analysis."""
    from rich.prompt import Prompt
    import webbrowser
    
    from shadowstrike.core.ai_agent import analyze_report, chat_with_ai
    import subprocess
    
    console = ShadowConsole()
    console.print("\n[bold magenta]🤖 SHADOW AI (PentestGPT Mode): Awaiting commands.[/] Type [bold]/help[/] for options.")
    
    # Store conversation history for multi-turn chat
    messages = [
        {"role": "system", "content": "You are Shadow AI, an elite offensive security AI agent (similar to PentestGPT) built into the ShadowStrike CLI. Help the operator with their pentesting tasks, providing brief, highly technical answers and actionable terminal commands."}
    ]
    
    while True:
        try:
            cmd = Prompt.ask("\n[bold red]shadowstrike[/][white]>[/]")
            cmd = cmd.strip()
            
            if not cmd:
                continue
            
            if cmd in ["/exit", "/quit", "exit"]:
                console.print("[dim]Terminating session. Goodbye, Operator.[/]")
                break
            
            elif cmd == "/help":
                console.print("\n[bold cyan]Available Commands:[/]")
                console.print("  [bold yellow]!<cmd>[/]     - Execute a terminal command directly (e.g., !nmap -p 80 target.com)")
                console.print("  [bold yellow]/analyze[/] - AI analyzes the latest scan and provides attack instructions")
                console.print("  [bold yellow]/report[/]  - Re-open the HTML report in your browser")
                console.print("  [bold yellow]/clear[/]   - Clear the terminal screen")
                console.print("  [bold yellow]/exit[/]    - Terminate ShadowStrike")
                
            elif cmd == "/analyze":
                if not report_path:
                    console.print("[red]No report available to analyze. Run a scan first.[/]")
                    continue
                console.print("\n[bold magenta blink]🤖 Shadow AI is reading the latest report...[/]")
                from shadowstrike.core.ai_agent import analyze_report
                analyze_report(report_path, console)
                
            elif cmd == "/report":
                if report_path:
                    console.print(f"[*] Opening: {report_path}")
                    webbrowser.open(f"file://{os.path.abspath(report_path)}")
                else:
                    console.print("[red]No report available.[/]")
                    
            elif cmd == "/clear":
                os.system('cls' if os.name == 'nt' else 'clear')
                console.banner()
                
            elif cmd.startswith("/"):
                console.print(f"[red]Unknown command '{cmd}'. Type /help for options.[/]")
                
            elif cmd.startswith("!"):
                # Direct shell execution
                shell_cmd = cmd[1:].strip()
                if not shell_cmd:
                    continue
                    
                console.print(f"[dim]⚡ Executing: {shell_cmd}[/]")
                try:
                    # Run the command with real-time output
                    process = subprocess.Popen(
                        shell_cmd, 
                        shell=True, 
                        text=True, 
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        bufsize=1,
                        env={**os.environ, "PATH": f"/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:{os.environ.get('PATH', '')}"}
                    )
                    
                    output_text = ""
                    for line in process.stdout:
                        console.print(line, end="")
                        output_text += line
                        
                    process.wait()
                    
                    if output_text.strip():
                        # Silently add the command and its result to the AI context
                        # We use a 'user' message but frame it as a system action the user took
                        context_msg = f"[System Context] The operator just executed the following terminal command:\n`{shell_cmd}`\n\nOutput:\n```\n{output_text}\n```"
                        messages.append({"role": "user", "content": context_msg})
                        # We also append a dummy assistant response so the history stays balanced if needed, 
                        # or let the next actual user prompt continue naturally.
                        messages.append({"role": "assistant", "content": "Confirmed. I have logged the output. Awaiting further instructions."})
                        console.print("[dim]\n[✓] Results logged to Shadow AI context.[/]")
                
                except Exception as e:
                    console.print(f"[bold red]Shell Error:[/] {str(e)}")
                    
            else:
                # Treat as a direct AI conversation
                messages.append({"role": "user", "content": cmd})
                
                console.print("\n[dim]🤖 Cognitive engine processing...[/]")
                response_text = chat_with_ai(messages, console)
                
                if response_text:
                    messages.append({"role": "assistant", "content": response_text})
                
        except KeyboardInterrupt:
            console.print("\n[dim]Terminating session. Goodbye, Operator.[/]")
            break
        except Exception as e:
            console.print(f"[bold red]System Error:[/] {str(e)}")


def main():
    parser = argparse.ArgumentParser(
        prog="shadowstrike",
        description="⚡ ShadowStrike — Automated Penetration Testing Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan profiles:
  scan      Full scan (all fast modules)
  recon     Reconnaissance only
  vuln      Vulnerability scan
  headers   Security headers check only
  osint     OSINT via SpiderFoot
  deep      Deep scan using AutoRecon & BBOT (slow)
  quick     Quick scan (headers, tech, secrets)
  showtime  🔴 CLI Presentation Mode (live dashboard)
  ai        🤖 Launch Shadow AI interactive shell directly

Examples:
  python -m shadowstrike scan example.com
  python -m shadowstrike osint example.com
  python -m shadowstrike ai
        """,
    )
    
    parser.add_argument("profile", choices=["scan", "recon", "vuln", "headers", "osint", "deep", "quick", "showtime", "ai"],
                        help="Scan profile to use")
    parser.add_argument("target", nargs="?", help="Target domain or IP (optional for 'ai' profile)")
    parser.add_argument("--output", "-o", help="Output directory", default=None)
    
    if len(sys.argv) == 1:
        # Launch interactive wizard
        interactive_wizard()
        sys.exit(0)
        
    args = parser.parse_args()
    
    if args.profile == "ai":
        # Launch AI shell directly without scanning
        print()
        interactive_shell(None)
    else:
        if not args.target:
            parser.error("The following arguments are required: target (unless using 'ai' profile)")
            
        print()
        _, report_path = run_scan(target=args.target, profile=args.profile, output_dir=args.output)
        
        # Launch the continuous shell after scan
        interactive_shell(report_path)

if __name__ == "__main__":
    main()
