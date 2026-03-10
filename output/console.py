"""
ShadowStrike Console — Beautiful terminal output with Rich library.
"""
import os
import time
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.text import Text
    from rich.columns import Columns
    from rich.live import Live
    from rich.layout import Layout
    from rich import box
    import threading
    import random
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


class ShadowConsole:
    """Beautiful terminal output for ShadowStrike."""
    
    def __init__(self):
        self.console = Console() if HAS_RICH else None
        self.start_time = None
        self._live = None
        self._stop_event = None
        self._thread = None
        self._current_module_name = ""
        self._current_step = 0
        self._total_steps = 0
        
    def print(self, text: str = "", **kwargs):
        """Expose print method."""
        if HAS_RICH:
            self.console.print(text, **kwargs)
        else:
            print(text, **kwargs)
    
    def banner(self):
        """Show the ShadowStrike ASCII banner."""
        banner_text = """
   ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
   ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
   ██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
   ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
   ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
   ███████║   ██║   ██║  ██║██║██║  ██╗███████╗
   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝"""
        
        if HAS_RICH:
            self.console.print(Panel(
                Text(banner_text, style="bold red"),
                subtitle="[dim]Automated Penetration Testing Toolkit v1.0[/dim]",
                border_style="red",
                box=box.DOUBLE,
            ))
        else:
            print(banner_text)
            print("  Automated Penetration Testing Toolkit v1.0")
    
    def target_info(self, target: str):
        """Display target information."""
        self.start_time = time.time()
        if HAS_RICH:
            table = Table(box=box.ROUNDED, border_style="bright_cyan", show_header=False, padding=(0, 2))
            table.add_column("Key", style="bold cyan")
            table.add_column("Value", style="white")
            table.add_row("🎯 Target", target)
            table.add_row("📅 Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            table.add_row("🔧 Mode", "Full Scan")
            self.console.print(table)
            self.console.print()
        else:
            print(f"\n🎯 Target: {target}")
            print(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    def _chaos_worker(self):
        """Background thread that prints fake hacking text while modules run."""
        chars = "0123456789ABCDEFabcdef"
        actions = ["Decrypting block", "Bypassing ACL", "Injecting payload", "Spoofing IP", "Cracking hash", "Extracting keys"]
        
        while not self._stop_event.is_set():
            time.sleep(random.uniform(0.05, 0.2))
            
            if random.random() > 0.3:
                # Print hex dump line
                hexa = "".join(random.choice(chars) for _ in range(32))
                self.console.print(f"      [dim green]0x{random.randint(1000,9999):04x}  {hexa[:16]} {hexa[16:]}  ...[/dim green]")
            else:
                # Print action
                ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"
                action = random.choice(actions)
                self.console.print(f"      [dim cyan][~] {action} {ip}...[/dim cyan]")

    def module_start(self, step: int, total: int, icon: str, name: str):
        """Show module starting and begin chaos stream."""
        self._current_module_name = name
        self._current_step = step
        self._total_steps = total
        
        if HAS_RICH:
            self.console.print(f"\n[bold white][{step}/{total}][/bold white] {icon} [bold yellow]{name}[/bold yellow] [dim]executing scan sequence...[/dim]")
            
            # Start background chaos thread
            self._stop_event = threading.Event()
            self._thread = threading.Thread(target=self._chaos_worker, daemon=True)
            self._thread.start()
        else:
            print(f"  [{step}/{total}] {icon} {name} ...", end="", flush=True)
    
    def module_done(self, success: bool, summary: str = "", duration: float = 0):
        """Show module completed and stop chaos stream."""
        # Stop background thread first
        if self._thread and self._thread.is_alive():
            self._stop_event.set()
            self._thread.join()
            
        dur = f"({duration:.1f}s)" if duration > 0 else ""
        if success:
            if HAS_RICH:
                self.console.print(f"[green]✅ {self._current_module_name} completed: {summary} {dur}[/green]")
            else:
                print(f" ✅ {summary} {dur}")
        else:
            if HAS_RICH:
                self.console.print(f"[red]❌ {self._current_module_name} failed {dur}[/red]")
            else:
                print(f" ❌ Failed {dur}")
    
    def module_skip(self, reason: str = "not available"):
        """Show module skipped."""
        if HAS_RICH:
            self.console.print(f"[yellow]⏭️  Skipped ({reason})[/yellow]")
        else:
            print(f" ⏭️ Skipped ({reason})")
    
    def smart_action(self, message: str):
        """Show smart action taken by the tool."""
        if HAS_RICH:
            self.console.print(f"      [yellow]↳ {message}[/yellow]")
        else:
            print(f"      ↳ {message}")
    
    def findings_table(self, all_findings: list):
        """Display all findings in a beautiful table."""
        if not all_findings:
            if HAS_RICH:
                self.console.print(Panel("[green]✅ No security issues found![/green]", border_style="green"))
            return
        
        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        all_findings.sort(key=lambda f: severity_order.get(f.severity.value, 5))
        
        if HAS_RICH:
            table = Table(
                title="🔍 Security Findings",
                box=box.ROUNDED,
                border_style="bright_yellow",
                show_lines=True,
            )
            table.add_column("#", style="dim", width=3)
            table.add_column("Severity", width=10)
            table.add_column("Finding", min_width=30)
            table.add_column("Module", style="dim", width=12)
            
            severity_colors = {
                "CRITICAL": "bold white on red",
                "HIGH": "bold red",
                "MEDIUM": "bold yellow",
                "LOW": "bold blue",
                "INFO": "dim white",
            }
            
            for i, finding in enumerate(all_findings, 1):
                sev_style = severity_colors.get(finding.severity.value, "white")
                table.add_row(
                    str(i),
                    Text(f"{finding.icon} {finding.severity.value}", style=sev_style),
                    finding.title,
                    finding.module,
                )
            
            self.console.print(table)
        else:
            print("\n🔍 Security Findings:")
            for i, f in enumerate(all_findings, 1):
                print(f"  {i}. [{f.severity.value}] {f.title}")
    
    def summary(self, all_findings: list, total_duration: float):
        """Display final summary."""
        criticals = sum(1 for f in all_findings if f.severity.value == "CRITICAL")
        highs = sum(1 for f in all_findings if f.severity.value == "HIGH")
        mediums = sum(1 for f in all_findings if f.severity.value == "MEDIUM")
        lows = sum(1 for f in all_findings if f.severity.value == "LOW")
        infos = sum(1 for f in all_findings if f.severity.value == "INFO")
        
        if HAS_RICH:
            summary_table = Table(box=box.ROUNDED, border_style="bright_green", show_header=False)
            summary_table.add_column("", width=20)
            summary_table.add_column("", width=10)
            summary_table.add_row("🔴 Critical", str(criticals))
            summary_table.add_row("🟠 High", str(highs))
            summary_table.add_row("🟡 Medium", str(mediums))
            summary_table.add_row("🔵 Low", str(lows))
            summary_table.add_row("⚪ Info", str(infos))
            summary_table.add_row("─" * 15, "─" * 5)
            summary_table.add_row("📊 Total", str(len(all_findings)))
            summary_table.add_row("⏱️  Duration", f"{total_duration:.1f}s")
            
            self.console.print(Panel(summary_table, title="📋 Summary", border_style="bright_green"))
        else:
            print(f"\n📋 Summary: {criticals}C {highs}H {mediums}M {lows}L {infos}I — Total: {len(all_findings)} in {total_duration:.1f}s")
    
    def report_saved(self, path: str):
        """Show report save location."""
        if HAS_RICH:
            self.console.print(f"\n  [bold green]📄 Report saved → {path}[/bold green]\n")
        else:
            print(f"\n  📄 Report saved → {path}\n")
