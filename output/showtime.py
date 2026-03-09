"""
Showtime Mode — Advanced, aggressive hacker visual dashboard for presentations.
Uses rich.live and rich.layout with spinning ASCII globes, geo-spoofing, and chaos effects.
"""
import os
import time
import random
import threading
from datetime import datetime
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from collections import deque


class ShowtimeDashboard:
    """Advanced Live terminal dashboard for presentations."""
    
    def __init__(self, target: str):
        self.console = Console()
        self.target = target
        self.start_time = time.time()
        
        # State
        self.current_module = "INIT SEQUENCE"
        self.overall_progress = 0
        self.total_modules = 1
        self.findings = []
        
        # Data Streams
        self.raw_logs = deque(maxlen=20)
        self.chaos_stream = deque(maxlen=25)
        self.globe_frames = [
            """
       .---.
     /   |   \\
    |--- | ---|
     \\   |   /
       '---' 
            """,
            """
       .---.
     /  /  |  \\
    |--- --|---|
     \\  \\  |  /
       '---' 
            """,
            """
       .---.
     / |    \\ \\
    |--|----|--|
     \\ |    / /
       '---' 
            """
        ]
        self.globe_idx = 0
        self.current_ip = "127.0.0.1"
        self.geo_loc = "[LOCAL]"
        
        # Threads
        self.running = True
        self.bg_thread = threading.Thread(target=self._generate_chaos)
        self.bg_thread.daemon = True
        self.bg_thread.start()
        
    def _generate_chaos(self):
        """Generates hyper-aggressive fake telemetry and brute-force visuals."""
        while self.running:
            # Spinner animation
            self.globe_idx = (self.globe_idx + 1) % len(self.globe_frames)
            
            # Fake IP hopping every 3 seconds
            if random.random() < 0.05:
                self.current_ip = f"{random.randint(11,250)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
                locations = ["RU", "CN", "BR", "DE", "VN", "TR", "IR"]
                self.geo_loc = f"[{random.choice(locations)} Proxy]"
            
            # Generate Chaos Stream (password crack / hash decryption visuals)
            if random.random() < 0.7:
                hash_val = "".join([random.choice("0123456789ABCDEF") for _ in range(32)])
                status = random.choice(["[bold red]FAIL[/]", "[bold blue]HASH[/]", "[bold yellow]SALT[/]", "[dim]SKIP[/]"])
                line = f"{status} {hash_val[:16]}... -> [dim]bruteforce_thread_{random.randint(10,99)}[/]"
                self.chaos_stream.append(line)
            
            # Occasional "Decrypted" flash
            if random.random() < 0.05:
                chars = "".join([chr(random.randint(33, 126)) for _ in range(12)])
                self.chaos_stream.append(f"[bold green]SUCCESS -> DECRYPTED:[/] {chars}")
                
            time.sleep(0.08)  # Very fast stream
            
    def update_state(self, step: int, total: int, module_name: str):
        self.current_module = module_name.upper()
        self.overall_progress = step
        self.total_modules = total
        self.add_log(f"[*] INITIATING PROTOCOL: {self.current_module}")
        
    def add_log(self, text: str, style: str = "bold white"):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.raw_logs.append(f"[{style}][{timestamp}] {text}[/]")
        
    def add_finding(self, severity: str, title: str):
        self.findings.append((severity, title))
        if severity in ("CRITICAL", "HIGH"):
            self.add_log(f"[!] CRITICAL VULNERABILITY BREACHED: {title}", "bold red blink")
            self.chaos_stream.append(f"\n[bold red blink]!!! SYSTEM BREACH DETECTED: {severity} !!![/]\n")
        else:
            self.add_log(f"[+] INTELLIGENCE GATHERED: {title}", "bold yellow")

    def _build_header(self) -> Panel:
        elapsed = time.time() - self.start_time
        
        grid = Table.grid(expand=True)
        grid.add_column(justify="left", ratio=1)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="right", ratio=1)
        
        proxy_info = f"[dim]ROUTING:[/] [bold green]{self.current_ip}[/] {self.geo_loc}"
        
        grid.add_row(
            f"[bold cyan]TARGET LOCK:[/] [bold white]{self.target}[/]",
            "[bold red blink]⚠️  OFFENSIVE SECURITY ENGINE ACTIVE ⚠️[/]",
            f"[bold cyan]T-MINUS:[/] [bold white]{elapsed:.1f}s[/] | {proxy_info}"
        )
        return Panel(grid, style="bold red")

    def _build_radar(self) -> Panel:
        """Shows spinning ASCII globe and Target info."""
        globe = self.globe_frames[self.globe_idx]
        text = f"[bold green]{globe}[/]\n\n[bold cyan]TARGET:[/] {self.target}\n[bold cyan]STATUS:[/] [bold yellow]INFILTRATING[/]"
        return Panel(Align.center(text, vertical="middle"), title="[bold]Uplink", border_style="cyan")

    def _build_progress(self) -> Panel:
        table = Table.grid(padding=(1, 2), expand=True)
        table.add_column("Key", justify="right", style="cyan bold")
        table.add_column("Value", justify="left")
        
        pct = (self.overall_progress / max(1, self.total_modules)) * 100
        bar_len = 30
        filled = int((pct / 100) * bar_len)
        bar = "█" * filled + "░" * (bar_len - filled)
        
        table.add_row("CURRENT OP:", f"[bold white]{self.current_module}[/]")
        table.add_row("INFILTRATION:", f"[bold red]{bar}[/] {pct:.0f}%")
        table.add_row("THREADS:", f"[bold yellow]{random.randint(24, 64)} ACTIVE[/]")
        
        return Panel(table, title="[bold]Operation Matrix", border_style="cyan")

    def _build_findings(self) -> Panel:
        table = Table(expand=True, show_header=True, header_style="bold black on red", box=None)
        table.add_column("SEV", width=6)
        table.add_column("DATA BREACH / INTELLIGENCE")
        
        shown = self.findings[-7:]
        styles = {
            "CRITICAL": "bold white on red blink",
            "HIGH": "bold red",
            "MEDIUM": "bold yellow",
            "LOW": "bold blue",
            "INFO": "dim white"
        }
        
        for sev, title in shown:
            table.add_row(f"[{styles.get(sev, 'white')}]{sev}[/]", f"[bold white]{title}[/]")
            
        return Panel(table, title="[bold red]Payloads Recovered", border_style="red")

    def _build_logs(self) -> Panel:
        text = "\n".join(list(self.raw_logs))
        return Panel(text, title="[bold green]Command & Control (C2) Stream", border_style="green")
        
    def _build_chaos(self) -> Panel:
        text = "\n".join(list(self.chaos_stream))
        return Panel(text, title="[bold yellow]Decryption / Brute-Force Matrix", border_style="yellow")

    def get_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main")
        )
        layout["main"].split_column(
            Layout(name="top", size=10),
            Layout(name="middle"),
            Layout(name="bottom", size=12)
        )
        
        # Top: Radar/Globe + Progress
        layout["top"].split_row(
            Layout(name="radar", ratio=1),
            Layout(name="progress", ratio=2)
        )
        
        # Middle: Findings
        layout["middle"].update(self._build_findings())
        
        # Bottom: Logs + Chaos Matrix
        layout["bottom"].split_row(
            Layout(name="logs", ratio=3),
            Layout(name="chaos", ratio=2)
        )
        
        layout["header"].update(self._build_header())
        layout["radar"].update(self._build_radar())
        layout["progress"].update(self._build_progress())
        layout["logs"].update(self._build_logs())
        layout["chaos"].update(self._build_chaos())
        
        return layout

    def stop(self):
        self.running = False
        if self.bg_thread.is_alive():
            self.bg_thread.join(timeout=1.0)
