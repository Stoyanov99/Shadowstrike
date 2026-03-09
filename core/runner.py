"""
Core runner — Executes external tools with retry logic and smart error handling.
Acts like a brain that runs terminal commands, reads output, and decides next steps.
"""
import subprocess
import shutil
import time
import json
import os
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console

console = Console()


@dataclass
class ToolResult:
    """Result from running an external tool."""
    tool: str
    command: str
    stdout: str
    stderr: str
    exit_code: int
    duration: float
    success: bool
    retries: int = 0


class Runner:
    """
    Smart command runner with retry logic.
    
    If a tool fails → retries with different parameters.
    If a tool is missing → warns and skips gracefully.
    """
    
    MAX_RETRIES = 3
    TIMEOUT = 300  # 5 minutes max per tool
    
    def __init__(self, output_dir: str = "results"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def is_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed and available."""
        return shutil.which(tool_name) is not None
    
    def run(
        self,
        command: str,
        tool_name: str = "unknown",
        timeout: Optional[int] = None,
        retry: bool = True,
        retry_commands: Optional[list] = None,
    ) -> ToolResult:
        """
        Run a command with smart retry logic.
        
        Args:
            command: The shell command to run
            tool_name: Name of the tool (for logging)
            timeout: Max seconds to wait
            retry: Whether to retry on failure
            retry_commands: Alternative commands to try on failure
        """
        timeout = timeout or self.TIMEOUT
        retry_commands = retry_commands or []
        
        # Try the main command first
        result = self._execute(command, tool_name, timeout)
        
        if result.success:
            return result
        
        # If failed and retry enabled, try alternatives
        if retry and retry_commands:
            for i, alt_cmd in enumerate(retry_commands):
                console.print(f"  [yellow]↳ Retry {i+1}/{len(retry_commands)}: trying alternative...[/yellow]")
                result = self._execute(alt_cmd, tool_name, timeout)
                result.retries = i + 1
                if result.success:
                    return result
        
        # If still failed, retry the original with longer timeout
        if retry and not result.success:
            console.print(f"  [yellow]↳ Final retry with extended timeout...[/yellow]")
            result = self._execute(command, tool_name, timeout * 2)
            result.retries += 1
        
        return result
    
    def _execute(self, command: str, tool_name: str, timeout: int) -> ToolResult:
        """Execute a single command and capture output."""
        start = time.time()
        
        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, "PATH": f"/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:{os.environ.get('PATH', '')}"},
            )
            
            duration = time.time() - start
            
            return ToolResult(
                tool=tool_name,
                command=command,
                stdout=proc.stdout,
                stderr=proc.stderr,
                exit_code=proc.returncode,
                duration=duration,
                success=proc.returncode == 0,
            )
        
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=tool_name,
                command=command,
                stdout="",
                stderr=f"TIMEOUT: Command exceeded {timeout}s",
                exit_code=-1,
                duration=timeout,
                success=False,
            )
        except Exception as e:
            return ToolResult(
                tool=tool_name,
                command=command,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                duration=time.time() - start,
                success=False,
            )
    
    def save_output(self, result: ToolResult, filename: str):
        """Save tool output to a file."""
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w") as f:
            f.write(f"# {result.tool} Output\n")
            f.write(f"# Command: {result.command}\n")
            f.write(f"# Exit Code: {result.exit_code}\n")
            f.write(f"# Duration: {result.duration:.1f}s\n")
            f.write(f"# Retries: {result.retries}\n\n")
            f.write(result.stdout)
            if result.stderr:
                f.write(f"\n\n# STDERR:\n{result.stderr}")
        return filepath
