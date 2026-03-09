"""
OPSEC (Operational Security) Module
Checks the user's public IP address before starting a scan to prevent accidental
exposure of their home/office IP address to the target's logs.
"""
import httpx
from rich.panel import Panel
from rich.prompt import Confirm
import sys

def check_opsec(console):
    """
    Fetches the current public IP, ISP, and Country.
    Displays a warning if a VPN is not detected (based on ISP or just as a general warning).
    Requires explicit confirmation to proceed.
    """
    console.print("\n[bold yellow]🛡️  Performing Pre-Flight OPSEC Check...[/bold yellow]")
    
    try:
        # Fetch IP data from a fast, free API
        with httpx.Client(timeout=5.0) as client:
            response = client.get("https://ipapi.co/json/")
            response.raise_for_status()
            data = response.json()
            
        ip = data.get("ip", "Unknown")
        city = data.get("city", "Unknown")
        country = data.get("country_name", "Unknown")
        org = data.get("org", "Unknown") # ISP
        
        warning_msg = (
            f"[bold red]WARNING: You are about to launch an offensive scan![/bold red]\n\n"
            f"Your current public footprint is visible to the target:\n"
            f"📍 [bold]IP Address:[/] {ip}\n"
            f"🌍 [bold]Location:[/] {city}, {country}\n"
            f"🏢 [bold]ISP/Org:[/] {org}\n\n"
            f"[dim]If this is your home or office connection, the target will log this IP.\n"
            f"Professional penetration testers always use a VPN (e.g., ProtonVPN, NordVPN)[/dim]"
        )
        
        if HAS_RICH:
            console.console.print(Panel(
                warning_msg,
                title="⚠️ OPSEC ALERT",
                border_style="red"
            ))
        else:
            print("\n⚠️ OPSEC ALERT ⚠️")
            print(f"IP: {ip} | Location: {country} | ISP: {org}")
            print("WARNING: This IP will be logged by the target.")
            
        # Ask for confirmation
        if HAS_RICH:
            proceed = Confirm.ask("\n[bold red]Are you absolutely sure you want to attack from this IP?[/bold red]")
        else:
            ans = input("\nAre you absolutely sure you want to attack from this IP? (y/N): ")
            proceed = ans.lower() == 'y'
            
        if not proceed:
            if HAS_RICH:
                console.console.print("[dim]Scan aborted for OPSEC reasons. Connect to a VPN and try again.[/dim]")
            else:
                print("Scan aborted. Connect to a VPN and try again.")
            sys.exit(0)
            
        if HAS_RICH:
            console.console.print("[bold green]✓ OPSEC overridden. Engaging target...[/bold green]\n")
        else:
            print("✓ OPSEC overridden. Engaging target...\n")

    except Exception as e:
        # If the API fails, we still warn the user to be safe
        if HAS_RICH:
            console.console.print(Panel(
                f"[yellow]Could not verify public IP: {str(e)}\nMake sure your VPN is active before proceeding.[/yellow]",
                title="⚠️ OPSEC Warning",
                border_style="yellow"
            ))
            proceed = Confirm.ask("\nProceed without IP verification?")
            if not proceed:
                sys.exit(0)
        else:
            print("Could not verify OPSEC. Proceed at your own risk.")

# Import HAS_RICH to use it in the check
try:
    from rich.console import Console
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
