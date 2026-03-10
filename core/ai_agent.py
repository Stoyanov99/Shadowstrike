"""
ShadowStrike AI Agent
Connects to Google Gemini API (3.1 Pro) to analyze reports and provide actionable attack commands.
"""
import os
import json
import time
from bs4 import BeautifulSoup
import httpx
from rich.panel import Panel
from rich.markdown import Markdown

# API Endpoint for Google Gemini
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-pro-preview:generateContent"

def load_env_key():
    """Manually load API key from .env file if it exists."""
    key = os.environ.get("SHADOWSTRIKE_AI_KEY")
    if not key and os.path.exists(".env"):
        with open(".env", "r") as f:
            for line in f:
                if line.startswith("SHADOWSTRIKE_AI_KEY="):
                    key = line.split("=", 1)[1].strip()
                    break
    return key

def extract_findings_from_html(report_path: str) -> str:
    """Read the HTML report and extract the core findings for the AI to read."""
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            html = f.read()
            
        soup = BeautifulSoup(html, "html.parser")
        
        # Extract target
        target_info = soup.find(string="Primary Target")
        target = target_info.find_next("td").text if target_info else "Unknown Target"
        
        # Extract findings
        findings_text = f"Target: {target}\n\nFindings:\n"
        finding_cards = soup.find_all("div", class_="finding-card")
        
        for card in finding_cards:
            title = card.find("h3").text if card.find("h3") else "Unknown"
            severity = card.find("span", class_="badge").text.strip() if card.find("span", class_="badge") else "Unknown"
            desc_div = card.find("div", class_="finding-desc")
            desc = desc_div.text.replace("VULNERABILITY DETAILS:", "").strip() if desc_div else ""
            
            findings_text += f"- [{severity}] {title}\n  {desc}\n"
            
        return findings_text
    except Exception as e:
        return f"Error parsing report: {str(e)}"

def format_ai_prompt(extracted_data: str) -> str:
    return f"""You are 'Shadow AI', an elite offensive security AI agent (similar to PentestGPT).
    
A scan has just completed. Interpret the following findings and give the operator exact, actionable terminal commands to exploit or verify the vulnerabilities.
Keep your response concise, aggressive, and highly technical. Use Markdown formatting.

Scan Data:
{extracted_data}

Provide your response in this format:
1. Brief summary of the attack surface.
2. The exact terminal command(s) (e.g., sqlmap, curl, nmap scripts, ffuf) to exploit the most critical issues.
"""

def analyze_report(report_path: str, console):
    """Analyze the report using Google Gemini 3.1 Pro and print the result."""
    api_key = load_env_key()
    
    if not api_key:
        console.print(Panel(
            "[red]No API key found.[/red]\n"
            "To use Shadow AI, set the [bold]SHADOWSTRIKE_AI_KEY[/bold] in your environment or .env file.",
            title="🤖 AI Offline",
            border_style="red"
        ))
        return

    # Extract clean text from HTML
    scan_data = extract_findings_from_html(report_path)
    prompt = format_ai_prompt(scan_data)
    
    payload = {
        "contents": [
            {"role": "user", "parts": [{"text": prompt}]}
        ],
        "systemInstruction": {
            "role": "user",
            "parts": [{"text": "You are Shadow AI, an elite offensive security mentor.\nCRITICAL RULES:\n1. Be educational: briefly explain *how* a vulnerability works and *why* it's dangerous.\n2. Summarize findings quickly without repeating raw data.\n3. Provide the exact bash commands to run, but briefly explain *what* the command does so the operator can learn.\n4. Keep responses focused and avoid unnecessary fluff."}]
        }
    }
    
    try:
        with httpx.Client(timeout=60.0) as client:
            response = client.post(f"{GEMINI_API_URL}?key={api_key}", json=payload)
            response.raise_for_status()
            data = response.json()
            ai_text = data['candidates'][0]['content']['parts'][0]['text']
            
            console.print("\n")
            console.print(Panel(
                Markdown(ai_text),
                title="[bold magenta]🤖 Shadow AI Analysis Complete[/bold magenta]",
                border_style="magenta",
                padding=(1, 2)
            ))
            
    except Exception as e:
        console.print(f"[bold red]❌ AI Integration Error:[/] {str(e)}")

def chat_with_ai(messages: list, console) -> str:
    """Send a conversational turn to Gemini 3.1 Pro and return its response string."""
    api_key = load_env_key()
    
    if not api_key:
        console.print(Panel("[red]No API key found.[/red]", title="🤖 AI Offline", border_style="red"))
        return ""
        
    # Convert message format to Gemini format
    contents = []
    
    # Strict instructions for concise, local-LLM friendly output, while being educational
    sys_prompt = (
        "You are Shadow AI, an elite offensive security mentor.\n"
        "CRITICAL RULES:\n"
        "1. Be educational. Act as a senior pentester mentoring a junior. Briefly explain *why* something is vulnerable or *how* an attack works.\n"
        "2. If I feed you raw terminal output, summarize the most important findings instantly.\n"
        "3. Provide exact bash commands to run (copy-pasteable), but add a 1-sentence explanation of *what* the command is actually doing.\n"
        "4. Balance detail with conciseness. Teach the operator, but do not write long essays."
    )
    system_instruction = {"role": "user", "parts": [{"text": sys_prompt}]}
    
    for msg in messages:
        if msg["role"] == "system":
            system_instruction = {"role": "user", "parts": [{"text": msg["content"]}]}
        else:
            gemini_role = "user" if msg["role"] == "user" else "model"
            contents.append({"role": gemini_role, "parts": [{"text": msg["content"]}]})
            
    payload = {
        "contents": contents,
        "systemInstruction": system_instruction
    }
           
    try:
        with httpx.Client(timeout=60.0) as client:
            response = client.post(f"{GEMINI_API_URL}?key={api_key}", json=payload)
            response.raise_for_status()
            data = response.json()
            ai_text = data['candidates'][0]['content']['parts'][0]['text']
    except Exception as e:
        console.print(f"[bold red]❌ AI Communication Error:[/] {str(e)}")
        return ""
            
    # Print the output nicely
    console.print("\n")
    console.print(Panel(
        Markdown(ai_text),
        title="[bold magenta]🤖 Shadow AI[/bold magenta]",
        border_style="magenta",
        padding=(1, 2)
    ))
    
    return ai_text
