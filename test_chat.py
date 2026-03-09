import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shadowstrike.core.ai_agent import chat_with_ai
from shadowstrike.output.console import ShadowConsole

# Inject the user's API key
os.environ["SHADOWSTRIKE_AI_KEY"] = "AIzaSyATS72wefMxAJJbHe_bDnLl04zlMjgFbGw"

console = ShadowConsole()
messages = [
    {"role": "system", "content": "You are a pentesting assistant."},
    {"role": "user", "content": "I found port 21 open with vsftpd 2.3.4. What should I do?"}
]

print("Testing direct AI chat...")
response = chat_with_ai(messages, console)

if response:
    print(f"\nSUCCESS: AI Responded with {len(response)} characters.")
else:
    print("\nFAILED: No response from AI.")
