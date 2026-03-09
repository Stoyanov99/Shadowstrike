import os
import sys

# Setup imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shadowstrike.output.report import ReportGenerator

def test_pdf():
    print("Testing PDF Generation...")
    rg = ReportGenerator()
    
    # Create fake findings
    class DummySeverity:
        def __init__(self, value):
            self.value = value
            
    class DummyFinding:
        def __init__(self):
            self.severity = DummySeverity("CRITICAL")
            self.title = "Test Finding"
            self.module = "test"
            self.description = "Test description"
            self.recommendation = "Test recommendation"
            self.evidence = "Test evidence"
            
    findings = [DummyFinding()]
    
    out_dir = "/tmp/test_report"
    os.makedirs(out_dir, exist_ok=True)
    
    html_path, pdf_path = rg.generate("test_target.com", findings, [], out_dir, notes="This is a test run.")
    
    print(f"HTML Path: {html_path}")
    print(f"PDF Path: {pdf_path}")
    
    if pdf_path and os.path.exists(pdf_path):
        print(f"SUCCESS: PDF created at {pdf_path} (Size: {os.path.getsize(pdf_path)} bytes)")
    else:
        print("FAILED: PDF not created")

if __name__ == "__main__":
    test_pdf()
