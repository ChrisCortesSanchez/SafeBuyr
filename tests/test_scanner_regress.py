"""
Regression Tests for Scanner
Tests that scanner STILL detects vulnerabilities correctly
"""

import pytest
import requests
import os
import glob


BASE_URL = "http://localhost:5001"


class TestScannerFunctionality:
    """Test that scanner still works correctly"""
    
    def test_scanner_runs_successfully(self):
        """Verify scanner can run without errors"""
        import subprocess
        
        result = subprocess.run(
            ['python', 'scanner/vulnerability_scanner.py', BASE_URL],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        # Scanner should exit successfully (even if it finds vulns)
        assert result.returncode == 0 or result.returncode is None, \
            f"Scanner should run successfully. Error: {result.stderr}"
        
        print("✓ Scanner runs without errors")
    
    def test_scanner_generates_reports(self):
        """Verify scanner generates HTML and TXT reports"""
        # Scanner should have created reports
        html_reports = glob.glob('docs/security_report_*.html')
        txt_reports = glob.glob('docs/security_report_*.txt')
        
        assert len(html_reports) > 0, "Scanner should generate HTML report"
        assert len(txt_reports) > 0, "Scanner should generate TXT report"
        
        print(f"✓ Scanner generated {len(html_reports)} HTML report(s)")
        print(f"✓ Scanner generated {len(txt_reports)} TXT report(s)")
    
    def test_scanner_detects_vulnerabilities(self):
        """Verify scanner found vulnerabilities in vulnerable version"""
        # Read the most recent TXT report
        txt_reports = sorted(glob.glob('docs/security_report_*.txt'))
        assert len(txt_reports) > 0, "No scanner reports found"
        
        with open(txt_reports[-1], 'r') as f:
            report_content = f.read()
        
        # Scanner should find multiple vulnerabilities
        assert 'Vulnerabilities Found:' in report_content, \
            "Report should list vulnerabilities found"
        
        # Check for key vulnerability types
        vulnerability_keywords = [
            'SQL Injection',
            'XSS',
            'IDOR',
            'CSRF',
            'Security Headers'
        ]
        
        found_count = sum(1 for keyword in vulnerability_keywords 
                         if keyword in report_content)
        
        assert found_count >= 3, \
            f"Scanner should detect at least 3 vulnerability types (found {found_count})"
        
        print(f"✓ Scanner detected {found_count} vulnerability types")
    
    def test_scanner_report_has_risk_score(self):
        """Verify scanner calculates risk score"""
        txt_reports = sorted(glob.glob('docs/security_report_*.txt'))
        assert len(txt_reports) > 0, "No scanner reports found"
        
        with open(txt_reports[-1], 'r') as f:
            report_content = f.read()
        
        # Should have risk score
        assert 'Risk Score:' in report_content or 'Overall Risk' in report_content, \
            "Report should include risk score"
        
        print("✓ Scanner calculated risk score")


class TestScannerAccuracy:
    """Test scanner detection accuracy"""
    
    def test_scanner_endpoint_discovery(self):
        """Verify scanner discovers endpoints"""
        txt_reports = sorted(glob.glob('docs/security_report_*.txt'))
        assert len(txt_reports) > 0, "No scanner reports found"
        
        with open(txt_reports[-1], 'r') as f:
            report_content = f.read()
        
        # Should mention endpoint discovery
        expected_endpoints = ['/login', '/register', '/products']
        found_endpoints = sum(1 for endpoint in expected_endpoints 
                            if endpoint in report_content)
        
        assert found_endpoints > 0, \
            "Scanner should discover common endpoints"
        
        print(f"✓ Scanner discovered endpoints")
    
    def test_html_report_valid(self):
        """Verify HTML report is valid HTML"""
        html_reports = sorted(glob.glob('docs/security_report_*.html'))
        assert len(html_reports) > 0, "No HTML reports found"
        
        with open(html_reports[-1], 'r') as f:
            html_content = f.read()
        
        # Basic HTML validation
        assert '<!DOCTYPE html>' in html_content or '<html' in html_content, \
            "Report should be valid HTML"
        assert '<body' in html_content, "HTML should have body tag"
        
        print("✓ HTML report is valid")


def test_application_accessible():
    """Sanity check: application is running for scanner"""
    response = requests.get(BASE_URL)
    assert response.status_code == 200, "Application should be running"
    print("✓ Application is accessible for scanning")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])