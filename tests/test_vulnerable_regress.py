"""
Regression Tests for Vulnerable Version
Tests that vulnerabilities STILL exist (regression = accidentally fixing them)
"""

import pytest
import requests
from bs4 import BeautifulSoup


BASE_URL = "http://localhost:5001"


class TestSQLInjectionRegression:
    """Test that SQL injection vulnerability still exists"""
    
    def test_sql_injection_login_bypass(self):
        """Verify SQL injection still works in login"""
        session = requests.Session()
        
        # First, get the login page to see if there are CSRF tokens
        login_page = session.get(f"{BASE_URL}/login")
        
        payload = {
            'username': "admin' OR '1'='1'--",
            'password': "anything"
        }
        
        # Try SQL injection
        response = session.post(
            f"{BASE_URL}/login",
            data=payload,
            allow_redirects=True
        )
        
        # SQL injection should either:
        # 1. Redirect to homepage (302 -> 200)
        # 2. Show logged-in state (logout button, welcome message, etc.)
        # 3. Access cookies showing we're logged in
        
        # Check multiple indicators of successful login
        is_logged_in = (
            'logout' in response.text.lower() or
            'dashboard' in response.text.lower() or
            'welcome' in response.text.lower() or
            'session' in response.cookies or
            response.url != f"{BASE_URL}/login"  # Redirected away from login
        )
        
        assert is_logged_in, f"SQL injection should work. Got status {response.status_code}, URL: {response.url}"
        
        print("✓ SQL injection vulnerability still present")


class TestXSSRegression:
    """Test that XSS vulnerability still exists"""
    
    def test_xss_in_reviews(self):
        """Verify XSS payload is not sanitized"""
        session = requests.Session()
        
        # Login first
        session.post(f"{BASE_URL}/login", data={
            'username': 'user',
            'password': 'password'
        })
        
        # Submit XSS payload in review
        xss_payload = '<script>alert("XSS")</script>'
        response = session.post(
            f"{BASE_URL}/product/1/review",
            data={'rating': '5', 'comment': xss_payload}
        )
        
        # Get product page
        product_page = session.get(f"{BASE_URL}/product/1")
        
        # XSS should be present (not escaped)
        assert xss_payload in product_page.text or '<script>' in product_page.text, \
            "XSS should not be sanitized in vulnerable version"
        
        print("✓ XSS vulnerability still present")


class TestIDORRegression:
    """Test that IDOR vulnerability still exists"""
    
    def test_idor_in_orders(self):
        """Verify can access other users' orders without authorization"""
        session = requests.Session()
        
        # Login as regular user
        session.post(f"{BASE_URL}/login", data={
            'username': 'user',
            'password': 'password'
        })
        
        # Try to access order ID 1 (might be admin's order)
        response = session.get(f"{BASE_URL}/order/1")
        
        # Should succeed (200) - no authorization check
        assert response.status_code == 200, \
            "IDOR vulnerability should allow access to any order"
        
        print("✓ IDOR vulnerability still present")


class TestWeakPasswordHashingRegression:
    """Test that weak password hashing still exists"""
    
    def test_md5_password_storage(self):
        """Verify passwords still stored as MD5"""
        import sqlite3
        
        # Connect to database
        conn = sqlite3.connect('app/data/ecommerce.db')
        cursor = conn.cursor()
        
        # Get a password hash
        cursor.execute("SELECT password FROM users LIMIT 1")
        password_hash = cursor.fetchone()[0]
        conn.close()
        
        # MD5 hashes are 32 characters, bcrypt are 60 characters starting with $2b$
        assert len(password_hash) == 32, \
            "Password should be MD5 (32 chars), not bcrypt (60 chars)"
        assert not password_hash.startswith('$2b$'), \
            "Password should be MD5, not bcrypt"
        
        print("✓ Weak password hashing (MD5) still present")


class TestCSRFRegression:
    """Test that CSRF protection is missing"""
    
    def test_no_csrf_tokens(self):
        """Verify forms don't have CSRF tokens"""
        response = requests.get(f"{BASE_URL}/login")
        soup = BeautifulSoup(response.text, 'html.parser')

        # Target the login form specifically (the page also has a global
        # header search form, which would never carry a CSRF token anyway).
        form = soup.find('form', attrs={'action': lambda a: a and a.endswith('/login')})
        assert form is not None, "Login form should be present"
        csrf_input = form.find('input', {'name': 'csrf_token'})

        # Should NOT have CSRF token in vulnerable version
        assert csrf_input is None, \
            "Vulnerable version should not have CSRF tokens"
        
        print("✓ Missing CSRF protection confirmed")


class TestSecurityHeadersRegression:
    """Test that security headers are missing"""
    
    def test_missing_security_headers(self):
        """Verify security headers are not present"""
        response = requests.get(BASE_URL)
        
        # These headers should be MISSING in vulnerable version
        missing_headers = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Content-Security-Policy'
        ]
        
        for header in missing_headers:
            assert header not in response.headers, \
                f"Vulnerable version should not have {header}"
        
        print("✓ Missing security headers confirmed")


def test_vulnerable_version_accessible():
    """Sanity check: vulnerable version is running"""
    response = requests.get(BASE_URL)
    assert response.status_code == 200, "Vulnerable application should be accessible"
    print("✓ Vulnerable version is accessible")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])