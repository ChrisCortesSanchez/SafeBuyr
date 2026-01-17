"""
Regression Tests for Secure Version
Tests that security fixes STILL work (regression = vulnerabilities coming back)
"""

import pytest
import requests
from bs4 import BeautifulSoup


BASE_URL = "http://localhost:5002"


class TestSQLInjectionBlocked:
    """Test that SQL injection is properly blocked"""
    
    def test_sql_injection_blocked(self):
        """Verify SQL injection does NOT work"""
        payload = {
            'username': "admin' OR '1'='1'--",
            'password': "anything"
        }
        
        response = requests.post(
            f"{BASE_URL}/login",
            data=payload,
            allow_redirects=False
        )
        
        # Should NOT redirect (should fail with 200 and error message)
        # OR redirect back to login
        assert response.status_code != 302 or '/login' in response.headers.get('Location', ''), \
            "SQL injection should be blocked in secure version"
        
        print("✓ SQL injection is blocked")


class TestXSSBlocked:
    """Test that XSS is properly sanitized"""
    
    def test_xss_sanitized(self):
        """Verify XSS payload is escaped/sanitized"""
        session = requests.Session()
        
        # Login first
        login_response = session.post(f"{BASE_URL}/login", data={
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
        
        # XSS should be escaped (not executable)
        # Either &lt;script&gt; or completely absent
        assert '<script>alert' not in product_page.text, \
            "XSS should be escaped in secure version"
        
        print("✓ XSS is properly escaped")


class TestIDORBlocked:
    """Test that IDOR is properly prevented with authorization"""
    
    def test_idor_blocked(self):
        """Verify cannot access other users' orders"""
        session = requests.Session()
        
        # Login as regular user
        session.post(f"{BASE_URL}/login", data={
            'username': 'user',
            'password': 'password'
        })
        
        # Try to access order ID 1 (likely admin's order)
        response = session.get(f"{BASE_URL}/order/1", allow_redirects=False)
        
        # Should be forbidden (403) or redirect
        assert response.status_code in [403, 404, 302], \
            "IDOR should be blocked with proper authorization"
        
        print("✓ IDOR is blocked with authorization checks")


class TestStrongPasswordHashing:
    """Test that strong password hashing is implemented"""
    
    def test_bcrypt_password_storage(self):
        """Verify passwords stored with bcrypt"""
        import sqlite3
        
        # Connect to secure database
        conn = sqlite3.connect('app/secured/data/ecommerce_secure.db')
        cursor = conn.cursor()
        
        # Get a password hash
        cursor.execute("SELECT password FROM users LIMIT 1")
        password_hash = cursor.fetchone()[0]
        conn.close()
        
        # bcrypt hashes are 60 characters starting with $2b$
        assert len(password_hash) == 60, \
            "Password should be bcrypt (60 chars)"
        assert password_hash.startswith('$2b$'), \
            "Password should start with $2b$ (bcrypt identifier)"
        
        print("✓ Strong password hashing (bcrypt) is implemented")


class TestCSRFProtection:
    """Test that CSRF protection is present"""
    
    def test_csrf_tokens_present(self):
        """Verify forms have CSRF tokens"""
        response = requests.get(f"{BASE_URL}/login")
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Look for CSRF token in form
        form = soup.find('form')
        csrf_input = form.find('input', {'name': 'csrf_token'}) if form else None
        
        # Should have CSRF token in secure version
        assert csrf_input is not None, \
            "Secure version should have CSRF tokens"
        assert csrf_input.get('value'), \
            "CSRF token should have a value"
        
        print("✓ CSRF protection is present")


class TestSecurityHeaders:
    """Test that security headers are present"""
    
    def test_security_headers_present(self):
        """Verify security headers are configured"""
        response = requests.get(BASE_URL)
        
        # These headers SHOULD be present in secure version
        required_headers = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Content-Security-Policy',
            'X-XSS-Protection',
            'Referrer-Policy'
        ]
        
        for header in required_headers:
            assert header in response.headers, \
                f"Secure version should have {header}"
        
        print("✓ Security headers are configured")
        
        # Verify specific values
        assert response.headers['X-Frame-Options'] == 'SAMEORIGIN'
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
        
        print("✓ Security headers have correct values")


def test_secure_version_accessible():
    """Sanity check: secure version is running"""
    response = requests.get(BASE_URL)
    assert response.status_code == 200, "Secure application should be accessible"
    print("✓ Secure version is accessible")


def test_valid_credentials_still_work():
    """Verify legitimate login still works"""
    session = requests.Session()
    
    response = session.post(
        f"{BASE_URL}/login",
        data={'username': 'admin', 'password': 'admin123'},
        allow_redirects=False
    )
    
    # Should successfully login (redirect to /)
    assert response.status_code == 302, "Valid login should work"
    assert response.headers.get('Location') == '/', "Should redirect to homepage"
    
    print("✓ Valid credentials still work correctly")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])