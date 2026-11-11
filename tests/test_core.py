import unittest
from pathlib import Path
from recon_osint.core.scope import validate_target, ScopeError
from recon_osint.modules.javascript import analyze_javascript
from recon_osint.modules.headers import analyze_headers
from recon_osint.core.config import load_config, get_profile

class CoreTests(unittest.TestCase):
    def test_scope_root_and_subdomain(self):
        p = {"root_domain": "example.com", "include_subdomains": True}
        self.assertEqual(validate_target("api.example.com", p), "api.example.com")
        with self.assertRaises(ScopeError): validate_target("evil-example.com", p)
        with self.assertRaises(ScopeError): validate_target("example.com.evil.org", p)

    def test_scope_blocks_subdomains_when_disabled(self):
        p = {"root_domain": "example.com", "include_subdomains": False}
        with self.assertRaises(ScopeError): validate_target("www.example.com", p)

    def test_javascript_extraction_and_secret_redaction(self):
        src = 'fetch("/api/items?page=2&sort=asc"); const api_key="EXAMPLE_NOT_A_REAL_SECRET_VALUE_12345";'
        out = analyze_javascript(src, "https://example.com/")
        self.assertIn("https://example.com/api/items?page=2&sort=asc", out["endpoints"])
        self.assertIn("page", out["parameters"])
        self.assertEqual(len(out["secret_indicators"]), 1)
        self.assertNotIn("EXAMPLE_NOT_A_REAL_SECRET_VALUE_12345", str(out))

    def test_headers_findings(self):
        out = analyze_headers({"host": "example.com", "headers": {"Server": "nginx"}})
        ids = {x["id"] for x in out["findings"]}
        self.assertIn("missing-content-security-policy", ids)
        self.assertIn("server-banner", ids)

    def test_config_profiles(self):
        cfg = load_config(Path(__file__).parents[1] / "config.json")
        self.assertEqual(get_profile(cfg, "meesho_root")["allowed_sources"], [])
        self.assertFalse(get_profile(cfg, "meesho_root")["active_http_enabled"])

if __name__ == "__main__": unittest.main()
