import unittest
from pathlib import Path
from recon_osint.core.scope import validate_target, ScopeError
from recon_osint.modules.javascript import analyze_javascript
from recon_osint.modules.headers import analyze_headers
from recon_osint.core.config import load_config, get_profile
from recon_osint.cli import _validate_js_base_url, _enforce_target_profile_policy, _analyze_header_response

class CoreTests(unittest.TestCase):
    def test_scope_root_and_subdomain(self):
        p = {"root_domain": "example.com", "include_subdomains": True}
        self.assertEqual(validate_target("api.example.com", p), "api.example.com")
        with self.assertRaises(ScopeError): validate_target("evil-example.com", p)
        with self.assertRaises(ScopeError): validate_target("example.com.evil.org", p)

    def test_scope_blocks_subdomains_when_disabled(self):
        p = {"root_domain": "example.com", "include_subdomains": False}
        with self.assertRaises(ScopeError): validate_target("www.example.com", p)

    def test_scope_accepts_only_the_exact_ip_address(self):
        profile = {"root_domain": "192.0.2.10", "include_subdomains": False}
        self.assertEqual(validate_target("192.0.2.10", profile), "192.0.2.10")
        with self.assertRaises(ScopeError):
            validate_target("192.0.2.11", profile)
        with self.assertRaises(ScopeError):
            validate_target("example.com", profile)

    def test_target_parser_accepts_domain_url_and_ip(self):
        from recon_osint.core.scope import parse_target_input
        self.assertEqual(parse_target_input("https://example.com/app?token=hidden#top"),
            ("example.com", "https://example.com/app", 443))
        self.assertEqual(parse_target_input("http://192.0.2.5:8080/login"),
            ("192.0.2.5", "http://192.0.2.5:8080/login", 8080))
        self.assertEqual(parse_target_input("2001:db8::1")[0], "2001:db8::1")

    def test_javascript_keeps_relative_paths_without_explicit_base(self):
        out = analyze_javascript('fetch("/api/items?page=2&sort=asc");')
        self.assertIn("/api/items?page=2&sort=asc", out["endpoints"])
        self.assertNotIn("https://example.com/api/items?page=2&sort=asc", out["endpoints"])

    def test_javascript_resolves_paths_only_with_explicit_base(self):
        out = analyze_javascript('fetch("/api/items?page=2&sort=asc");', "https://example.com/app.js")
        self.assertIn("https://example.com/api/items?page=2&sort=asc", out["endpoints"])

    def test_meesho_target_requires_locked_profile(self):
        for target in ("meesho.com", "www.meesho.com", "api.meesho.com"):
            with self.assertRaises(ScopeError):
                _enforce_target_profile_policy("lab", target)
        _enforce_target_profile_policy("meesho_root", "meesho.com")
        _enforce_target_profile_policy("lab", "example.com")

    def test_header_analysis_skips_failed_http_fetch(self):
        raw = {"host": "example.com", "status": "error", "error": "TimeoutError"}
        out = _analyze_header_response(raw)
        self.assertEqual(out["analysis"]["status"], "skipped")
        self.assertNotIn("findings", out["analysis"])

    def test_header_analysis_accepts_real_http_response(self):
        raw = {"host": "example.com", "status": 200, "headers": {"Server": "nginx"}}
        out = _analyze_header_response(raw)
        self.assertEqual(out["analysis"]["count"], 5)

    def test_js_base_url_must_be_in_profile_scope(self):
        profile = {"root_domain": "example.com", "include_subdomains": False, "https_only": True}
        self.assertEqual(_validate_js_base_url("https://example.com/app.js", profile), "https://example.com/app.js")
        with self.assertRaises(ScopeError):
            _validate_js_base_url("https://other.example.net/app.js", profile)
        with self.assertRaises(ScopeError):
            _validate_js_base_url("http://example.com/app.js", profile)

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
        lab = get_profile(cfg, "lab")
        self.assertTrue(lab["active_http_enabled"])
        self.assertTrue(lab["dns_enabled"])
        self.assertTrue(lab["active_crawl_enabled"])
        self.assertEqual(set(lab["enabled_tools"]), {"subfinder", "gau", "dnsx", "httpx", "katana", "semgrep", "gitleaks"})
        self.assertEqual(lab["root_domain"], "")

if __name__ == "__main__": unittest.main()
