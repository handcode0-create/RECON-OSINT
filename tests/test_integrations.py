import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from recon_osint.integrations.orchestrator import run_pipeline

class IntegrationPolicyTests(unittest.TestCase):
    def test_meesho_profile_does_not_run_external_tools_by_default(self):
        profile = {
            "root_domain": "meesho.com",
            "include_subdomains": False,
            "mode": "passive_only",
            "enabled_tools": [],
            "max_results": 100,
            "max_hosts": 1,
        }
        with tempfile.TemporaryDirectory() as tmp:
            with patch("recon_osint.integrations.orchestrator._execute") as execute:
                result = run_pipeline(profile, "meesho.com", tmp, confirm_authorized=True)
                execute.assert_not_called()
        self.assertEqual(result["summary"]["hosts_in_scope"], 1)
        self.assertEqual(result["stages"]["subfinder"]["status"], "skipped")
        self.assertEqual(result["stages"]["httpx"]["status"], "skipped")

    def test_httpx_requires_explicit_authorization_and_profile_toggle(self):
        profile = {
            "root_domain": "example.com",
            "include_subdomains": True,
            "mode": "authorized_lab",
            "enabled_tools": ["httpx"],
            "active_http_enabled": False,
            "max_hosts": 10,
        }
        with tempfile.TemporaryDirectory() as tmp:
            with patch("recon_osint.integrations.orchestrator._execute") as execute:
                result = run_pipeline(profile, "example.com", tmp, confirm_authorized=True)
                execute.assert_not_called()
        self.assertEqual(result["stages"]["httpx"]["status"], "skipped")

    def test_active_tool_requires_confirmation(self):
        profile = {
            "root_domain": "example.com",
            "include_subdomains": True,
            "mode": "authorized_lab",
            "enabled_tools": ["dnsx"],
            "dns_enabled": True,
            "max_hosts": 10,
        }
        with tempfile.TemporaryDirectory() as tmp:
            with patch("recon_osint.integrations.orchestrator._execute") as execute:
                result = run_pipeline(profile, "example.com", tmp, confirm_authorized=False)
                execute.assert_not_called()
        self.assertEqual(result["stages"]["dnsx"]["status"], "skipped")

    def test_subfinder_output_is_scope_filtered(self):
        profile = {
            "root_domain": "example.com",
            "include_subdomains": True,
            "mode": "authorized_lab",
            "enabled_tools": ["subfinder"],
            "max_results": 10,
            "max_hosts": 10,
        }
        with tempfile.TemporaryDirectory() as tmp:
            def fake_execute(tool, args, out_dir, timeout):
                return {"tool": tool, "status": "ok", "stdout": "api.example.com\nevil.example.net\nwww.example.com\n"}
            with patch("recon_osint.integrations.orchestrator._execute", side_effect=fake_execute):
                result = run_pipeline(profile, "example.com", tmp)
        self.assertEqual(result["scope_filtered"]["hosts"], ["api.example.com", "example.com", "www.example.com"])

if __name__ == "__main__":
    unittest.main()
