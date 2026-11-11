import tempfile
import unittest
from unittest.mock import patch
from recon_osint.integrations.orchestrator import run_pipeline, _scope_filter_urls, check_tools

class IntegrationPolicyTests(unittest.TestCase):
    def test_meesho_profile_kill_switch_blocks_every_external_tool(self):
        profile = {
            "root_domain": "meesho.com", "include_subdomains": False,
            "mode": "passive_only", "integrations_disabled": True,
            "enabled_tools": ["subfinder", "gau", "dnsx", "httpx", "katana"],
            "max_results": 100, "max_hosts": 1,
        }
        with tempfile.TemporaryDirectory() as tmp:
            with patch("recon_osint.integrations.orchestrator._execute") as execute:
                result = run_pipeline(profile, "meesho.com", tmp, confirm_authorized=True)
                execute.assert_not_called()
        self.assertTrue(all(x["status"] == "skipped" for x in result["stages"].values()))
        self.assertTrue(result["policy"]["meesho_profile_integrations_disabled"])

    def test_active_tools_require_profile_toggle(self):
        profile = {
            "root_domain": "example.com", "include_subdomains": True,
            "mode": "authorized_lab", "integrations_disabled": False,
            "enabled_tools": ["httpx"], "active_http_enabled": False, "max_hosts": 10,
        }
        with tempfile.TemporaryDirectory() as tmp:
            with patch("recon_osint.integrations.orchestrator._execute") as execute:
                result = run_pipeline(profile, "example.com", tmp, confirm_authorized=True)
                execute.assert_not_called()
        self.assertEqual(result["stages"]["httpx"]["status"], "skipped")

    def test_external_tools_require_cli_confirmation(self):
        profile = {
            "root_domain": "example.com", "include_subdomains": True,
            "mode": "authorized_lab", "integrations_disabled": False,
            "enabled_tools": ["dnsx"], "dns_enabled": True, "max_hosts": 10,
        }
        with tempfile.TemporaryDirectory() as tmp:
            with patch("recon_osint.integrations.orchestrator._execute") as execute:
                result = run_pipeline(profile, "example.com", tmp, confirm_authorized=False)
                execute.assert_not_called()
        self.assertEqual(result["stages"]["dnsx"]["status"], "skipped")

    def test_passive_sources_require_profile_opt_in(self):
        profile = {
            "root_domain": "example.com", "include_subdomains": True,
            "mode": "authorized_lab", "integrations_disabled": False,
            "allow_passive_integrations": False, "enabled_tools": ["subfinder"],
            "max_results": 10, "max_hosts": 10,
        }
        with tempfile.TemporaryDirectory() as tmp:
            with patch("recon_osint.integrations.orchestrator._execute") as execute:
                result = run_pipeline(profile, "example.com", tmp, confirm_authorized=True)
                execute.assert_not_called()
        self.assertEqual(result["stages"]["subfinder"]["status"], "skipped")

    def test_subfinder_output_is_filtered_to_configured_scope(self):
        profile = {
            "root_domain": "example.com", "include_subdomains": True,
            "mode": "authorized_lab", "integrations_disabled": False,
            "allow_passive_integrations": True, "enabled_tools": ["subfinder"],
            "max_results": 10, "max_hosts": 10,
        }
        with tempfile.TemporaryDirectory() as tmp:
            def fake_execute(tool, args, out_dir, timeout):
                return {"tool": tool, "status": "ok", "stdout": "api.example.com\nevil.example.net\nwww.example.com\n"}
            with patch("recon_osint.integrations.orchestrator._execute", side_effect=fake_execute):
                result = run_pipeline(profile, "example.com", tmp, confirm_authorized=True)
        self.assertEqual(result["scope_filtered"]["hosts"], ["api.example.com", "example.com", "www.example.com"])

    def test_httpx_name_collision_is_detected(self):
        from subprocess import CompletedProcess
        def fake_which(name):
            return r"C:\\fake\\httpx.exe" if name == "httpx" else None
        wrong_cli = CompletedProcess(args=["httpx", "-h"], returncode=0,
            stdout="HTTPX - A next generation HTTP client -j --json", stderr="")
        with patch("recon_osint.integrations.orchestrator.shutil.which", side_effect=fake_which), \\
             patch("recon_osint.integrations.orchestrator.subprocess.run", return_value=wrong_cli):
            result = check_tools()
        self.assertEqual(result["httpx"]["status"], "incompatible_binary")

    def test_projectdiscovery_httpx_signature_is_accepted(self):
        from subprocess import CompletedProcess
        def fake_which(name):
            return r"C:\\tools\\pd-httpx.exe" if name == "httpx" else None
        expected_cli = CompletedProcess(args=["httpx", "-h"], returncode=0,
            stdout="httpx is a fast and multi-purpose HTTP toolkit -td -sc", stderr="")
        with patch("recon_osint.integrations.orchestrator.shutil.which", side_effect=fake_which), \\
             patch("recon_osint.integrations.orchestrator.subprocess.run", return_value=expected_cli):
            result = check_tools()
        self.assertEqual(result["httpx"]["status"], "installed")

    def test_url_filter_rejects_out_of_scope_and_invalid_urls(self):
        profile = {"root_domain": "example.com", "include_subdomains": True}
        urls = [
            "https://api.example.com/ok", "https://evil.example.net/no",
            "javascript:alert(1)", "http://user:pass@example.com/creds",
            "https://example.com:8443/nonstandard-port",
        ]
        self.assertEqual(_scope_filter_urls(urls, profile, 20), ["https://api.example.com/ok"])

if __name__ == "__main__":
    unittest.main()
