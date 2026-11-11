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
        with patch("recon_osint.integrations.orchestrator.shutil.which", side_effect=fake_which), \
             patch("recon_osint.integrations.orchestrator.subprocess.run", return_value=wrong_cli):
            result = check_tools()
        self.assertEqual(result["httpx"]["status"], "incompatible_binary")

    def test_projectdiscovery_httpx_signature_is_accepted(self):
        from subprocess import CompletedProcess
        def fake_which(name):
            return r"C:\\tools\\pd-httpx.exe" if name == "httpx" else None
        expected_cli = CompletedProcess(args=["httpx", "-h"], returncode=0,
            stdout="httpx is a fast and multi-purpose HTTP toolkit -td -sc", stderr="")
        with patch("recon_osint.integrations.orchestrator.shutil.which", side_effect=fake_which), \
             patch("recon_osint.integrations.orchestrator.subprocess.run", return_value=expected_cli):
            result = check_tools()
        self.assertEqual(result["httpx"]["status"], "installed")

    def test_projectdiscovery_katana_v1_signature_is_accepted(self):
        from subprocess import CompletedProcess
        def fake_which(name):
            return r"C:\\tools\\katana.exe" if name == "katana" else None
        expected_cli = CompletedProcess(args=["katana", "-h"], returncode=0,
            stdout="Katana is a fast crawler focused on execution in automation pipelines -j, -jsonl -fs, -field-scope",
            stderr="")
        with patch("recon_osint.integrations.orchestrator.shutil.which", side_effect=fake_which), \
             patch("recon_osint.integrations.orchestrator.subprocess.run", return_value=expected_cli):
            result = check_tools()
        self.assertEqual(result["katana"]["status"], "installed")

    def test_https_only_scope_filter_rejects_http_results(self):
        profile = {"root_domain": "example.com", "include_subdomains": True, "https_only": True, "target_port": 443}
        urls = ["http://example.com/plain", "https://example.com/secure"]
        self.assertEqual(_scope_filter_urls(urls, profile, 10, require_https=True), ["https://example.com/secure"])

    def test_custom_port_is_allowed_only_when_it_matches_the_entered_target(self):
        profile = {"root_domain": "example.com", "include_subdomains": False, "target_port": 8080}
        self.assertEqual(_scope_filter_urls(["http://example.com:8080/app", "http://example.com:8081/admin"], profile, 10),
            ["http://example.com:8080/app"])

    def test_ip_target_skips_domain_tools_and_runs_web_tools(self):
        profile = {
            "root_domain": "192.0.2.10",
            "include_subdomains": False,
            "mode": "authorized_lab",
            "integrations_disabled": False,
            "allow_passive_integrations": True,
            "enabled_tools": ["subfinder", "gau", "dnsx", "httpx", "katana"],
            "dns_enabled": True,
            "active_http_enabled": True,
            "active_crawl_enabled": True,
            "allow_private_targets": True,
            "target_port": 443,
            "max_hosts": 5,
            "max_results": 10,
            "max_web_targets": 2,
            "https_only": True,
        }
        calls = []
        def fake_execute(tool, args, out_dir, timeout):
            calls.append(tool)
            if tool == "httpx":
                return {"tool": tool, "status": "ok", "stdout": '{"url":"https://192.0.2.10/"}\n'}
            return {"tool": tool, "status": "ok", "stdout": ""}
        with tempfile.TemporaryDirectory() as tmp:
            with patch("recon_osint.integrations.orchestrator.check_tools", return_value={}), \\
                 patch("recon_osint.integrations.orchestrator._execute", side_effect=fake_execute):
                result = run_pipeline(profile, "192.0.2.10", tmp, confirm_authorized=True,
                    seed_url="https://192.0.2.10/")
        self.assertEqual(calls, ["httpx", "katana"])
        self.assertEqual(result["stages"]["subfinder"]["status"], "skipped")
        self.assertEqual(result["stages"]["gau"]["status"], "skipped")
        self.assertEqual(result["stages"]["dnsx"]["status"], "skipped")
        self.assertEqual(result["stages"]["httpx"]["count"], 1)

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
