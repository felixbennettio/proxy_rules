from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from build_dist_manifest import discover_published_files
from sync_modules import asset_path, build, public_url, render_module, write_json


class ModuleMirrorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.module_url = "https://example.com/Test.sgmodule"
        self.script_url = "https://example.com/test.js"
        self.module = b"#!name=Test\n#!arguments=Existing:true\n[Script]\ntest = type=generic,script-path=https://example.com/test.js\n"
        self.script = b"$done({});\n"
        self.config = {"gitlab_base": "https://git.routeforge.zone", "gitlab_project_id": 13,
                       "modules": [{"name": "Test", "url": self.module_url, "filename": "Test.sgmodule", "seed_last_success": "2026-01-01"}],
                       "assets": [{"url": self.script_url, "path": asset_path(self.script_url), "sha256": hashlib.sha256(self.script).hexdigest(), "seed_last_success": "2026-01-01"}]}
        self.save("modules/upstream/Test.sgmodule", self.module)
        self.save(asset_path(self.script_url), self.script)
        self.configure()
        self.responses = {self.module_url: self.module, self.script_url: self.script}
        self.calls = []

    def save(self, path, data):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def configure(self):
        write_json(self.root / "modules/SOURCES.json", self.config)

    def fetch(self, url):
        self.calls.append(url)
        response = self.responses.get(url, OSError("Unavailable"))
        if isinstance(response, Exception):
            raise response
        return response

    def test_complete_snapshot_encodes_paths_and_uses_argument_without_secret(self):
        report = build(self.root, self.fetch)
        text = (self.root / "modules/Test.sgmodule").read_text()
        self.assertIn('Existing:true,GitLabToken:""', text)
        self.assertIn("modules%2Fscripts%2F", text)
        self.assertIn("private_token={{{GitLabToken}}}", text)
        self.assertEqual(report["fresh_sources"], 2)
        self.assertIn("modules/Test.sgmodule", discover_published_files(self.root))
        self.assertIn(asset_path(self.script_url), discover_published_files(self.root))

    def test_unavailable_sources_keep_verified_last_success(self):
        self.responses = {}
        report = build(self.root, self.fetch)
        self.assertEqual(report["status"], "using_cached_sources")
        self.assertEqual(report["cached_sources"], 2)
        self.assertTrue(all(s["last_success"] == "2026-01-01" for s in report["sources"]))
        self.assertEqual((self.root / asset_path(self.script_url)).read_bytes(), self.script)

    def test_html_script_does_not_replace_good_cache(self):
        self.responses[self.script_url] = b"<!DOCTYPE html><html>Bad Gateway</html>"
        report = build(self.root, self.fetch)
        self.assertEqual(report["cached_sources"], 1)
        self.assertEqual((self.root / asset_path(self.script_url)).read_bytes(), self.script)

    def test_new_missing_dependency_aborts_without_publishing_partial_module(self):
        self.save("modules/Test.sgmodule", b"previous published module")
        self.responses[self.module_url] = self.module.replace(b"test.js", b"missing.js")
        with self.assertRaises(RuntimeError):
            build(self.root, self.fetch)
        self.assertEqual((self.root / "modules/Test.sgmodule").read_bytes(), b"previous published module")
        self.assertEqual((self.root / "modules/upstream/Test.sgmodule").read_bytes(), self.module)

    def test_corrupted_cached_script_is_rejected(self):
        self.responses = {}
        self.save(asset_path(self.script_url), b"corrupted")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            build(self.root, self.fetch)

    def test_removed_dependency_is_pruned(self):
        self.responses[self.module_url] = b"#!name=Test\n[Rule]\nDOMAIN,example.com,REJECT\n"
        report = build(self.root, self.fetch)
        self.assertEqual(report["scripts"], 0)
        self.assertFalse((self.root / asset_path(self.script_url)).exists())
        self.assertNotIn("GitLabToken", (self.root / "modules/Test.sgmodule").read_text())

    def test_shared_script_is_fetched_only_once(self):
        other = dict(self.config["modules"][0], name="Other", filename="Other.sgmodule", url="https://example.com/Other.sgmodule")
        self.config["modules"].append(other)
        self.configure()
        self.responses[other["url"]] = self.module.replace(b"#!name=Test", b"#!name=Other")
        report = build(self.root, self.fetch)
        self.assertEqual(report["modules"], 2)
        self.assertEqual(self.calls.count(self.script_url), 1)

    def test_credentials_in_public_source_urls_are_rejected(self):
        for url in ["https://user:secret@example.com/a.js", "https://example.com/a.js?token=secret", "file:///tmp/a.js"]:
            with self.assertRaises(ValueError):
                public_url(url)

    def test_reserved_argument_is_not_silently_overwritten(self):
        text = "#!name=Test\n#!arguments=GitLabToken:upstream\n[Script]\nx=script-path=https://example.com/test.js\n"
        with self.assertRaisesRegex(ValueError, "reserved"):
            render_module(text, {}, "https://git.routeforge.zone", 13)


if __name__ == "__main__":
    unittest.main()
