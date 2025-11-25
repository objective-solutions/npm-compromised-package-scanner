#!/usr/bin/env python3

import json
import os
import subprocess
import sys
import tempfile
import unittest


SCRIPT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "scan_compromised_packages.py",
)


class ScanCompromisedPackagesIntegrationTest(unittest.TestCase):
    def run_scan(
        self,
        bom_name,
        compromised_entries,
        lockfile_name,
        lockfile_contents,
        package_json_contents=None,
    ):
        """Run the scan script in an isolated temporary directory with a BOM file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a BOM file with the new format
            bom_data = {
                "name": bom_name,
                "date": "2025-11-25",
                "compromised-packages": compromised_entries,
            }
            bom_path = os.path.join(tmpdir, "bom-test.json")
            with open(bom_path, "w", encoding="utf-8") as f:
                json.dump(bom_data, f)

            lockfile_path = os.path.join(tmpdir, lockfile_name)
            os.makedirs(os.path.dirname(lockfile_path), exist_ok=True)
            with open(lockfile_path, "w", encoding="utf-8") as f:
                f.write(lockfile_contents)

            if package_json_contents is not None:
                package_json_path = os.path.join(
                    os.path.dirname(lockfile_path),
                    "package.json",
                )
                with open(package_json_path, "w", encoding="utf-8") as f:
                    f.write(package_json_contents)

            result = subprocess.run(
                [sys.executable, SCRIPT_PATH],
                cwd=tmpdir,
                capture_output=True,
                text=True,
                check=False,
            )

            return result.returncode, result.stdout, result.stderr

    def test_finds_compromised_package_in_lockfile(self):
        compromised_entries = [{"left-pad": "1.0.0"}]
        lockfile_contents = '"left-pad" "1.0.0"'

        returncode, stdout, stderr = self.run_scan(
            "Test BOM",
            compromised_entries,
            "package-lock.json",
            lockfile_contents,
        )

        self.assertEqual(returncode, 0, msg=stderr)
        self.assertIn(
            "Compromised package found: left-pad:1.0.0",
            stdout,
        )
        self.assertIn("Summary:", stdout)
        self.assertIn("Unique compromised packages found: 1", stdout)
        self.assertIn("BOM: Test BOM", stdout)
        self.assertIn("Scanned files:", stdout)
        self.assertIn("package-lock.json", stdout)

    def test_no_compromised_packages_found(self):
        compromised_entries = [{"left-pad": "1.0.0"}]
        lockfile_contents = '"another-package" "2.0.0"'

        returncode, stdout, stderr = self.run_scan(
            "Test BOM",
            compromised_entries,
            "package-lock.json",
            lockfile_contents,
        )

        self.assertEqual(returncode, 0, msg=stderr)
        self.assertNotIn("Compromised package found:", stdout)
        self.assertIn("Summary:", stdout)
        self.assertIn("No compromised packages found in scanned files.", stdout)
        self.assertIn("Scanned files:", stdout)
        self.assertIn("package-lock.json", stdout)

    def test_dependency_tree_with_package_json(self):
        """Test that dependency trees are generated when package.json is present."""
        compromised_entries = [{"vulnerable-lib": "1.2.3"}]

        # Create a package-lock.json v1 structure
        lockfile = {
            "name": "test-app",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "top-dep": {
                    "version": "2.0.0",
                    "dependencies": {
                        "vulnerable-lib": {
                            "version": "1.2.3",
                        },
                    },
                },
            },
        }

        package_json = {
            "name": "test-app",
            "version": "1.0.0",
            "dependencies": {
                "top-dep": "^2.0.0",
            },
        }

        returncode, stdout, stderr = self.run_scan(
            "Test BOM",
            compromised_entries,
            "package-lock.json",
            json.dumps(lockfile),
            json.dumps(package_json),
        )

        self.assertEqual(returncode, 0, msg=stderr)
        self.assertIn("Compromised package found: vulnerable-lib:1.2.3", stdout)
        self.assertIn("Dependency paths for compromised package vulnerable-lib:1.2.3", stdout)
        self.assertIn("Path 1:", stdout)
        self.assertIn("top-dep:2.0.0", stdout)
        self.assertIn("-> vulnerable-lib:1.2.3", stdout)

    def test_dependency_tree_without_package_json(self):
        """Test that script handles missing package.json gracefully."""
        compromised_entries = [{"vulnerable-lib": "1.2.3"}]

        lockfile = {
            "name": "test-app",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "vulnerable-lib": {
                    "version": "1.2.3",
                },
            },
        }

        returncode, stdout, stderr = self.run_scan(
            "Test BOM",
            compromised_entries,
            "package-lock.json",
            json.dumps(lockfile),
            package_json_contents=None,  # No package.json
        )

        self.assertEqual(returncode, 0, msg=stderr)
        self.assertIn("Compromised package found: vulnerable-lib:1.2.3", stdout)
        self.assertIn("No package.json next to", stdout)

    def test_multiple_compromised_packages(self):
        """Test detection of multiple compromised packages."""
        compromised_entries = [
            {"pkg-a": "1.0.0"},
            {"pkg-b": "2.0.0"},
        ]
        lockfile_contents = '"pkg-a" "1.0.0" "pkg-b" "2.0.0"'

        returncode, stdout, stderr = self.run_scan(
            "Test BOM",
            compromised_entries,
            "package-lock.json",
            lockfile_contents,
        )

        self.assertEqual(returncode, 0, msg=stderr)
        self.assertIn("Compromised package found: pkg-a:1.0.0", stdout)
        self.assertIn("Compromised package found: pkg-b:2.0.0", stdout)
        self.assertIn("Unique compromised packages found: 2", stdout)

    def test_yarn_lock_detection(self):
        """Test that yarn.lock files are scanned (but no tree generation)."""
        compromised_entries = [{"left-pad": "1.0.0"}]
        lockfile_contents = 'left-pad@^1.0.0:\n  version "1.0.0"'

        returncode, stdout, stderr = self.run_scan(
            "Test BOM",
            compromised_entries,
            "yarn.lock",
            lockfile_contents,
        )

        self.assertEqual(returncode, 0, msg=stderr)
        self.assertIn("Compromised package found: left-pad:1.0.0", stdout)
        # yarn.lock doesn't generate trees
        self.assertNotIn("Dependency paths for", stdout)

    def test_malformed_lockfile(self):
        """Test that malformed lockfiles are handled gracefully."""
        compromised_entries = [{"some-pkg": "1.0.0"}]
        lockfile_contents = "{ this is not valid json"

        returncode, stdout, stderr = self.run_scan(
            "Test BOM",
            compromised_entries,
            "package-lock.json",
            lockfile_contents,
        )

        self.assertEqual(returncode, 0, msg=stderr)
        # Should still complete without crashing
        self.assertIn("Summary:", stdout)

    def test_lockfile_v2_format(self):
        """Test package-lock.json v2+ format with dependency trees."""
        compromised_entries = [{"bad-dep": "3.0.0"}]

        lockfile = {
            "name": "test-app",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "packages": {
                "": {
                    "name": "test-app",
                    "version": "1.0.0",
                },
            },
            "dependencies": {
                "root-dep": {
                    "version": "1.0.0",
                    "requires": {
                        "bad-dep": "3.0.0",
                    },
                },
                "bad-dep": {
                    "version": "3.0.0",
                },
            },
        }

        package_json = {
            "name": "test-app",
            "version": "1.0.0",
            "dependencies": {
                "root-dep": "^1.0.0",
            },
        }

        returncode, stdout, stderr = self.run_scan(
            "Test BOM",
            compromised_entries,
            "package-lock.json",
            json.dumps(lockfile),
            json.dumps(package_json),
        )

        self.assertEqual(returncode, 0, msg=stderr)
        self.assertIn("Compromised package found: bad-dep:3.0.0", stdout)
        self.assertIn("Dependency paths for compromised package bad-dep:3.0.0", stdout)

    def test_no_bom_files(self):
        """Test behavior when *no* bom-*.json files exist in cwd or script dir.

        This is done by copying the script into an isolated temporary directory
        that has no bom-*.json files in either the working directory or next to
        the script copy.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Copy the script into the temp directory
            script_copy_path = os.path.join(tmpdir, "scan_compromised_packages.py")
            with open(SCRIPT_PATH, "r", encoding="utf-8") as src, open(
                script_copy_path,
                "w",
                encoding="utf-8",
            ) as dst:
                dst.write(src.read())

            # Create a minimal lockfile so the script can run its normal flow
            lockfile_path = os.path.join(tmpdir, "package-lock.json")
            with open(lockfile_path, "w", encoding="utf-8") as f:
                f.write('{"dependencies": {}}')

            result = subprocess.run(
                [sys.executable, script_copy_path],
                cwd=tmpdir,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0)
            self.assertIn("No bom-*.json files found", result.stdout)

    def test_empty_bom_packages(self):
        """Test behavior with empty compromised-packages list in BOM."""
        compromised_entries = []
        lockfile_contents = '"some-package" "1.0.0"'

        returncode, stdout, stderr = self.run_scan(
            "Test BOM",
            compromised_entries,
            "package-lock.json",
            lockfile_contents,
        )

        self.assertEqual(returncode, 0, msg=stderr)
        # Should still scan but find no matches
        self.assertNotIn("Compromised package found:", stdout)
        self.assertIn("No compromised packages found in scanned files.", stdout)

    def test_warning_when_package_json_but_no_lockfile(self):
        """Test warning when package.json exists but no lock files are found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a BOM file
            bom_data = {
                "name": "Test BOM",
                "date": "2025-11-25",
                "compromised-packages": [{"some-pkg": "1.0.0"}],
            }
            bom_path = os.path.join(tmpdir, "bom-test.json")
            with open(bom_path, "w", encoding="utf-8") as f:
                json.dump(bom_data, f)

            # Create a package.json but NO lockfile
            package_json_path = os.path.join(tmpdir, "package.json")
            with open(package_json_path, "w", encoding="utf-8") as f:
                json.dump({"name": "test-app", "version": "1.0.0"}, f)

            result = subprocess.run(
                [sys.executable, SCRIPT_PATH],
                cwd=tmpdir,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0)
            self.assertIn("Warning: package.json found", result.stdout)
            self.assertIn("Lock files", result.stdout)
            self.assertIn("docker environment", result.stdout)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
