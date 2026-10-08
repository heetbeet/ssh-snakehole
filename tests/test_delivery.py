"""The standard module entry point is the product's only command launcher."""

import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path

from ssh_snakehole.cli import parser

ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))["project"][
    "version"
]


class Delivery(unittest.TestCase):
    def test_command_worker_starts_without_loading_network_dependencies(self):
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                "import sys; import ssh_snakehole.worker; "
                "assert not {'asyncssh', 'cryptography', 'nacl', 'spake2', 'wsproto'} & sys.modules.keys(); "
                "import ssh_snakehole; "
                "assert all(getattr(ssh_snakehole, name) is not None for name in ssh_snakehole.__all__)",
            ],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wheel_contains_current_package_sources_only(self):
        wheel = ROOT / f"dist/ssh_snakehole-{VERSION}-py3-none-any.whl"
        if not wheel.exists():
            self.skipTest("Build a wheel to verify packaging")
        with zipfile.ZipFile(wheel) as package:
            sources = {
                name
                for name in package.namelist()
                if name.startswith("ssh_snakehole/") and name.endswith(".py")
            }
            root = Path(__file__).resolve().parents[1]
            expected = {
                path.relative_to(root).as_posix()
                for path in (root / "ssh_snakehole").rglob("*.py")
            }
            self.assertEqual(sources, expected)
            for name in sources:
                self.assertEqual(package.read(name), (root / name).read_bytes(), name)
            self.assertIn("ssh_snakehole/py.typed", package.namelist())

    def test_installed_module_runs_outside_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = dict(os.environ)
            environment.pop("PYTHONPATH", None)
            result = subprocess.run(
                [sys.executable, "-I", "-m", "ssh_snakehole", "version"],
                cwd=directory,
                env=environment,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(
                (result.returncode, result.stdout.strip()),
                (0, VERSION.encode()),
                result.stderr,
            )

    def test_no_custom_installer_commands(self):
        help = parser().format_help()
        self.assertNotIn("install", help)
        self.assertNotIn("remove", help)
