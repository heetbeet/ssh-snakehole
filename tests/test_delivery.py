import asyncio
import os
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from ssh_snakehole.install import build_archive
from ssh_snakehole import install


class Delivery(unittest.TestCase):
    def test_offline_archive_install_update_remove(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); archive=root/"ssh-snakehole.pyz"
            build_archive(archive)
            with zipfile.ZipFile(archive) as package:
                self.assertTrue(all(not name.endswith((".so",".dll",".pyd",".exe")) for name in package.namelist()))
                self.assertIn("wsproto/__init__.py",package.namelist())
                self.assertIn("h11/__init__.py",package.namelist())
                self.assertIn("licenses/wsproto-LICENSE",package.namelist())
            result=subprocess.run([sys.executable,"-I",str(archive),"version"],capture_output=True,timeout=10)
            self.assertEqual((result.returncode,result.stdout.strip()),(0,b"0.1.0"),result.stderr)
            with patch.object(install,"location",return_value=root/"installed"),patch.object(install,"windows_path"),patch.object(Path,"home",return_value=root):
                shim=install.install(); time.sleep(2.1); install.install()
                self.assertEqual(len(list((root/"installed").glob("app-*.pyz"))),1)
                if os.name=="nt":
                    result=subprocess.run([os.environ["COMSPEC"],"/d","/c",str(shim),"version"],capture_output=True,timeout=10)
                else: result=subprocess.run([str(shim),"version"],capture_output=True,timeout=10)
                self.assertEqual((result.returncode,result.stdout.strip()),(0,b"0.1.0"),result.stderr)
                install.remove(); self.assertFalse(shim.exists())
                self.assertFalse((root/"installed").exists())


if __name__=="__main__": unittest.main()
