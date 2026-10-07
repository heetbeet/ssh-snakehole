"""Run beside ssh-snakehole.pyz; no network or third-party installer required."""
import subprocess
import sys
from pathlib import Path

if not (3,12)<=sys.version_info[:2]<=(3,14): raise SystemExit("Python 3.12-3.14 required")
archive=Path(__file__).resolve().with_name("ssh-snakehole.pyz")
if not archive.is_file(): raise SystemExit("Keep offline-install.py beside ssh-snakehole.pyz")
raise SystemExit(subprocess.call([sys.executable,str(archive),*(sys.argv[1:] or ["install"])]))
