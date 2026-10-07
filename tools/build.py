"""Build the offline bundle from the runtime environment, without build helpers."""
import hashlib
import json
import sys
import zipfile
from pathlib import Path

root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root))
from ssh_snakehole.install import build_archive

dist=root/"dist"; dist.mkdir(exist_ok=True)
build_archive(dist/"ssh-snakehole.pyz")
with zipfile.ZipFile(dist/"ssh-snakehole-0.1.0-offline.zip","w",zipfile.ZIP_DEFLATED) as archive:
    archive.write(dist/"ssh-snakehole.pyz","ssh-snakehole.pyz")
    for name in ("offline-install.py","README.txt","LICENSE"): archive.write(root/name,name)
    archive.writestr("manifest.json",json.dumps({"version":"0.1.0","python":">=3.12.14,<3.15","sha256":hashlib.sha256((dist/"ssh-snakehole.pyz").read_bytes()).hexdigest()},indent=2))
print(dist/"ssh-snakehole.pyz")
print(dist/"ssh-snakehole-0.1.0-offline.zip")
