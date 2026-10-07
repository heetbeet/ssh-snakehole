"""Check runtime imports and generated artifacts against the dependency boundary."""
import ast
import sys
import zipfile
from pathlib import Path

root=Path(__file__).resolve().parents[1]
allowed=set(sys.stdlib_module_names)|{"wsproto","h11","ssh_snakehole"}
extra=set(); lines=0
for path in (root/"ssh_snakehole").rglob("*.py"):
    source=path.read_text("utf-8"); lines+=len(source.splitlines())
    for node in ast.walk(ast.parse(source)):
        if isinstance(node,ast.Import):
            extra.update(alias.name.split(".")[0] for alias in node.names if alias.name.split(".")[0] not in allowed)
        elif isinstance(node,ast.ImportFrom) and not node.level and node.module:
            if node.module.split(".")[0] not in allowed: extra.add(node.module.split(".")[0])
assert not extra,extra
for path in (root/"dist").glob("*"):
    if path.suffix not in (".pyz",".whl"): continue
    with zipfile.ZipFile(path) as archive:
        assert not [name for name in archive.namelist() if name.lower().endswith((".so",".dll",".pyd",".exe"))]
print(f"Runtime import boundary passed; {lines} Python lines; no extra native artifact files")
