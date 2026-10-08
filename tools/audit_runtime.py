"""Check runtime imports and generated artifacts against the dependency boundary."""

import ast
import sys
import tomllib
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
allowed = set(sys.stdlib_module_names) | {
    "wsproto",
    "h11",
    "ssh_snakehole",
    "asyncssh",
    "aiortc",
    "cryptography",
    "nacl",
    "spake2",
    "winpty",
    "ptyprocess",
    "certifi",
}
extra = set()
lines = 0
for path in (root / "ssh_snakehole").rglob("*.py"):
    source = path.read_text("utf-8")
    lines += len(source.splitlines())
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            extra.update(
                alias.name.split(".")[0]
                for alias in node.names
                if alias.name.split(".")[0] not in allowed
            )
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            if node.module.split(".")[0] not in allowed:
                extra.add(node.module.split(".")[0])
assert not extra, extra
version = tomllib.loads((root / "pyproject.toml").read_text("utf-8"))["project"][
    "version"
]
wheels = list((root / "dist").glob(f"ssh_snakehole-{version}-*.whl"))
assert wheels, "Build a wheel before checking its contents"
for path in wheels:
    with zipfile.ZipFile(path) as archive:
        sources = {
            name
            for name in archive.namelist()
            if name.startswith("ssh_snakehole/") and name.endswith(".py")
        }
        expected = {
            path.relative_to(root).as_posix()
            for path in (root / "ssh_snakehole").rglob("*.py")
        }
        assert sources == expected, (sources - expected, expected - sources)
        for name in sources:
            assert archive.read(name) == (root / name).read_bytes(), name
        assert "ssh_snakehole/py.typed" in archive.namelist()
print(
    f"Runtime import boundary passed; {lines} Python lines; wheel matches current sources"
)
