"""Per-user foreground command installation. No service or scheduled task."""
import importlib.util
import importlib.metadata
import os
import shlex
import shutil
import sys
import tempfile
import zipfile
import hashlib
import time
import re
from pathlib import Path


def build_archive(destination):
    root=Path(__file__).resolve().parent.parent
    if root.is_file() and zipfile.is_zipfile(root):
        shutil.copyfile(root,destination); return
    with zipfile.ZipFile(destination,"w",zipfile.ZIP_DEFLATED) as archive:
        def write(name,data):
            # Stable archive metadata keeps repeat installs on the same owned path.
            entry=zipfile.ZipInfo(name); entry.create_system=3; entry.external_attr=0o100644<<16
            archive.writestr(entry,data,compress_type=zipfile.ZIP_DEFLATED)
        for name in ("ssh_snakehole","wsproto","h11"):
            source=Path(importlib.util.find_spec(name).origin).parent
            if source.is_dir():
                for path in sorted(source.rglob("*")):
                    if path.is_file() and "__pycache__" not in path.parts and path.suffix in (".py",".json",".txt"):
                        write(name+"/"+path.relative_to(source).as_posix(),path.read_bytes())
            else:
                bundled=next(parent for parent in source.parents if parent.is_file() and zipfile.is_zipfile(parent))
                with zipfile.ZipFile(bundled) as dependency:
                    for file in dependency.namelist():
                        if file.startswith(name+"/") or file.startswith("licenses/"+name+"-"): write(file,dependency.read(file))
        for name in ("LICENSE","README.txt"):
            if (root/name).exists(): write(name,(root/name).read_bytes())
        for name in ("wsproto","h11"):
            try: distribution=importlib.metadata.distribution(name)
            except importlib.metadata.PackageNotFoundError: continue  # Notices copied from the bundled dependency above.
            for file in distribution.files:
                if "LICENSE" in str(file).upper(): write("licenses/"+name+"-"+Path(file).name,Path(distribution.locate_file(file)).read_bytes())
        write("__main__.py","from ssh_snakehole.cli import main\nmain()\n")


def location():
    if os.name=="nt": return Path(os.environ["LOCALAPPDATA"])/"Programs/ssh-snakehole"
    return Path.home()/".local/share/ssh-snakehole"


def windows_path(add):
    import winreg
    target=str(location())
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER,"Environment") as key:
        try: old,kind=winreg.QueryValueEx(key,"Path")
        except FileNotFoundError: old,kind="",winreg.REG_EXPAND_SZ
        entries=[entry for entry in old.split(";") if entry.casefold().rstrip("\\")!=target.casefold().rstrip("\\")] if old else []
        if add: entries.insert(0,target)
        winreg.SetValueEx(key,"Path",0,kind,";".join(entries))
    import ctypes
    from ctypes import wintypes
    user=ctypes.WinDLL("user32",use_last_error=True)
    user.SendMessageTimeoutW.argtypes=[wintypes.HWND,wintypes.UINT,wintypes.WPARAM,wintypes.LPCWSTR,wintypes.UINT,wintypes.UINT,ctypes.c_void_p]
    user.SendMessageTimeoutW(0xffff,0x1a,0,"Environment",2,1000,None)


def install():
    root=location(); root.mkdir(parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile(suffix=".pyz",delete=False,dir=root) as file: temporary=Path(file.name)
    try:
        build_archive(temporary)
        name="app-"+hashlib.sha256(temporary.read_bytes()).hexdigest()[:16]+".pyz"
        artifact=root/name
        if not artifact.exists(): os.replace(temporary,artifact)
    finally: temporary.unlink(missing_ok=True)
    if os.name=="nt":
        shim=root/"ssh-snakehole.cmd"
        if shim.exists() and "rem ssh-snakehole" not in shim.read_text(): raise FileExistsError("An unrelated command occupies the install location")
        shim.write_text(f'@echo off\nrem ssh-snakehole\n"{sys.executable}" "%~dp0{name}" %*\n',encoding="utf-8")
        windows_path(True)
        os.environ["PATH"]=str(root)+os.pathsep+os.environ.get("PATH","")
    else:
        binary=Path.home()/".local/bin"; binary.mkdir(parents=True,exist_ok=True)
        shim=binary/"ssh-snakehole"
        if shim.exists() and "ssh-snakehole" not in shim.read_text(): raise FileExistsError("An unrelated command occupies ~/.local/bin/ssh-snakehole")
        shim.write_text(f'#!/bin/sh\n# ssh-snakehole\nexec {shlex.quote(sys.executable)} {shlex.quote(str(artifact))} "$@"\n',encoding="utf-8")
        shim.chmod(0o755)
        profile=Path.home()/(".zprofile" if os.environ.get("SHELL","").endswith("zsh") else ".profile")
        if str(binary) not in os.environ.get("PATH","").split(os.pathsep):
            text=profile.read_text() if profile.exists() else ""
            line='export PATH="$HOME/.local/bin:$PATH" # ssh-snakehole'
            if line not in text.splitlines(): profile.write_text(text.rstrip("\n")+"\n"+line+"\n")
    # A running host may still import its startup worker from its original archive.
    for previous in root.glob("app-*.pyz"):
        if re.fullmatch(r"app-[0-9a-f]{16}\.pyz",previous.name) and previous!=artifact and time.time()-previous.stat().st_mtime>3*3600: previous.unlink()
    return shim


def remove():
    root=location()
    if os.name=="nt": windows_path(False); shim=root/"ssh-snakehole.cmd"
    else: shim=Path.home()/".local/bin/ssh-snakehole"
    if shim.exists() and "app-" in shim.read_text() and "ssh-snakehole" in str(shim): shim.unlink()
    for artifact in root.glob("app-*.pyz"):
        if re.fullmatch(r"app-[0-9a-f]{16}\.pyz",artifact.name): artifact.unlink()
    if os.name!="nt":
        for name in (".profile",".zprofile"):
            profile=Path.home()/name
            if profile.exists():
                text=profile.read_text()
                updated="\n".join(line for line in text.split("\n") if line!='export PATH="$HOME/.local/bin:$PATH" # ssh-snakehole')
                if updated!=text: profile.write_text(updated)
    try: root.rmdir()
    except OSError: pass
    return root
