"""Native SSH/SFTP are independent peers, never runtime dependencies."""
import asyncio
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from ssh_snakehole import open_host,pair,RelayConfig
from ssh_snakehole.native import export
from ssh_snakehole import vault
from ssh_snakehole.platform import elevated
from ssh_snakehole.relay import Relay


@unittest.skipUnless(shutil.which("ssh") and not elevated(),"Native SSH and a non-admin account required")
class Native(unittest.IsolatedAsyncioTestCase):
    async def test_native_exec_rekey_and_sftp(self):
        relay=await Relay().start()
        config=RelayConfig(f"ws://127.0.0.1:{relay.mailbox_port}/v1",f"tcp://127.0.0.1:{relay.transit_port}")
        try:
            async with open_host(relay=config,lifetime=120) as host:
                ticket=await pair(host.code,relay=config)
                with tempfile.TemporaryDirectory() as directory:
                    root=Path(directory); password="native peer test passphrase"
                    path=await vault.save(ticket,password,root/"vault"/"ticket")
                    export(ticket,root/"native",path)
                    environment=dict(os.environ,SSH_SNAKEHOLE_PASSPHRASE=password)
                    # A zipapp supplies both this package and its source-only imports in WSL.
                    environment["PYTHONPATH"]=os.pathsep.join(sys.path)
                    command='[Console]::Out.Write("native"); [Console]::Error.Write("err"); exit 7' if os.name=="nt" else "printf native; printf err >&2; exit 7"
                    process=await asyncio.create_subprocess_exec(shutil.which("ssh"),"-F",str(root/"native/config"),"-o","RekeyLimit=1K","snakehole-"+ticket.info.session_id,command,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,env=environment)
                    async with asyncio.timeout(30): out,err=await process.communicate()
                    self.assertEqual((out,err,process.returncode),(b"native",b"err",7))
                    if shutil.which("sftp"):
                        from ssh_snakehole.sftp import remote_path
                        source=root/"source bytes"; target=root/"remote bytes"; download=root/"download bytes"
                        source.write_bytes(bytes(range(256))*400)
                        batch=f'pwd\nput "{source.as_posix()}" "{remote_path(target)}"\nget "{remote_path(target)}" "{download.as_posix()}"\nquit\n'.encode()
                        process=await asyncio.create_subprocess_exec(shutil.which("sftp"),"-b","-","-F",str(root/"native/config"),"-o","RekeyLimit=16K","snakehole-"+ticket.info.session_id,stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,env=environment)
                        async with asyncio.timeout(30): out,err=await process.communicate(batch)
                        self.assertEqual(process.returncode,0,err.decode("utf-8",errors="replace"))
                        self.assertEqual(download.read_bytes(),source.read_bytes())
        finally: await relay.aclose()


if __name__=="__main__": unittest.main()
