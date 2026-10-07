import asyncio
import base64
import secrets
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import asyncssh
from ssh_snakehole.ssh import SSHConnection,key_blob
from ssh_snakehole.wire import Reader,string

async def main():
    host_seed,client_seed=secrets.token_bytes(32),secrets.token_bytes(32)
    authorized=key_blob(client_seed)
    native_client_key=asyncssh.import_private_key(
        private_openssh(client_seed))

    async def command(channel):
        await channel.send(b'hello stdout\x00\xff')
        await channel.send(b'hello stderr',stderr=True)
        await channel.exit(7)

    def handler(channel,name,payload):
        if name!=b'exec': return None
        r=Reader(payload); assert r.text()=='example'; r.done()
        return command(channel)

    connections=[]
    async def accept(reader,writer):
        conn=SSHConnection(reader,writer,server=True,seed=host_seed,authorized=authorized,handler=handler)
        connections.append(conn)
        try: await conn.start(); await conn.wait_closed()
        except Exception as exc: print('our server error',type(exc).__name__,str(exc)); raise

    server=await asyncio.start_server(accept,'127.0.0.1',0)
    port=server.sockets[0].getsockname()[1]
    async with server:
        async with asyncssh.connect('127.0.0.1',port,username='help',known_hosts=None,client_keys=[native_client_key],encoding=None) as native:
            result=await native.run('example',check=False)
            assert result.stdout==b'hello stdout\x00\xff',result.stdout
            assert result.stderr==b'hello stderr'
            assert result.exit_status==7,result.exit_status
        print('AsyncSSH client -> Python server: pinned profile, public auth, stdout/stderr/status passed')
        reader,writer=await asyncio.open_connection('127.0.0.1',port)
        client=await SSHConnection(reader,writer,seed=client_seed,pin=key_blob(host_seed)).start()
        channel=await client.open_channel(); await channel.request(b'exec',string('example'))
        assert await channel.stdout.read()==b'hello stdout\x00\xff'
        assert await channel.stderr.read()==b'hello stderr'
        assert await channel.wait()==(7,None)
        await client.aclose()
        print('Python client -> Python server passed')
    for conn in connections: await conn.aclose()

    native_host=asyncssh.generate_private_key('ssh-ed25519')
    native_blob=base64.b64decode(native_host.export_public_key().split()[1])
    public=asyncssh.import_public_key(b'ssh-ed25519 '+base64.b64encode(authorized))
    class NativeServer(asyncssh.SSHServer):
        def begin_auth(self,username): return True
        def public_key_auth_supported(self): return True
        def validate_public_key(self,username,key): return key==public
    async def native_command(process):
        process.stdout.write(b'native reply'); process.stderr.write(b'native stderr'); process.exit(9)
    listener=await asyncssh.create_server(NativeServer,'127.0.0.1',0,server_host_keys=[native_host],process_factory=native_command,encoding=None)
    try:
        reader,writer=await asyncio.open_connection('127.0.0.1',listener.get_port())
        client=await SSHConnection(reader,writer,seed=client_seed,pin=native_blob).start()
        channel=await client.open_channel(); await channel.request(b'exec',string('example'))
        assert await channel.stdout.read()==b'native reply'
        assert await channel.stderr.read()==b'native stderr'
        assert await channel.wait()==(9,None)
        await client.aclose()
        print('Python client -> AsyncSSH server: host signature pin and command bytes/status passed')
    finally:
        listener.close(); await listener.wait_closed()

def private_openssh(seed):
    from ssh_snakehole._crypto import public_key
    from ssh_snakehole.wire import uint
    public=public_key(seed); check=secrets.token_bytes(4)
    body=check+check+string(b'ssh-ed25519')+string(public)+string(seed+public)+string(b'')
    padding=(-len(body))%8
    body+=bytes(range(1,padding+1))
    data=b'openssh-key-v1\0'+string(b'none')+string(b'none')+string(b'')+uint(1)+string(key_blob(seed))+string(body)
    return b'-----BEGIN OPENSSH PRIVATE KEY-----\n'+base64.encodebytes(data)+b'-----END OPENSSH PRIVATE KEY-----\n'

if __name__=='__main__': asyncio.run(main())
