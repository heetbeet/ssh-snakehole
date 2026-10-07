"""Optional Python mailbox and Transit relay, independent of client installation.

Run behind a TLS reverse proxy for internet use. A SQLite file preserves pairing
messages across restarts; Transit connections always end when this process exits.
"""
import argparse
import asyncio
import collections
import contextlib
import re
import secrets
import sqlite3
import ssl
import time

from wsproto import WSConnection,ConnectionType
from wsproto.events import Request,AcceptConnection

from .errors import ProtocolViolation
from .websocket import WebSocket,WebSocketStream
from .wire import parse_json,json_bytes


class Relay:
    def __init__(self,*,state=":memory:"):
        self.db=sqlite3.connect(state)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS boxes(id TEXT PRIMARY KEY, app TEXT, created REAL);
            CREATE TABLE IF NOT EXISTS names(app TEXT, name TEXT, box TEXT, claims TEXT, PRIMARY KEY(app,name));
            CREATE TABLE IF NOT EXISTS messages(box TEXT, side TEXT, phase TEXT, body TEXT);
        """)
        self.subscribers=collections.defaultdict(set)
        self.pending=collections.defaultdict(list)
        self.tasks=set(); self.servers=[]; self.ips=collections.Counter(); self.streams=0

    async def start(self,*,host="127.0.0.1",mailbox_port=0,transit_port=0,tls=None):
        mailbox=await asyncio.start_server(self._websocket,host,mailbox_port,ssl=tls,limit=65536)
        transit=await asyncio.start_server(self._transit_socket,host,transit_port,limit=65536)
        self.servers=[mailbox,transit]
        self.mailbox_port=mailbox.sockets[0].getsockname()[1]
        self.transit_port=transit.sockets[0].getsockname()[1]
        self.cleanup_task=asyncio.create_task(self._expire())
        return self

    async def _expire(self):
        while True:
            await asyncio.sleep(60)
            old=[row[0] for row in self.db.execute("SELECT id FROM boxes WHERE created<?",(time.time()-3600,)) if not self.subscribers[row[0]]]
            for box in old:
                self.db.execute("DELETE FROM names WHERE box=?",(box,))
                self.db.execute("DELETE FROM messages WHERE box=?",(box,))
                self.db.execute("DELETE FROM boxes WHERE id=?",(box,))
            self.db.commit()

    def _enter(self,writer):
        ip=writer.get_extra_info("peername",("unknown",))[0]
        if len(self.tasks)>=512 or self.ips[ip]>=32: return None
        task=asyncio.current_task(); self.tasks.add(task); self.ips[ip]+=1
        return ip

    def _leave(self,ip):
        self.tasks.discard(asyncio.current_task()); self.ips[ip]-=1

    async def _websocket(self,reader,writer):
        ip=self._enter(writer)
        if ip is None: writer.close(); return
        ws=WebSocket(reader,writer,WSConnection(ConnectionType.SERVER),262160)
        box=None; app=side=name=None; value={}
        async def response(kind,**fields): await ws.send(json_bytes(dict(type=kind,**fields)).decode("ascii"))
        try:
            async with asyncio.timeout(10):
                request=await ws.next_event()
                if not isinstance(request,Request): raise ProtocolViolation("Expected WebSocket request")
                await ws.send_event(AcceptConnection())
            if request.target=="/transit":
                stream=WebSocketStream(ws)
                await self._transit(stream,stream)
                return
            ws.limit=65536
            await response("welcome",welcome={"permission-required":{"none":{}}})
            while True:
                async with asyncio.timeout(650): value=parse_json(await ws.receive(),65536)
                if not isinstance(value,dict): raise ValueError("Expected JSON object")
                kind=value.get("type"); identity=value.get("id")
                await response("ack",id=identity)
                if kind=="bind":
                    if app is not None: raise ValueError("Already bound")
                    app,side=value["appid"],value["side"]
                    if not isinstance(app,str) or len(app)>256 or not isinstance(side,str) or not re.fullmatch(r"[0-9a-f]{2,64}",side): raise ValueError("Invalid binding")
                    continue
                if app is None: raise ValueError("Bind first")
                if kind=="allocate":
                    if self.db.execute("SELECT count(*) FROM boxes").fetchone()[0]>=1000: raise ValueError("Mailbox capacity reached")
                    name="1"
                    while self.db.execute("SELECT 1 FROM names WHERE app=? AND name=?",(app,name)).fetchone(): name=str(int(name)+1)
                    mailbox=secrets.token_hex(16)
                    self.db.execute("INSERT INTO boxes VALUES(?,?,?)",(mailbox,app,time.time()))
                    self.db.execute("INSERT INTO names VALUES(?,?,?,?)",(app,name,mailbox,side))
                    self.db.commit(); await response("allocated",id=identity,nameplate=name)
                elif kind=="claim":
                    name=value["nameplate"]
                    if not isinstance(name,str) or not re.fullmatch(r"[0-9]{1,40}",name): raise ValueError("Invalid nameplate")
                    row=self.db.execute("SELECT box,claims FROM names WHERE app=? AND name=?",(app,name)).fetchone()
                    if row is None:
                        if self.db.execute("SELECT count(*) FROM boxes").fetchone()[0]>=1000: raise ValueError("Mailbox capacity reached")
                        mailbox=secrets.token_hex(16)
                        self.db.execute("INSERT INTO boxes VALUES(?,?,?)",(mailbox,app,time.time()))
                        self.db.execute("INSERT INTO names VALUES(?,?,?,?)",(app,name,mailbox,side))
                    else:
                        mailbox,claims=row; claims=set(claims.split(","))
                        if side not in claims and len(claims)>=2: raise ValueError("Nameplate crowded")
                        claims.add(side)
                        self.db.execute("UPDATE names SET claims=? WHERE app=? AND name=?",(",".join(claims),app,name))
                    self.db.commit(); await response("claimed",id=identity,mailbox=mailbox)
                elif kind=="open":
                    if box is not None: raise ValueError("Mailbox already open")
                    box=value["mailbox"]
                    if not self.db.execute("SELECT 1 FROM boxes WHERE id=? AND app=?",(box,app)).fetchone(): raise ValueError("Unknown mailbox")
                    if len(self.subscribers[box])>=2: raise ValueError("Mailbox crowded")
                    self.subscribers[box].add(ws)
                    for peer,phase,body in self.db.execute("SELECT side,phase,body FROM messages WHERE box=?",(box,)):
                        await response("message",side=peer,phase=phase,body=body)
                elif kind=="release":
                    row=self.db.execute("SELECT claims FROM names WHERE app=? AND name=?",(app,value.get("nameplate",name))).fetchone()
                    if row:
                        claims=set(row[0].split(",")); claims.discard(side)
                        if claims: self.db.execute("UPDATE names SET claims=? WHERE app=? AND name=?",(",".join(claims),app,value.get("nameplate",name)))
                        else: self.db.execute("DELETE FROM names WHERE app=? AND name=?",(app,value.get("nameplate",name)))
                    self.db.commit(); await response("released",id=identity)
                elif kind=="add":
                    if box is None: raise ValueError("Open mailbox first")
                    phase,body=value["phase"],value["body"]
                    if not isinstance(phase,str) or len(phase)>64 or not isinstance(body,str) or len(body)>65536 or not re.fullmatch(r"(?:[0-9a-f]{2})*",body): raise ValueError("Invalid phase or body")
                    count,size=self.db.execute("SELECT count(*),coalesce(sum(length(body)),0) FROM messages WHERE box=?",(box,)).fetchone()
                    if count>=256 or size+len(body)>2*1024*1024: raise ValueError("Mailbox message budget reached")
                    self.db.execute("INSERT INTO messages VALUES(?,?,?,?)",(box,side,phase,body)); self.db.commit()
                    message=json_bytes(dict(type="message",side=side,phase=phase,body=body,id=identity)).decode("ascii")
                    for subscriber in tuple(self.subscribers[box]):
                        with contextlib.suppress(Exception):
                            async with asyncio.timeout(5): await subscriber.send(message)
                elif kind=="close":
                    if box: self.subscribers[box].discard(ws)
                    await response("closed",id=identity); break
                elif kind=="list":
                    await response("nameplates",id=identity,nameplates=[{"id":r[0]} for r in self.db.execute("SELECT name FROM names WHERE app=? LIMIT 100",(app,))])
                elif kind=="ping": await response("pong",id=identity,pong=value.get("ping"))
                else: raise ValueError("Unknown mailbox command")
        except asyncio.CancelledError: raise
        except (Exception,):
            with contextlib.suppress(Exception):
                async with asyncio.timeout(1): await response("error",error="Relay request rejected",orig=value if isinstance(value,dict) else {})
        finally:
            if box: self.subscribers[box].discard(ws)
            await ws.aclose(); self._leave(ip)

    async def _transit_socket(self,reader,writer):
        ip=self._enter(writer)
        if ip is None: writer.close(); return
        try: await self._transit(reader,writer)
        except (Exception,): pass
        finally:
            writer.close()
            with contextlib.suppress(Exception): await writer.wait_closed()
            self._leave(ip)

    async def _transit(self,reader,writer):
        entry=None; token=None; pumps=[]
        try:
            async with asyncio.timeout(10): line=await reader.readuntil(b"\n")
            if len(line)>128: raise ValueError("Relay greeting exceeds limit")
            match=re.fullmatch(rb"please relay ([0-9a-f]{64}) for side ([0-9a-f]{16})\n",line)
            if not match: raise ValueError("Invalid Transit greeting")
            token,side=match.groups(); future=asyncio.get_running_loop().create_future()
            waiting=self.pending[token]
            peer=next((item for item in waiting if item[0]!=side and not item[3].done()),None)
            if peer:
                waiting.remove(peer)
                if not waiting: self.pending.pop(token,None)
                # Each side owns its writer. Once matched, each copies peer -> own.
                future.set_result(peer[:3]); peer[3].set_result((side,reader,writer))
            else:
                if sum(len(items) for items in self.pending.values())>=256 or len(waiting)>=8: raise ValueError("Transit pending capacity reached")
                entry=(side,reader,writer,future); waiting.append(entry)
            async with asyncio.timeout(300): _,peer_reader,peer_writer=await future
            writer.write(b"ok\n"); await writer.drain()
            while data:=await peer_reader.read(32768): writer.write(data); await writer.drain()
        finally:
            if entry and token in self.pending:
                with contextlib.suppress(ValueError): self.pending[token].remove(entry)
                if not self.pending[token]: self.pending.pop(token,None)
            writer.close()

    async def aclose(self):
        self.cleanup_task.cancel()
        for server in self.servers: server.close()
        for task in tuple(self.tasks): task.cancel()
        await asyncio.gather(*self.tasks,self.cleanup_task,return_exceptions=True)
        for server in self.servers: await server.wait_closed()
        self.db.close()


async def run(args):
    tls=None
    if args.cert:
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(args.cert,args.key)
    relay=await Relay(state=args.state).start(host=args.bind,mailbox_port=args.mailbox_port,transit_port=args.transit_port,tls=tls)
    try:
        print(f"Mailbox on {relay.mailbox_port}; Transit TCP on {relay.transit_port}; Transit WebSocket at /transit",flush=True)
        await asyncio.Event().wait()
    finally: await relay.aclose()


def main():
    parser=argparse.ArgumentParser(description="Optional mailbox and Transit service. Use TLS for internet deployment.")
    parser.add_argument("--bind",default="127.0.0.1"); parser.add_argument("--mailbox-port",type=int,default=4000)
    parser.add_argument("--transit-port",type=int,default=4001); parser.add_argument("--state",default="snakehole-relay.sqlite")
    parser.add_argument("--cert"); parser.add_argument("--key")
    try: asyncio.run(run(parser.parse_args()))
    except KeyboardInterrupt: pass


if __name__=="__main__": main()
