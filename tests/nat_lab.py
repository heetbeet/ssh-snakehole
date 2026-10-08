"""Linux-only network lab: two separate NAT routers and a local STUN/relay.

Run explicitly as root in a disposable Linux/WSL environment. Both application
peers run as nobody. All namespaces, links and processes created here are removed.
Invitations pass through owned process pipes and are never written to files.
"""

import asyncio
import contextlib
import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

from aioice import stun

from ssh_snakehole import RelayConfig, connect, open_host
from ssh_snakehole.errors import OutcomeUnknown
from ssh_snakehole.relay import Relay


class Stun(asyncio.DatagramProtocol):
    def __init__(self, network):
        self.network = network

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        with contextlib.suppress(ValueError):
            request = stun.parse_message(data)
            if request.message_class == stun.Class.REQUEST:
                self.network.map_udp(address)
                reply = stun.Message(
                    stun.Method.BINDING, stun.Class.RESPONSE, request.transaction_id
                )
                reply.attributes["XOR-MAPPED-ADDRESS"] = address
                self.transport.sendto(bytes(reply), address)


async def peer(role, settings):
    config = RelayConfig(**settings["relay"])
    if role == "host":
        async with open_host(relay=config) as host:
            print(host.code, flush=True)
            await host.wait_closed()
        return
    code = sys.stdin.readline().strip()
    async with connect(code, relay=config) as session:
        code = None
        ticket = session.ticket
        result = await session.run_argv(
            [
                sys.executable,
                "-c",
                "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read());sys.exit(7)",
            ],
            stdin=bytes(range(256)) * 4096,
        )
        assert result.stdout == bytes(range(256)) * 4096 and result.exit_code == 7, (
            len(result.stdout),
            result.exit_code,
            result.stderr[:1024],
        )
        observed = {"transport": session.transport}
        if session.transport == "direct-udp":
            pair = session.connection.writer.peer.sctp.transport.transport._connection._nominated[
                1
            ]
            observed.update(
                remote_type=pair.remote_candidate.type,
                remote_address=pair.remote_candidate.host,
            )
            assert pair.remote_candidate.type in ("srflx", "prflx")
            assert pair.remote_candidate.host.startswith("198.18.73.")
        assert session.transport == settings["expected"], observed
        print(json.dumps(observed), flush=True)
        if settings["scenario"] == "recover":
            with tempfile.TemporaryDirectory() as directory:
                marker = Path(directory) / "once"
                command = f"'{sys.executable}' -c \"import pathlib,time;pathlib.Path('{marker}').write_text('one');print('started',flush=True);time.sleep(60)\""
                async with session.exec(command) as process:
                    await process.close_stdin()
                    assert await process.stdout.readexactly(8) == b"started\n"
                    print(json.dumps({"phase": "drop-udp"}), flush=True)
                    assert sys.stdin.readline().strip() == "blocked"
                    try:
                        async with asyncio.timeout(60):
                            await process.wait()
                    except OutcomeUnknown:
                        pass
                    else:
                        raise AssertionError(
                            "Connection loss returned a confirmed command outcome"
                        )
                assert marker.read_text() == "one"
                async with connect(ticket, relay=config) as recovered:
                    assert recovered.transport == "relay"
                    assert (
                        await recovered.run_argv(
                            [sys.executable, "-c", "print('recovered')"]
                        )
                    ).stdout.strip() == b"recovered"
                    assert marker.read_text() == "one"
                    await recovered.close_host()
                print(
                    json.dumps({"recovered": "relay", "command_replayed": False}),
                    flush=True,
                )
        else:
            await session.close_host()


class Network:
    def __init__(self):
        self.prefix = "sn" + secrets.token_hex(3)
        self.namespaces = []
        self.links = []
        self.routers = []
        self.clients = []
        self.mappings = set()

    def run(self, *args):
        subprocess.run(args, check=True, capture_output=True)

    def setup(self):
        self.run("ip", "link", "set", "lo", "up")
        bridge = self.prefix + "w"
        self.run("ip", "link", "add", bridge, "type", "bridge")
        self.links.append(bridge)
        self.run("ip", "addr", "add", "198.18.73.1/24", "dev", bridge)
        self.run("ip", "link", "set", bridge, "up")
        for index in (1, 2):
            router, client = f"{self.prefix}r{index}", f"{self.prefix}c{index}"
            for name in (router, client):
                self.run("ip", "netns", "add", name)
                self.namespaces.append(name)
                self.run("ip", "-n", name, "link", "set", "lo", "up")
            self.routers.append(router)
            self.clients.append(client)
            inside, outside = f"{self.prefix}i{index}", f"{self.prefix}o{index}"
            self.run(
                "ip", "link", "add", inside, "type", "veth", "peer", "name", outside
            )
            self.links.extend((inside, outside))
            self.run("ip", "link", "set", inside, "netns", client)
            self.run("ip", "link", "set", outside, "netns", router)
            self.run("ip", "-n", client, "link", "set", inside, "name", "eth0")
            self.run("ip", "-n", router, "link", "set", outside, "name", "lan")
            wan, external = f"{self.prefix}u{index}", f"{self.prefix}e{index}"
            self.run("ip", "link", "add", wan, "type", "veth", "peer", "name", external)
            self.links.extend((wan, external))
            self.run("ip", "link", "set", wan, "netns", router)
            self.run("ip", "-n", router, "link", "set", wan, "name", "wan")
            self.run("ip", "link", "set", external, "master", bridge)
            self.run("ip", "link", "set", external, "up")
            self.run(
                "ip",
                "-n",
                router,
                "addr",
                "add",
                f"198.18.73.{10 + index}/24",
                "dev",
                "wan",
            )
            self.run(
                "ip", "-n", router, "addr", "add", f"10.201.{index}.1/24", "dev", "lan"
            )
            self.run(
                "ip", "-n", client, "addr", "add", f"10.201.{index}.2/24", "dev", "eth0"
            )
            self.run("ip", "-n", client, "link", "set", "eth0", "up")
            for interface in ("wan", "lan"):
                self.run("ip", "-n", router, "link", "set", interface, "up")
            self.run(
                "ip",
                "-n",
                client,
                "route",
                "add",
                "default",
                "via",
                f"10.201.{index}.1",
            )
            self.run(
                "ip", "netns", "exec", router, "sysctl", "-w", "net.ipv4.ip_forward=1"
            )
            command = ("ip", "netns", "exec", router, "iptables")
            self.run(*command, "-P", "FORWARD", "DROP")
            self.run(
                *command, "-A", "FORWARD", "-i", "lan", "-o", "wan", "-j", "ACCEPT"
            )
            self.run(
                *command,
                "-A",
                "FORWARD",
                "-i",
                "wan",
                "-o",
                "lan",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            )
            self.run(
                *command,
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                "wan",
                "-j",
                "MASQUERADE",
            )

    def map_udp(self, address):
        # Endpoint-independent, port-preserving mapping created by an outbound
        # STUN probe. The FORWARD filter still requires an outbound peer check
        # before inbound traffic passes, modelling port-restricted filtering.
        if address in self.mappings:
            return
        self.mappings.add(address)
        host, port = address
        index = int(host.rsplit(".", 1)[1]) - 10
        command = (
            "ip",
            "netns",
            "exec",
            self.routers[index - 1],
            "iptables",
            "-t",
            "nat",
        )
        self.run(
            *command,
            "-I",
            "POSTROUTING",
            "1",
            "-p",
            "udp",
            "--sport",
            str(port),
            "-j",
            "SNAT",
            "--to-source",
            f"{host}:{port}",
        )
        self.run(
            *command,
            "-A",
            "PREROUTING",
            "-i",
            "wan",
            "-p",
            "udp",
            "--dport",
            str(port),
            "-j",
            "DNAT",
            "--to-destination",
            f"10.201.{index}.2:{port}",
        )

    def block_udp(self, stun_port):
        for router in self.routers:
            self.run(
                "ip",
                "netns",
                "exec",
                router,
                "iptables",
                "-I",
                "FORWARD",
                "1",
                "-i",
                "lan",
                "-p",
                "udp",
                "!",
                "--dport",
                str(stun_port),
                "-j",
                "DROP",
            )

    def unblock_udp(self):
        for router in self.routers:
            self.run("ip", "netns", "exec", router, "iptables", "-D", "FORWARD", "1")

    def close(self):
        for name in reversed(self.namespaces):
            subprocess.run(["ip", "netns", "delete", name], capture_output=True)
        for name in reversed(self.links):
            subprocess.run(["ip", "link", "delete", name], capture_output=True)


async def lab():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise SystemExit("Run explicitly as root in a disposable Linux/WSL environment")
    network = Network()
    processes = []
    relay = None
    stun_transport = None
    try:
        network.setup()
        relay = await Relay().start(host="198.18.73.1")
        stun_transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: Stun(network), local_addr=("198.18.73.1", 0)
        )
        stun_port = stun_transport.get_extra_info("sockname")[1]
        config = dict(
            mailbox=f"ws://198.18.73.1:{relay.mailbox_port}/v1",
            transit=f"tcp://198.18.73.1:{relay.transit_port}",
            stun=f"stun:198.18.73.1:{stun_port}",
        )
        for scenario in ("direct", "blocked", "recover"):
            if scenario == "blocked":
                network.block_udp(stun_port)
            settings = dict(
                relay=config,
                scenario=scenario,
                expected="relay" if scenario == "blocked" else "direct-udp",
            )

            async def launch(role, namespace, peer_settings):
                process = await asyncio.create_subprocess_exec(
                    "ip",
                    "netns",
                    "exec",
                    namespace,
                    "runuser",
                    "-u",
                    "nobody",
                    "--",
                    sys.executable,
                    "-I",
                    str(Path(__file__).resolve()),
                    "--peer",
                    role,
                    json.dumps(peer_settings),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd="/var/tmp",
                    start_new_session=True,
                )
                processes.append(process)
                return process

            host = await launch("host", network.clients[0], settings)
            async with asyncio.timeout(30):
                code = await host.stdout.readline()
            if not code or host.returncode is not None:
                raise AssertionError((await host.stderr.read()).decode())
            client = await launch("operator", network.clients[1], settings)
            client.stdin.write(code)
            await client.stdin.drain()
            code = None
            observed = []
            async with asyncio.timeout(100):
                while line := await client.stdout.readline():
                    result = json.loads(line)
                    observed.append(result)
                    if result.get("phase") == "drop-udp":
                        network.block_udp(stun_port)
                        client.stdin.write(b"blocked\n")
                        await client.stdin.drain()
                await client.wait()
                if client.returncode:
                    raise AssertionError((await client.stderr.read()).decode())
                await host.wait()
                if host.returncode:
                    raise AssertionError((await host.stderr.read()).decode())
            print(json.dumps(dict(scenario=scenario, results=observed)), flush=True)
            if scenario in ("blocked", "recover"):
                network.unblock_udp()
    finally:
        for process in processes:
            if process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                await process.wait()
        if stun_transport:
            stun_transport.close()
        if relay:
            await relay.aclose()
        network.close()


if __name__ == "__main__":
    if sys.argv[1:2] == ["--peer"]:
        asyncio.run(peer(sys.argv[2], json.loads(sys.argv[3])))
    elif sys.argv[1:2] == ["--lab"]:
        asyncio.run(lab())
    else:
        if sys.platform != "linux" or os.geteuid() != 0:
            raise SystemExit(
                "Run explicitly as root in a disposable Linux/WSL environment"
            )
        # Isolate the WAN too, so the host's Docker/bridge firewall cannot
        # influence the simulated routers and no global network policy changes.
        namespace = "snake-wan-" + secrets.token_hex(4)
        subprocess.run(["ip", "netns", "add", namespace], check=True)
        try:
            subprocess.run(
                [
                    "ip",
                    "netns",
                    "exec",
                    namespace,
                    sys.executable,
                    "-I",
                    str(Path(__file__).resolve()),
                    "--lab",
                ],
                check=True,
            )
        finally:
            subprocess.run(["ip", "netns", "delete", namespace], check=True)
