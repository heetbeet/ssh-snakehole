"""Independent upstream Magic Wormhole peer against our mailbox/PAKE phases."""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
loop = asyncio.SelectorEventLoop()
# Twisted must select the asyncio reactor before importing Wormhole.
from twisted.internet import asyncioreactor  # noqa: E402

asyncioreactor.install(loop)
from twisted.internet import reactor  # noqa: E402
from wormhole import create  # noqa: E402

from ssh_snakehole.pairing import APPID, Pairing  # noqa: E402
from ssh_snakehole.relay import Relay  # noqa: E402


async def main():
    relay = await Relay().start()
    url = f"ws://127.0.0.1:{relay.mailbox_port}/v1"
    ours = await Pairing.open(url)
    native = None
    try:
        code = await ours.allocate()
        native = create(APPID, url, reactor, versions={"ssh-snakehole": 3})
        native.set_code(code)
        establish = asyncio.create_task(ours.establish())
        await native.get_verifier().asFuture(loop)
        await establish
        await ours.send("0", {"hello": "independent peer"})
        assert json.loads(await native.get_message().asFuture(loop)) == {
            "hello": "independent peer"
        }
        native.send_message(b'{"reply":"authenticated"}')
        assert await ours.receive("0") == {"reply": "authenticated"}
        print(
            "Upstream Magic Wormhole peer: code, SPAKE2, version and encrypted phases passed"
        )
    finally:
        async with asyncio.timeout(5):
            await ours.aclose()
        if native:
            await asyncio.wait_for(native.close().asFuture(loop), 5)
        async with asyncio.timeout(5):
            await relay.aclose()


reactor.startRunning(installSignalHandlers=False)
loop.run_until_complete(main())
reactor.fireSystemEvent("shutdown")
loop.close()
