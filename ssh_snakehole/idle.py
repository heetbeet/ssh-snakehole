"""Host-owned inactivity clock, paused while authenticated work is active."""

import asyncio
import contextlib
import math
import time


class Idle:
    def __init__(self, timeout: float):
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 0 < timeout <= 1800
        ):
            raise ValueError("Inactivity timeout must be between 0 and 1800 seconds")
        self.timeout = timeout
        self.active = 0
        self.changed = asyncio.Event()
        self.deadline = time.monotonic() + timeout

    def touch(self):
        self.deadline = time.monotonic() + self.timeout
        self.changed.set()

    @contextlib.contextmanager
    def operation(self):
        self.active += 1
        self.changed.set()
        try:
            yield
        finally:
            self.active -= 1
            self.touch()

    async def wait_expired(self):
        while True:
            self.changed.clear()
            delay = None if self.active else max(0, self.deadline - time.monotonic())
            try:
                async with asyncio.timeout(delay):
                    await self.changed.wait()
            except TimeoutError:
                if not self.active and time.monotonic() >= self.deadline:
                    return
