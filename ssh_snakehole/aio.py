"""Finish bounded file operations before cancellation can close their handles."""

import asyncio
import contextvars
import os
import stat


def open_regular(path):
    fd = os.open(
        path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("A regular file is required")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


async def close_stream(writer):
    """Bound shutdown even when a TLS peer never completes its close handshake."""
    writer.close()
    try:
        async with asyncio.timeout(2):
            await writer.wait_closed()
    except BaseException as exc:
        writer.transport.abort()
        if isinstance(exc, asyncio.CancelledError):
            raise


async def file_call(function, *args):
    work = asyncio.get_running_loop().run_in_executor(
        None, contextvars.copy_context().run, function, *args
    )
    cancelled = False
    try:
        while True:
            try:
                return await asyncio.shield(work)
            except asyncio.CancelledError:
                cancelled = True
                if work.cancelled():
                    raise
    finally:
        if cancelled:
            raise asyncio.CancelledError
