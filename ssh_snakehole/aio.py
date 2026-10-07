"""Finish bounded file operations before cancellation can close their handles."""
import asyncio


async def file_call(function,*args):
    task=asyncio.create_task(asyncio.to_thread(function,*args))
    try: return await asyncio.shield(task)
    except asyncio.CancelledError:
        try: await task
        finally: raise
