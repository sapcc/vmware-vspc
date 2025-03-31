import asyncio
from collections.abc import Iterable


def run_async(awaitable):
    """Run one or more awaitables untiil they ar ecomplete

    If multiple awaitables are given as list or tuple, we use asyncio.gather to
    await all of them and return the results.
    """
    loop = asyncio.get_event_loop()
    if isinstance(awaitable, Iterable):
        awaitable = asyncio.gather(*awaitable)
    return loop.run_until_complete(awaitable)
