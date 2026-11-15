"""Byte deletion with a caller-supplied predicate for the same error and site."""
from collections.abc import Callable


def minimize(data: bytes, predicate: Callable[[bytes], bool], max_attempts: int = 200) -> tuple[bytes, int]:
    attempts = 0
    granularity = 2
    # shortcut: bounded attempts may stop before a minimum; increase the budget for large PoCs.
    while data and attempts < max_attempts:
        chunk = max(1, (len(data) + granularity - 1) // granularity)
        for start in range(0, len(data), chunk):
            candidate = data[:start] + data[start + chunk:]
            attempts += 1
            if predicate(candidate):
                data = candidate
                granularity = max(2, granularity - 1)
                break
            if attempts >= max_attempts:
                return data, attempts
        else:
            if granularity >= len(data):
                break
            granularity = min(len(data), granularity * 2)
    return data, attempts
