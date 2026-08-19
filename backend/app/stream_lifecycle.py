"""Streaming helpers whose work lifetime is independent from HTTP clients."""

from __future__ import annotations

import queue
import threading
from collections.abc import Iterable, Iterator
from typing import Any


def run_stream_in_background(
    producer: Iterable[Any],
    analysis_id: str,
    error_chunk: Any | None = None,
) -> Iterator[Any]:
    """Relay output while allowing ``producer`` to outlive its browser stream."""

    output: queue.Queue = queue.Queue()
    finished = object()
    client_connected = threading.Event()
    client_connected.set()

    def consume() -> None:
        try:
            for chunk in producer:
                if client_connected.is_set():
                    output.put(chunk)
        except Exception as exc:
            print(f"Detached analysis stream failed ({analysis_id}): {exc}")
            if client_connected.is_set() and error_chunk is not None:
                output.put(error_chunk)
        finally:
            if client_connected.is_set():
                output.put(finished)

    threading.Thread(
        target=consume,
        name=f"analysis-{analysis_id[:24]}",
        daemon=True,
    ).start()

    def relay() -> Iterator[Any]:
        try:
            while True:
                item = output.get()
                if item is finished:
                    return
                yield item
        finally:
            # Stop forwarding only. The producer deliberately keeps running.
            client_connected.clear()

    return relay()
