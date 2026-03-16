#!/usr/bin/env python3
"""
pipeline/traffic_capture.py
────────────────────────────
Phase 2 – Live Traffic Capture via Zeek

Watches the Zeek conn.log (JSON format) that Zeek writes to /logs/zeek/.
Each new line = one closed TCP/UDP flow.

The module tails the log, parses each flow record, and hands it to
feature_extractor.CICFlowExtractor to convert it into a CIC-IDS feature vector.

The extracted features are then queued for the XGBoost inference engine.
"""

import json
import os
import queue
import threading
import time
from datetime import datetime
from typing import Generator


ZEEK_LOG_DIR  = os.getenv("ZEEK_LOG_DIR", "/logs/zeek")
CONN_LOG_NAME = "conn.log"


class ZeekConnRecord:
    """Parsed fields from a Zeek conn.log JSON line."""

    __slots__ = (
        "ts", "uid", "src_ip", "src_port", "dst_ip", "dst_port",
        "proto", "duration", "orig_bytes", "resp_bytes",
        "orig_pkts", "resp_pkts", "conn_state", "orig_ip_bytes", "resp_ip_bytes",
    )

    def __init__(self, d: dict):
        self.ts           = float(d.get("ts", 0))
        self.uid          = d.get("uid", "")
        self.src_ip       = d.get("id.orig_h", "")
        self.src_port     = int(d.get("id.orig_p", 0))
        self.dst_ip       = d.get("id.resp_h", "")
        self.dst_port     = int(d.get("id.resp_p", 0))
        self.proto        = d.get("proto", "")
        self.duration     = float(d.get("duration", 0) or 0)
        self.orig_bytes   = int(d.get("orig_bytes", 0) or 0)
        self.resp_bytes   = int(d.get("resp_bytes", 0) or 0)
        self.orig_pkts    = int(d.get("orig_pkts", 0) or 0)
        self.resp_pkts    = int(d.get("resp_pkts", 0) or 0)
        self.conn_state   = d.get("conn_state", "")
        self.orig_ip_bytes = int(d.get("orig_ip_bytes", 0) or 0)
        self.resp_ip_bytes = int(d.get("resp_ip_bytes", 0) or 0)

    @property
    def timestamp_dt(self) -> datetime:
        return datetime.utcfromtimestamp(self.ts)


def _tail_file(filepath: str) -> Generator[str, None, None]:
    """Generator that yields new lines as Zeek appends them."""
    while not os.path.exists(filepath):
        time.sleep(1)

    with open(filepath, "r") as fh:
        fh.seek(0, 2)          # seek to end
        while True:
            line = fh.readline()
            if line:
                yield line.rstrip()
            else:
                # Detect rotation
                try:
                    if os.stat(filepath).st_ino != os.fstat(fh.fileno()).st_ino:
                        fh = open(filepath, "r")
                except FileNotFoundError:
                    pass
                time.sleep(0.05)


class ZeekCapture:
    """
    Background thread that tails Zeek's conn.log and puts parsed
    ZeekConnRecord objects into a thread-safe queue.
    """

    def __init__(self, log_dir: str = ZEEK_LOG_DIR):
        self.log_dir  = log_dir
        self.queue: queue.Queue = queue.Queue(maxsize=10_000)
        self._thread  = threading.Thread(target=self._run, daemon=True)
        self._running = False

    def start(self):
        self._running = True
        self._thread.start()

    def stop(self):
        self._running = False

    def _run(self):
        log_path = os.path.join(self.log_dir, CONN_LOG_NAME)
        for raw_line in _tail_file(log_path):
            if not self._running:
                break
            if not raw_line or raw_line.startswith("#"):
                continue                # Zeek header / comment lines
            try:
                d = json.loads(raw_line)
                rec = ZeekConnRecord(d)
                self.queue.put_nowait(rec)
            except (json.JSONDecodeError, ValueError):
                pass

    def get_record(self, timeout: float = 0.5) -> ZeekConnRecord | None:
        try:
            return self.queue.get(timeout=timeout)
        except queue.Empty:
            return None
