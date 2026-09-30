#!/usr/bin/env python3
"""Loopback-only warm workload for the opt-in development VM proof."""
import json
import os
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class Handler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        path = urlsplit(self.path).path
        if path not in ("/health", "/state", "/timer"):
            return super().do_GET()
        if path == "/timer":
            started = time.monotonic()
            time.sleep(0.1)
            value = {"elapsed": time.monotonic() - started}
        elif path == "/health":
            value = {"ready": True}
        else:
            with self.server.counter_lock:
                self.server.counter += 1
                count = self.server.counter
            value = dict(pid=os.getpid(), counter=count, entropy=os.urandom(32).hex(),
                         monotonic=time.monotonic(), wall_time=time.time(),
                         age=time.monotonic() - self.server.started_mono)
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ProofServer(ThreadingHTTPServer):
    def __init__(self, address):
        super().__init__(address, Handler)
        self.counter = 0
        self.counter_lock = threading.Lock()
        self.started_mono = time.monotonic()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=38973)
    args = parser.parse_args()
    with ProofServer(("127.0.0.1", args.port)) as server:
        server.serve_forever()
