#!/usr/bin/env python3
"""A stand-in for the credential's provider, so no real key is in the loop.

    stub_provider.py PORT CERT KEY      with the key in $STUB_SECRET

Answers 200 to a request carrying `Authorization: Bearer <the key>` and 401
to anything else, and in either case reports in the body which
Authorization value arrived. Both halves are load-bearing. The 401 is what
makes "the origin with no key" a probe that measures something: a stub
that said 200 to everything would pass a broker that attached nothing.
The echoed value is what makes the 200 mean the *real* key arrived, from
the far side, rather than any 200 at all.

TLS, because both programs refuse a plaintext upstream and are right to;
the leg that carries the real credential is the one this exercises.

`/slow/N/...`, with the key, is a download that takes a while: N chunks of
SLOW_CHUNK bytes, chunk i all byte i % 256, SLOW_PAUSE seconds apart, so
something can happen while it runs.
"""
import http.server
import json
import os
import ssl
import sys
import time

PORT = int(sys.argv[1])
CERT, KEY = sys.argv[2], sys.argv[3]
SECRET = os.environ["STUB_SECRET"]
SLOW_CHUNK = 64 * 1024
SLOW_PAUSE = 0.1


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # The Server the workload must see on a brokered response: the
    # provider's, relayed, and not one the broker stamps. riglib.STUB_SERVER.
    server_version = "stub-provider/1"
    sys_version = ""

    def log_message(self, fmt, *args):
        print(f"stub: {self.address_string()} {fmt % args}", flush=True)

    def _reply(self):
        got = self.headers.get("authorization", "")
        status = 200 if got == f"Bearer {SECRET}" else 401
        parts = self.path.split("/")
        if status == 200 and parts[1:2] == ["slow"] and parts[2:3] \
                and parts[2].isdigit():
            self._slow(int(parts[2]))
            return
        body = json.dumps({"path": self.path, "authorization": got,
                           "status": status}).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _slow(self, chunks):
        self.send_response(200)
        self.send_header("content-type", "application/octet-stream")
        self.send_header("content-length", str(chunks * SLOW_CHUNK))
        self.end_headers()
        for i in range(chunks):
            self.wfile.write(bytes([i % 256]) * SLOW_CHUNK)
            self.wfile.flush()
            time.sleep(SLOW_PAUSE)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _reply


if __name__ == "__main__":
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"stub provider on 127.0.0.1:{PORT}", flush=True)
    srv.serve_forever()
