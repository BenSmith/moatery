#!/usr/bin/env python3
"""shape2_guest.py -- the probes one shape-2 boot makes from inside the VM.

The guest half of tests/manual/shape2_rig.py. The NoCloud seed writes it
into the guest and a small systemd unit runs it; it reports raw
observations -- an answer, a status, a send outcome -- as
``CUSTOMS-RIG {json}`` lines on a virtio-serial port the host reads as a
file. The serial console stays for boot diagnostics, because writing
results there competes with the kernel console and the getty.

The names and addresses below are shape2_rig.py's; the two files are read
side by side and ship together, so they are repeated rather than imported.
"""

import http.client
import json
import os
import select
import socket
import ssl
import struct
import subprocess
import sys
import time

PROVIDER = "provider.test"
UNLISTED = "unlisted.test"
MAP = "169.254.1.3"
ELSEWHERE = "192.0.2.53"
CA = "/etc/customs-rig/bundle.pem"
PLACEHOLDER = "sk-placeholder"
DROP_PORT = 8081
TEST_NET = "192.0.2.1"
TRUST_VARS = ("SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS",
              "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO", "PIP_CERT",
              "EXAMPLE_API_KEY")
PORTS = ("/dev/virtio-ports/customs-rig", "/dev/vport0p1")

_out = None


def emit(probe, **fields):
    global _out
    line = ("CUSTOMS-RIG " + json.dumps({"probe": probe, **fields})
            + "\n").encode()
    if _out is None:
        for path in PORTS:
            if os.path.exists(path):
                _out = open(path, "wb", buffering=0)
                break
    if _out is not None:
        _out.write(line)
    else:
        sys.stdout.buffer.write(line)
        sys.stdout.flush()


def resolver():
    """The DNS server to query directly.

    systemd-resolved is in front of /etc/resolv.conf (127.0.0.53), and
    this file's queries are raw, so the uplink file is preferred: the
    query reaches passt's forwarder without resolved's own special cases.
    """
    for path in ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"):
        try:
            with open(path) as fh:
                for line in fh:
                    if line.startswith("nameserver"):
                        return line.split()[1]
        except OSError:
            pass
    return None


def dns_query(server, name, qtype, transport):
    """One query, as riglib.DNS_LOOKUP makes it: the first address,
    "nodata", "rcode N", "timeout", or the error class."""
    t = 28 if qtype == "AAAA" else 1
    q = (struct.pack("!6H", 0x5a18, 0x0100, 1, 0, 0, 0)
         + b"".join(bytes([len(x)]) + x.encode()
                    for x in name.split("."))
         + b"\0" + struct.pack("!2H", t, 1))
    try:
        if transport == "tcp":
            s = socket.create_connection((server, 53), timeout=5)
            s.sendall(struct.pack("!H", len(q)) + q)
            head = s.recv(2)
            n = struct.unpack("!H", head)[0] if len(head) == 2 else 0
            r = b""
            while len(r) < n:
                chunk = s.recv(n - len(r))
                if not chunk:
                    break
                r += chunk
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.sendto(q, (server, 53))
            r = s.recv(512)
    except TimeoutError:
        return "timeout"
    except OSError as exc:
        return type(exc).__name__
    if r[:2] != q[:2]:
        return "garbled"
    if r[3] & 0xF:
        return f"rcode {r[3] & 0xF}"
    if struct.unpack("!H", r[6:8])[0] == 0:
        return "nodata"
    size, family = (16, socket.AF_INET6) if t == 28 else (4, socket.AF_INET)
    return socket.inet_ntop(family, r[-size:])


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """A connection to the address the responder gave, with the name in
    SNI, so a request does not depend on the guest's stub resolver and
    the address that is dialled is the one the DNS row observed."""

    def __init__(self, host, address, **kw):
        super().__init__(host, **kw)
        self._address = address

    def connect(self):
        sock = socket.create_connection((self._address, self.port),
                                        self.timeout)
        self.sock = self._context.wrap_socket(sock,
                                              server_hostname=self.host)


def http(host, path, headers=None):
    """One request through the guest's client stack: status, Server, body."""
    address = dns_query(resolver(), host, "A", "udp")
    if address != MAP:
        return {"error": f"resolve {host}: {address}"}
    ctx = ssl.create_default_context(cafile=CA)
    conn = PinnedHTTPSConnection(host, address, context=ctx, timeout=20)
    try:
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        return {"status": resp.status,
                "server": resp.getheader("Server"),
                "body": resp.read(65536).decode("utf-8", "replace")}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    finally:
        conn.close()


def dns_rows(server):
    tag = os.urandom(4).hex()
    names = {k: f"{k}-{tag}.exfil.test"
             for k in ("udp", "tcp", "elsewhere", "aaaa")}
    for label, qname, qtype, transport, target in (
            ("udp", names["udp"], "A", "udp", server),
            ("tcp", names["tcp"], "A", "tcp", server),
            ("elsewhere", names["elsewhere"], "A", "udp", ELSEWHERE),
            ("aaaa", names["aaaa"], "AAAA", "udp", server),
            ("provider", PROVIDER, "A", "tcp", ELSEWHERE)):
        emit("dns", label=label, server=target, name=qname, qtype=qtype,
             transport=transport,
             result=dns_query(target, qname, qtype, transport))


def tcp_probe():
    """A connect to a map port nothing accepts: the egress chain drops it.
    A non-blocking connect with its own deadline, so a lost packet is a
    timeout rather than the kernel's much longer SYN retry."""
    s = socket.socket()
    s.setblocking(False)
    started = time.time()
    try:
        s.connect((MAP, DROP_PORT))
        result = "connected"
    except BlockingIOError:
        _, writable, _ = select.select([], [s], [], 6)
        if writable:
            err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            result = "connected" if err == 0 else f"errno {err}"
        else:
            result = "timeout"
    except OSError as exc:
        result = type(exc).__name__
    finally:
        s.close()
    emit("tcp", port=DROP_PORT, result=result,
         seconds=round(time.time() - started, 2))


def main():
    emit("boot", netns=os.readlink("/proc/self/ns/net"),
         python=sys.version.split()[0])
    emit("resolver", server=resolver())
    emit("env", vars={k: v for k, v in os.environ.items()
                      if k in TRUST_VARS})
    try:
        tables = subprocess.run(["nft", "list", "tables"],
                                capture_output=True, text=True,
                                timeout=10).stdout.splitlines()
    except (OSError, subprocess.SubprocessError) as exc:
        emit("nft", tables=None, error=type(exc).__name__)
    else:
        emit("nft", tables=tables)
    dns_rows(resolver())
    emit("http", label="provider",
         **http(PROVIDER, "/v1/probe",
                {"Authorization": f"Bearer {PLACEHOLDER}"}))
    emit("http", label="unlisted", **http(UNLISTED, "/"))
    for port in (9, 443):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(b"x", (TEST_NET, port))
            emit("udp", port=port, result="sent")
        except OSError as exc:
            emit("udp", port=port, result=type(exc).__name__)
        finally:
            s.close()
    tcp_probe()
    emit("done")


if __name__ == "__main__":
    main()
