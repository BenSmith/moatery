#!/usr/bin/env python3
"""copilot_rig.py — Copilot CLI in a hut, against GitHub's real API.

docs/MOATHUT-COPILOT.md: the recipe's sealed host login, its policy and
its pinned CLI, in a hut made by the guide's steps 1 to 3. Run on the
host, as the hut's user, from a checkout:

    python3 tests/manual/copilot_rig.py NAME [--restart] [--plant]
                                             [--probe-permitted]

It makes one real inference request, which Copilot counts as usage.
--restart stops the hut first, so the rows run in a fresh start of it;
that interrupts whatever is running in it.

The rig pipes itself into the hut (`moathut enter NAME -- python3 -
probe ...`). What runs there sends the requests and reports what it
saw; the rows are judged on the host, beside the hut's record.

Break flags, each of which must turn its rows red:

  --plant            a decoy token is written in the hut's home and the
                     scan looks for it in place of the host's token.
  --probe-permitted  the refusal probes go to a route the policy
                     permits, so no drop is recorded.
"""

import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

PERMITTED = ("api.github.com", "GET", "/copilot_internal/user")
MARKER = "MOATHUT_COPILOT_OK"


# --- inside the hut: the standard library only ------------------------------

def request(url, token, method="GET", body=None, extra=None):
    headers = {"Authorization": "Bearer " + token,
               "User-Agent": "moatery-copilot-rig",
               "Accept": "application/json, text/event-stream"}
    headers.update(extra or {})
    if body is not None:
        body = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as error:
        error.close()
        return error.code, b"", {}


def rpc_result(body):
    if body.lstrip().startswith(b"{"):
        return json.loads(body).get("result")
    for line in body.splitlines():
        if line.startswith(b"data:"):
            return json.loads(line[5:]).get("result")
    return None


def get_me(provider, token):
    """GitHub MCP's read-only get_me, through /mcp/readonly: whether it
    answered without an error. The account details are not kept."""
    headers = {"MCP-Protocol-Version": "2025-03-26",
               "X-MCP-Tools": "get_me"}
    calls = (("initialize", {"protocolVersion": "2025-03-26",
                             "capabilities": {},
                             "clientInfo": {"name": "moatery-copilot-rig",
                                            "version": "1"}}),
             ("notifications/initialized", {}),
             ("tools/call", {"name": "get_me", "arguments": {}}))
    for number, (method, params) in enumerate(calls):
        message = {"jsonrpc": "2.0", "method": method, "params": params}
        if method != "notifications/initialized":
            message["id"] = number
        status, body, answered = request(
            provider + "/mcp/readonly", token, "POST", message, headers)
        if status not in (200, 202, 204):
            return f"{method} answered {status}"
        if "id" in message:
            result = rpc_result(body)
            if result is None or result.get("isError"):
                return f"{method} returned no result"
        for key, value in answered.items():
            if key.lower() == "mcp-session-id":
                headers["Mcp-Session-Id"] = value
    return "ok"


def scan_home(home, length, fingerprint):
    """Whether a regular file under home holds a gho_ string of the given
    length and fingerprint. Symlinks are not followed."""
    for directory, _, filenames in os.walk(home, followlinks=False):
        for filename in filenames:
            path = Path(directory) / filename
            try:
                if not stat.S_ISREG(path.lstat().st_mode):
                    continue
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW
                             | os.O_NONBLOCK)
            except OSError:
                return f"unreadable: {path}"
            with os.fdopen(fd, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    continue
                carry = b""
                while block := stream.read(1024 * 1024):
                    block = carry + block
                    for match in re.finditer(rb"gho_", block):
                        value = block[match.start():match.start() + length]
                        if hashlib.sha256(value).hexdigest() == fingerprint:
                            return f"found: {path}"
                    carry = block[-length:]
    return "absent"


def probe(spec):
    """Every observation the rows need, as one JSON object on stdout."""
    seen = {}
    token = os.environ.get("COPILOT_GITHUB_TOKEN", "")
    seen["shape"] = token.startswith("gho_")
    seen["is_host_token"] = (
        hashlib.sha256(token.encode()).hexdigest() == spec["token_sha"])
    status, body, _ = request(
        "https://api.github.com/copilot_internal/user", token)
    seen["user"] = status
    provider = ""
    if status == 200:
        provider = json.loads(body).get("endpoints", {}).get("api", "")
        provider = provider.rstrip("/")
    seen["provider"] = provider
    # The placeholder goes to the endpoint the account names only once it
    # is one of the policy's backends.
    if provider in spec["providers"]:
        seen["models"] = request(provider + "/models", token)[0]
        seen["get_me"] = get_me(provider, token)
        refused = {}
        for host, method, path in spec["refusals"]:
            host = provider.removeprefix("https://") if host == "*" else host
            refused[f"{method} {host}{path}"] = request(
                f"https://{host}{path}", token, method,
                {} if method == "POST" else None)[0]
        seen["refused"] = refused
        result = subprocess.run(
            [str(Path.home() / ".local/bin/copilot"), "--silent",
             "--disable-client-telemetry", "--no-custom-instructions",
             "--no-auto-update", "-p",
             f"Reply only {MARKER}. Do not use tools."],
            capture_output=True, text=True, check=False, timeout=180)
        seen["inference"] = (result.returncode == 0
                             and result.stdout.strip() == MARKER)
    if spec["plant"]:
        decoy = Path.home() / ".moatery-copilot-rig-decoy"
        decoy.write_text(spec["plant"])
        try:
            seen["scan"] = scan_home(Path.home(), spec["scan_length"],
                                     spec["scan_sha"])
        finally:
            decoy.unlink()
    else:
        seen["scan"] = scan_home(Path.home(), spec["scan_length"],
                                 spec["scan_sha"])
    print(json.dumps(seen))


# --- on the host ------------------------------------------------------------

def host_main(argv):
    import argparse

    from riglib import CHECKOUT, report, row, run, say
    from moatery.egress_record import DROP_NOT_PERMITTED
    from moathut.paths import Hut, user_dirs, valid_name
    from tests import load_script

    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0])
    parser.add_argument("name")
    parser.add_argument("--moathut", default="moathut")
    parser.add_argument("--restart", action="store_true")
    parser.add_argument("--plant", action="store_true")
    parser.add_argument("--probe-permitted", action="store_true")
    args = parser.parse_args(argv)
    if not valid_name(args.name):
        sys.exit(f"{args.name!r} is not a hut's name")

    recipe = load_script("examples/copilot/copilot_hut.py")
    home = Path(os.environ.get("COPILOT_HOME",
                               str(Path.home() / ".copilot")))
    token = recipe.host_token(home)
    token_sha = hashlib.sha256(token.encode()).hexdigest()
    refusals = [("api.github.com", "GET", "/copilot_internal/v2/token"),
                ("*", "POST", "/mcp"), ("*", "POST", "/agents/sessions")]
    if args.probe_permitted:
        refusals = [PERMITTED] * len(refusals)
    plant = ""
    scan_length, scan_sha = len(token), token_sha
    if args.plant:
        plant = "gho_" + secrets.token_hex(18)
        scan_length = len(plant)
        scan_sha = hashlib.sha256(plant.encode()).hexdigest()
    spec = {"token_sha": token_sha,
            "providers": [f"https://{h}" for h in recipe.PROVIDERS],
            "refusals": refusals, "plant": plant,
            "scan_length": scan_length, "scan_sha": scan_sha}

    record = Hut(args.name, user_dirs()).record
    say(f"premise: hut {args.name}, record {record}, checkout {CHECKOUT}")
    with record.open() as records:
        records.seek(0, os.SEEK_END)
        if args.restart:
            run([args.moathut, "stop", args.name], timeout=120)
        result = run([args.moathut, "enter", args.name, "--", "python3",
                      "-", "probe", json.dumps(spec)],
                     input=Path(__file__).read_text(), check=False,
                     timeout=420)
        if result.returncode:
            say(result.stderr[-2000:])
            sys.exit(f"the probe exited {result.returncode}")
        seen = json.loads(result.stdout.splitlines()[-1])
        rows = []
        deadline = time.monotonic() + 5
        while True:
            rows += [json.loads(ln) for ln in records if ln.strip()]
            drops = {(r.get("method"), r.get("host"), r.get("path"))
                     for r in rows if r.get("decision") == "drop"
                     and r.get("reason") == DROP_NOT_PERMITTED
                     and not r.get("credential")}
            if len(drops) >= len(refusals) or time.monotonic() > deadline:
                break
            time.sleep(0.5)

    row("the hut holds a gho_ placeholder, not the host's token",
        seen["shape"] and not seen["is_host_token"],
        f"gho_ shape {seen['shape']}, "
        f"is the host's token {seen['is_host_token']}")
    row("a brokered account check answers, naming a policy backend",
        seen["user"] == 200 and seen["provider"] in spec["providers"],
        f"status {seen['user']}, backend {seen['provider'] or 'none'}")
    if "models" not in seen:
        return report()
    row("the backend's model list answers", seen["models"] == 200,
        f"status {seen['models']}")
    row("GitHub MCP's read-only get_me answers", seen["get_me"] == "ok",
        seen["get_me"])
    for key, status in seen["refused"].items():
        method, _, rest = key.partition(" ")
        host, _, path = rest.partition("/")
        logged = (method, host, "/" + path) in drops
        row(f"{key} is refused by the policy, in a new record",
            status == 403 and logged,
            f"status {status}, drop recorded {logged}")
    row("Copilot answers an inference request", seen["inference"],
        f"marker {'returned' if seen['inference'] else 'missing'}")
    row("the token is in no regular file of the hut's home",
        seen["scan"] == "absent",
        seen["scan"] + (" (planted decoy)" if plant else ""))
    flags = [f for f in ("--plant", "--probe-permitted")
             if getattr(args, f[2:].replace("-", "_"))]
    return report(f"{', '.join(flags)} must turn rows red" if flags
                  else None)


if __name__ == "__main__":
    if sys.argv[1:2] == ["probe"]:
        probe(json.loads(sys.argv[2]))
    else:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        sys.exit(host_main(sys.argv[1:]))
