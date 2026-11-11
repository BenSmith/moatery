#!/usr/bin/env python3
"""Copilot CLI in a hut: the host login sealed, the hut's policy, and the
CLI installed at a pinned release (docs/MOATHUT-COPILOT.md)."""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path


COPILOT_VERSION = "1.0.109"
ASSETS = {
    "x86_64": ("x64",
              "45a7f37e822e8c8725eda6b27deaed55dad"
              "2688ff4163ed27ec22e23293cb761"),
    "aarch64": ("arm64",
               "679db06c3168457d8154cd8ce93b822f7c"
               "46d3169e61da4c0b78ac6e110c4af6"),
}
PROVIDERS = (
    "api.githubcopilot.com",
    "api.individual.githubcopilot.com",
    "api.business.githubcopilot.com",
    "api.enterprise.githubcopilot.com",
)


class Error(ValueError):
    """A failed prerequisite, without credential contents in the message."""


def commented_json(text):
    tokens = r'"(?:\\.|[^"\\])*"|//[^\r\n]*|/\*[\s\S]*?\*/'
    text = re.sub(tokens, lambda m: m[0] if m[0][0] == '"' else " ", text)
    tokens = r'"(?:\\.|[^"\\])*"|,(?=\s*[}\]])'
    text = re.sub(tokens, lambda m: m[0] if m[0][0] == '"' else "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        raise Error("Unsupported Copilot configuration syntax") from None


def host_token(home):
    try:
        data = commented_json((home / "config.json").read_text())
        active = data["lastLoggedInUser"]
        if active["host"] != "https://github.com":
            raise Error("This recipe supports github.com accounts only")
        base = f"{active['host']}:{active['login']}"
        records = data["authTokens"]
        key = base + ":github" if base + ":github" in records else base
        token = records[key]["token"]
        if not isinstance(token, str) or not re.fullmatch(
                r"gho_[A-Za-z0-9_]{20,}", token):
            raise Error("The active account has no stored OAuth token")
        return token
    except (OSError, KeyError, TypeError):
        raise Error("No supported plaintext host Copilot login; keychain "
                    "and other credential stores are not imported") from None


def enroll(home, moathut):
    token = host_token(home)
    argv = [moathut, "credential", "add", "copilot",
            "--env", "COPILOT_GITHUB_TOKEN",
            "--auth-header", "Authorization",
            "--auth-format", "Bearer {secret}",
            "--placeholder-prefix", "gho_"]
    for host in ("api.github.com", *PROVIDERS):
        argv.extend(("--host", host))
    subprocess.run(argv, input=token, text=True, check=True)
    print("Host OAuth token sealed; host login unchanged.")


def policy():
    entries = [{
        "host": "api.github.com", "methods": ["GET"],
        "paths": ["/user", "/copilot_internal/user",
                  "/copilot_internal/managed_settings",
                  "/copilot_internal/content_exclusion",
                  "/copilot_internal/team_customizations",
                  "/copilot/mcp_registry",
                  "/repos/github/copilot-cli/releases",
                  "/repos/github/copilot-cli/releases/latest"],
        "credential": "copilot",
    }]
    for host in PROVIDERS:
        entries.extend((
            {"host": host, "methods": ["GET"],
             "paths": ["/meta", "/models", "/responses",
                       "/agents/swe/internal/memory/v0/enabled"],
             "credential": "copilot"},
            {"host": host, "methods": ["POST"],
             "paths": ["/responses", "/chat/completions",
                       "/v1/messages", "/mcp/readonly"],
             "credential": "copilot"},
        ))
    return {"hosts": ["github.com", "*.githubusercontent.com",
                      "exp.githubcopilot.com", "exp.*.githubcopilot.com"],
            "policy": entries}


def version_matches(binary):
    try:
        result = subprocess.run(
            [str(binary), "--version"], capture_output=True,
            text=True, check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return (result.returncode == 0
            and result.stdout.splitlines()[:1]
            == [f"GitHub Copilot CLI {COPILOT_VERSION}."])


def install(home):
    if platform.system() != "Linux" or platform.machine() not in ASSETS:
        raise Error("The pinned installer supports Linux x86_64 and aarch64")
    target = home / ".local/bin/copilot"
    if target.is_file() and version_matches(target):
        print(f"Copilot {COPILOT_VERSION} is already installed.")
        return
    arch, digest = ASSETS[platform.machine()]
    url = ("https://github.com/github/copilot-cli/releases/download/"
           f"v{COPILOT_VERSION}/copilot-linux-{arch}.tar.gz")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".copilot-",
                                     dir=target.parent) as directory:
        archive = Path(directory) / "release.tar.gz"
        with urllib.request.urlopen(url, timeout=60) as response, \
                archive.open("wb") as stream:
            shutil.copyfileobj(response, stream)
        with archive.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise Error("Copilot archive checksum mismatch")
        binary = Path(directory) / "copilot"
        with tarfile.open(archive, "r:gz") as release:
            member = release.getmember("copilot")
            if not member.isfile():
                raise Error("Copilot archive has no regular binary")
            with release.extractfile(member) as source, \
                    binary.open("wb") as out:
                shutil.copyfileobj(source, out)
        binary.chmod(0o755)
        if not version_matches(binary):
            raise Error("Downloaded binary did not report the pinned version")
        os.replace(binary, target)
    print(f"Copilot {COPILOT_VERSION} installed in {target}.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--moathut", default="moathut",
                        help="host moathut executable")
    parser.add_argument("--copilot-home", type=Path,
                        default=Path(os.environ.get(
                            "COPILOT_HOME", str(Path.home() / ".copilot"))),
                        help="existing host Copilot state directory")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("enroll", help="seal the active host OAuth token")
    sub.add_parser("policy", help="print a policy for all account backends")
    sub.add_parser("install", help="install the pinned CLI inside the hut")
    args = parser.parse_args(argv)
    try:
        if args.command == "enroll":
            enroll(args.copilot_home, args.moathut)
        elif args.command == "policy":
            print(json.dumps(policy(), indent=2))
        else:
            install(Path.home())
    except (OSError, subprocess.SubprocessError, tarfile.TarError,
            ValueError) as error:
        print(f"copilot-hut: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
