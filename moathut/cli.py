"""moathut's command line: parse, hand the environment in, report."""

import argparse
import getpass
import os
import signal
import sys
from pathlib import Path

from .commands import (DEFAULT_IMAGE, DEFAULT_LIBEXEC, HutError, allow,
                       create, credential_add, credential_ls, credential_rm,
                       edit_policy, enter, log, ls, ptyxis_add,
                       ptyxis_remove, refused, rm, stop, unit_exec,
                       unit_netns, unit_rotate, unit_sudoers)
from .netns import NetnsError
from .paths import user_dirs
from .process import CommandFailed

PUBLIC = ("{create,enter,log,allow,network-policy,stop,rm,ls,"
          "credential,ptyxis}")

# The release's VERSION, which the RPM installs beside the package.
VERSION = Path(__file__).with_name("VERSION")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="moathut",
        description="long-lived, inspected containers for command-line "
                    "workloads")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {VERSION.read_text().strip()}")
    sub = parser.add_subparsers(dest="command", required=True,
                                metavar=PUBLIC)
    p = sub.add_parser("create", help="lay out a hut; nothing starts")
    p.add_argument("name")
    p.add_argument("--network-policy", metavar="FILE",
                   help="the inspector's policy document, copied in")
    p.add_argument("--image",
                   help=f"default {DEFAULT_IMAGE}, or the --like hut's")
    p.add_argument("--mount", action="append", default=[],
                   metavar="SRC[:DST][:ro]",
                   help="a host directory the hut shares; repeatable")
    p.add_argument("--autostart", action="store_true",
                   help="start it with the user's session, and at boot "
                        "if the user lingers")
    p.add_argument("--seccomp", metavar="PROFILE",
                   help="strict, the default; debug, which allows "
                        "ptrace; or a seccomp profile file, copied in")
    p.add_argument("--like", metavar="HUT",
                   help="start from another hut's policy, image, mounts "
                        "and seccomp profile; --network-policy, --image "
                        "and --seccomp replace its, and --mount adds to "
                        "them")
    p.add_argument("--dry-run", action="store_true",
                   help="print the files it would write, and write none; "
                        "the image is pulled, to find its trust store")
    p = sub.add_parser("enter", usage="%(prog)s NAME [--root] "
                                      "[-- COMMAND...]",
                       help="start a hut if it is stopped, and run a "
                            "command in it, a shell by default")
    p.add_argument("name")
    p.add_argument("--root", action="store_true", help="as uid 0")
    p = sub.add_parser("log", help="follow a hut's record")
    p.add_argument("name")
    p.add_argument("--refused", action="store_true",
                   help="instead, what the record holds that the hut's "
                        "policy still refuses, and the names asked for "
                        "that no list admits")
    p = sub.add_parser("allow", help="let a hut reach a host, or a method "
                                     "or path on it; its listeners reload")
    p.add_argument("name")
    p.add_argument("host")
    p.add_argument("--method", action="append", default=[],
                   help="a method the host is allowed; repeatable")
    p.add_argument("--path", action="append", default=[],
                   metavar="PATTERN",
                   help="a path pattern the host is allowed, where * "
                        "matches / too; repeatable")
    p = sub.add_parser("network-policy",
                       help="edit a hut's policy in $EDITOR; its "
                            "listeners reload")
    p.add_argument("name")
    p = sub.add_parser("stop", help="stop a hut")
    p.add_argument("name")
    p = sub.add_parser("rm", help="stop a hut and remove it; its home "
                                  "and its record stay")
    p.add_argument("name")
    p.add_argument("--home", action="store_true",
                   help="remove its home too, or the home a hut removed "
                        "without --home left")
    sub.add_parser("ls", help="list the huts")
    p = sub.add_parser("ptyxis", help="a Ptyxis profile that opens the hut "
                                      "with moathut enter")
    p.add_argument("name")
    p.add_argument("--remove", action="store_true",
                   help="remove it instead")
    credential = sub.add_parser(
        "credential", help="seal a provider's key for the huts' brokers"
    ).add_subparsers(dest="credential_command", required=True)
    p = credential.add_parser(
        "add", help="seal the secret on standard input as ID; an ID that "
                    "exists is replaced, keeping what is not given")
    p.add_argument("id")
    p.add_argument("--host", action="append", default=[],
                   help="a host the secret is sent to; repeatable")
    p.add_argument("--env", metavar="VARIABLE",
                   help="the variable a hut holds the placeholder in")
    p.add_argument("--auth-header", metavar="FIELD",
                   help="the header the secret is sent in (x-api-key)")
    p.add_argument("--auth-format", metavar="FORMAT",
                   help="its value, with {secret} substituted ({secret})")
    credential.add_parser("ls", help="list the credentials")
    credential.add_parser("rm", help="remove a credential no hut's "
                                     "policy names").add_argument("id")
    # For the units' own use; not listed.
    unit = sub.add_parser("unit").add_subparsers(dest="unit_command",
                                                 required=True)
    unit.add_parser("netns").add_argument("name")
    unit.add_parser("sudoers").add_argument("name")
    unit.add_parser("rotate").add_argument("name")
    unit.add_parser("exec").add_argument("name")
    return parser


def parse(words):
    """The words before the first `--` are moathut's; those after it
    are the command's, options and all."""
    words, command = list(words), []
    if "--" in words:
        at = words.index("--")
        words, command = words[:at], words[at + 1:]
    parser = build_parser()
    args = parser.parse_args(words)
    if command and not (args.command == "enter"
                        or getattr(args, "unit_command", None) == "exec"):
        parser.error(f"{args.command} takes no command")
    args.argv = command
    return args


def _secret(credential, stdin):
    if stdin.isatty():
        return getpass.getpass(f"{credential}: ")
    return stdin.read()


def run_credential(args, *, dirs, stdin):
    if args.credential_command == "add":
        huts, moved = credential_add(
            args.id, _secret(args.id, stdin), hosts=args.host, env=args.env,
            auth_header=args.auth_header, auth_format=args.auth_format,
            dirs=dirs)
        print(f"credential {args.id} sealed")
        for name in huts:
            print(f"hut {name}: its broker holds it"
                  + ("; the new variable is set from its next start"
                     if moved else ""))
    elif args.credential_command == "ls":
        for row in credential_ls(dirs=dirs):
            print("  ".join(row))
    else:
        credential_rm(args.id, dirs=dirs)


def _applied(name, what, unchanged, applied):
    if applied is None:
        print(f"hut {name}: {unchanged}")
        return
    if not applied.running:
        listeners = "it applies from the hut's next start"
    elif applied.restarted:
        listeners = (f"its inspector restarted, since {applied.restarted}, "
                     "and its responder reloaded")
    else:
        listeners = "its inspector and responder reloaded"
    print(f"hut {name}: {what}; {listeners}"
          + ("; the workload has its new variables from its next start"
             if applied.moved else ""))


def print_refused(name, rows, names):
    if not rows and not names:
        print(f"hut {name}: its policy refuses nothing its record or its "
              "responder holds")
        return
    if rows:
        width = max(len(host) for _n, host, _reason, _req in rows)
        print("refused, and refused by the policy now:")
        for n, host, reason, request in rows:
            print(f"  {n:>6}  {host:<{width}}  "
                  + (f"{request}  " if request else "") + f"({reason})")
    if names:
        print("names asked for that no list admits:")
        for n, host in names:
            print(f"  {n:>6}  {host}")
    print(f"to allow one: moathut allow {name} HOST "
          "[--method M]... [--path P]...")


def _stopped(signum, frame):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise SystemExit(0)


def run_command(args, *, tool, environ, cwd, isatty, stdin=sys.stdin):
    dirs = user_dirs(environ)
    if args.command == "create":
        hut = create(args.name, args.network_policy, args.image, args.mount,
                     dirs=dirs, tool=tool, python=sys.executable,
                     libexec=environ.get("MOATERY_LIBEXEC")
                     or DEFAULT_LIBEXEC,
                     pythonpath=environ.get("PYTHONPATH") or None,
                     uid=os.getuid(), gid=os.getgid(), cwd=cwd,
                     environ=environ, autostart=args.autostart,
                     dry_run=args.dry_run, like=args.like,
                     profile=args.seccomp)
        if args.dry_run:
            for path, text in hut.items():
                print(f"# {path}\n{text}")
        else:
            print(f"hut {hut.name} created; moathut enter {hut.name}")
    elif args.command == "enter":
        enter(args.name, args.argv, root=args.root, dirs=dirs,
              cwd=cwd, environ=environ, isatty=isatty)
    elif args.command == "log" and args.refused:
        print_refused(args.name, *refused(args.name, dirs=dirs))
    elif args.command == "log":
        try:
            log(args.name, dirs=dirs,
                write=lambda line: print(line, flush=True))
        except KeyboardInterrupt:
            pass
    elif args.command == "allow":
        _applied(args.name, f"{args.host} allowed",
                 "its policy allows that already",
                 allow(args.name, args.host, methods=args.method,
                       paths=args.path, dirs=dirs))
    elif args.command == "network-policy":
        _applied(args.name, "policy replaced", "policy unchanged",
                 edit_policy(args.name, dirs=dirs, environ=environ,
                             isatty=isatty))
    elif args.command == "stop":
        stop(args.name, dirs=dirs)
    elif args.command == "rm":
        for path in rm(args.name, home=args.home, dirs=dirs):
            print(f"kept {path}")
        if not args.home:
            print(f"moathut rm --home {args.name} removes the home")
        if ptyxis_remove(args.name):
            print(f"hut {args.name}'s Ptyxis profile removed")
    elif args.command == "ptyxis" and args.remove:
        if not ptyxis_remove(args.name):
            raise HutError(f"hut {args.name} has no Ptyxis profile")
        print(f"hut {args.name}'s Ptyxis profile removed")
    elif args.command == "ptyxis":
        ptyxis_add(args.name, dirs=dirs)
        print(f"Ptyxis profile 'moathut {args.name}' written; new tabs "
              "from it enter the hut")
    elif args.command == "ls":
        rows = ls(dirs=dirs)
        for row in rows:
            print("  ".join(row))
        for row in rows:
            if "unprotected" in row[1:]:
                print(f"moathut: hut {row[0]} is not protected by the "
                      "moat: its namespace has no moatery rules. moathut "
                      f"stop {row[0]}, then moathut enter {row[0]}",
                      file=sys.stderr)
    elif args.command == "credential":
        run_credential(args, dirs=dirs, stdin=stdin)
    elif args.unit_command == "netns":
        # The manager stops it with SIGTERM, which then unwinds it, so it
        # lets go of what it holds; once.
        signal.signal(signal.SIGTERM, _stopped)
        unit_netns(args.name, dirs=dirs)
    elif args.unit_command == "sudoers":
        unit_sudoers(args.name, dirs=dirs)
    elif args.unit_command == "rotate":
        unit_rotate(args.name, dirs=dirs)
    else:
        unit_exec(args.name, args.argv)
    return 0


def main(argv=None, environ=os.environ):
    argv = sys.argv if argv is None else argv
    try:
        args = parse(argv[1:])
    except SystemExit as exc:
        return int(exc.code or 0)
    # -s for the reason units.interpreter gives.
    tool = (sys.executable, "-s", os.path.abspath(argv[0]))
    try:
        return run_command(args, tool=tool, environ=environ,
                           cwd=os.getcwd(), isatty=sys.stdin.isatty())
    except (HutError, CommandFailed, NetnsError) as exc:
        print(f"moathut: {exc}", file=sys.stderr)
        return 1
