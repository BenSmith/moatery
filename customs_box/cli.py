"""customs-box's command line: parse, hand the environment in, report."""

import argparse
import os
import sys

from .commands import (DEFAULT_IMAGE, DEFAULT_LIBEXEC, BoxError, create,
                       enter, ls, rm, stop, unit_exec, unit_rules,
                       unit_sudoers)
from .netns import NetnsError
from .paths import user_dirs
from .process import CommandFailed

PUBLIC = "{create,enter,stop,rm,ls}"


def build_parser():
    parser = argparse.ArgumentParser(
        prog="customs-box",
        description="long-lived, inspected containers for command-line "
                    "workloads")
    sub = parser.add_subparsers(dest="command", required=True,
                                metavar=PUBLIC)
    p = sub.add_parser("create", help="lay out a box; nothing starts")
    p.add_argument("name")
    p.add_argument("--policy", required=True,
                   help="the inspector's policy document, copied in")
    p.add_argument("--image", default=DEFAULT_IMAGE,
                   help=f"default {DEFAULT_IMAGE}")
    p.add_argument("--mount", action="append", default=[],
                   metavar="SRC[:DST][:ro]",
                   help="a host directory the box shares; repeatable")
    p = sub.add_parser("enter", usage="%(prog)s NAME [--root] "
                                      "[-- COMMAND...]",
                       help="start a box if it is stopped, and run a "
                            "command in it, a shell by default")
    p.add_argument("name")
    p.add_argument("--root", action="store_true", help="as uid 0")
    p = sub.add_parser("stop", help="stop a box")
    p.add_argument("name")
    p = sub.add_parser("rm", help="stop a box and remove it; its home "
                                  "and its record stay")
    p.add_argument("name")
    p.add_argument("--home", action="store_true",
                   help="remove its home too")
    sub.add_parser("ls", help="list the boxes")
    # For the units' own use; not listed.
    unit = sub.add_parser("unit").add_subparsers(dest="unit_command",
                                                 required=True)
    unit.add_parser("rules").add_argument("name")
    unit.add_parser("sudoers").add_argument("name")
    unit.add_parser("exec").add_argument("name")
    return parser


def parse(words):
    """The words before the first `--` are customs-box's; those after it
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


def run_command(args, *, tool, environ, cwd, isatty):
    dirs = user_dirs(environ)
    if args.command == "create":
        box = create(args.name, args.policy, args.image, args.mount,
                     dirs=dirs, tool=tool, python=sys.executable,
                     libexec=environ.get("CUSTOMS_LIBEXEC")
                     or DEFAULT_LIBEXEC,
                     pythonpath=environ.get("PYTHONPATH") or None,
                     uid=os.getuid(), gid=os.getgid(), cwd=cwd,
                     environ=environ)
        print(f"box {box.name} created; customs-box enter {box.name}")
    elif args.command == "enter":
        enter(args.name, args.argv, root=args.root, dirs=dirs,
              cwd=cwd, environ=environ, isatty=isatty)
    elif args.command == "stop":
        stop(args.name, dirs=dirs)
    elif args.command == "rm":
        for path in rm(args.name, home=args.home, dirs=dirs):
            print(f"kept {path}")
    elif args.command == "ls":
        for row in ls(dirs=dirs):
            print("  ".join(row))
    elif args.unit_command == "rules":
        unit_rules(args.name)
    elif args.unit_command == "sudoers":
        unit_sudoers(args.name, dirs=dirs)
    else:
        unit_exec(args.name, args.argv)
    return 0


def main(argv=None, environ=os.environ):
    argv = sys.argv if argv is None else argv
    try:
        args = parse(argv[1:])
    except SystemExit as exc:
        return int(exc.code or 0)
    tool = (sys.executable, os.path.abspath(argv[0]))
    try:
        return run_command(args, tool=tool, environ=environ,
                           cwd=os.getcwd(), isatty=sys.stdin.isatty())
    except (BoxError, CommandFailed, NetnsError) as exc:
        print(f"customs-box: {exc}", file=sys.stderr)
        return 1
