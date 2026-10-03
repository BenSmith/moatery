"""Running podman, systemctl and the programs, with their words kept for
the error."""

import subprocess


class CommandFailed(Exception):
    """A command exited non-zero; its stderr, or stdout, is the message."""


def run(argv, *, input=None, check=True, env=None):
    done = subprocess.run(argv, input=input, capture_output=True,
                          text=True, env=env)
    if check and done.returncode != 0:
        words = (done.stderr or done.stdout).strip()
        raise CommandFailed(f"{' '.join(argv[:3])}: exit {done.returncode}"
                            + (f": {words}" if words else ""))
    return done
