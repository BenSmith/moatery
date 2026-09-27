"""Helpers for measuring coverage of scripts we invoke as subprocesses.

Some tests exercise our extension-less scripts by running them as real
subprocesses for clean argv/env isolation. A plain ``coverage run`` cannot
see into a ``subprocess`` call, so those scripts read as untested even when
they are thoroughly exercised.

The mechanism is the environment, not this module: ``just coverage`` sets
``COVERAGE_PROCESS_START`` and puts ``tests/`` on ``PYTHONPATH``, so every
Python child imports ``tests/sitecustomize.py`` at startup and calls
``coverage.process_startup()`` for itself (see that file). That catches a
child launched with ``os.execve(sys.executable, ...)`` too, which wrapping
the argv here could never do.

What remains here is for the case a test builds a child argv itself and
wants to be sure it is measured even if its env was assembled by hand:
``python_cmd()`` spells the interpreter to use, and ``coverage_env()`` a
copy of an environment that turns measurement on.
"""

import os
import sys

# The repository's .coveragerc, and the tests/ directory that holds the
# sitecustomize hook, both relative to this file.
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TESTS_DIR)
RC_FILE = os.path.join(REPO_ROOT, ".coveragerc")


def coverage_env(env=None):
    """`env` (a copy of os.environ by default) with subprocess coverage on.

    A no-op copy outside a coverage run, so a test that uses it behaves the
    same under `just test`.
    """
    env = dict(os.environ if env is None else env)
    if not env.get("COVERAGE_PROCESS_START"):
        return env
    paths = [p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p]
    if TESTS_DIR not in paths:
        paths.insert(0, TESTS_DIR)
    env["PYTHONPATH"] = os.pathsep.join(paths)
    return env


def python_cmd(script, *args):
    """Build an argv list to run ``script`` under the current interpreter.

    Left as the one spelling of "the interpreter that runs the suite", so a
    child argv does not hard-code ``python3``. Coverage follows from the
    environment (see :func:`coverage_env`), not from this argv.
    """
    return [sys.executable, str(script), *[str(a) for a in args]]
