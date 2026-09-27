"""Subprocess coverage bootstrap.

``just coverage`` exports ``COVERAGE_PROCESS_START`` and puts this
directory on ``PYTHONPATH``; every Python child the suite launches then
imports ``sitecustomize`` at startup (the interpreter does so
automatically for any directory on the path) and calls
``coverage.process_startup()``, which starts measuring and writes a
parallel data file ``coverage combine`` merges.

This is the piece a plain ``coverage run`` cannot reach: the entrypoints
are executed as scripts (``load_script`` execs one per call), and the
sidecar forks and ``execve``s ``sys.executable`` directly, so nothing
the test process does decides whether they are measured -- the child's
own startup does. ``COVERAGE_PROCESS_START`` is absent outside
``just coverage``, so importing this is a no-op in a normal run.
"""

import os

if os.environ.get("COVERAGE_PROCESS_START"):
    try:
        import coverage
        coverage.process_startup()
    except Exception:  # coverage missing or a broken child: never fatal
        pass
