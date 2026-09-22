# customs — egress inspector + credential broker

set shell := ["bash", "-euo", "pipefail", "-c"]

export PYTHONDONTWRITEBYTECODE := "1"

# all unit tests
test:
    python3 -B -m unittest discover -t . -s tests -p 'test_*.py'

# syntax check of everything that ships; compiles in memory, writes nothing
lint:
    #!/usr/bin/env python3
    import sys
    from pathlib import Path
    files = sorted(Path("lib").glob("*.py")) + [
        Path("libexec/customs-broker"), Path("libexec/customs-inspect")]
    bad = False
    for path in files:
        try:
            compile(path.read_bytes(), str(path), "exec")
        except SyntaxError as exc:
            print(f"{path}:{exc.lineno}: {exc.msg}", file=sys.stderr)
            bad = True
    print(f"{len(files)} files compiled")
    sys.exit(bad)
