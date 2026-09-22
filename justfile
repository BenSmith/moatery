# customs — egress inspector + credential broker

set shell := ["bash", "-euo", "pipefail", "-c"]

export PYTHONDONTWRITEBYTECODE := "1"

# all unit tests
test:
    python3 -B -m unittest discover -t . -s tests -p 'test_*.py'

# everything that ships, and the rigs: syntax, names, imports, 79 columns
lint:
    ruff check
