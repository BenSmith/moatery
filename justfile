# customs — egress inspector + credential broker

set shell := ["bash", "-euo", "pipefail", "-c"]

export PYTHONDONTWRITEBYTECODE := "1"

# all unit tests
test:
    python3 -B -m unittest discover -t . -s tests -p 'test_*.py'

# syntax check of everything that ships
lint:
    python3 -m py_compile lib/*.py libexec/customs-broker libexec/customs-inspect
