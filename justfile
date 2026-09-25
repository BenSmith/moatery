# customs — egress inspector + credential broker

set shell := ["bash", "-euo", "pipefail", "-c"]

export PYTHONDONTWRITEBYTECODE := "1"

# all unit tests
test:
    python3 -B -m unittest discover -t . -s tests -p 'test_*.py'

# everything that ships, and the rigs: syntax, names, imports, 79 columns
lint:
    ruff check

# the RPM, into rpmbuild/RPMS; rpmbuild reads this checkout directly
rpm:
    #!/usr/bin/env bash
    set -euo pipefail
    serial="$(date +%Y%m%d%H%M%S)"
    mkdir -p rpmbuild/{BUILD,RPMS,SRPMS,SPECS}
    rpmbuild -bb \
        --define "_topdir $(pwd)/rpmbuild" \
        --define "_sourcedir $(pwd)" \
        --define "_builddir $(pwd)/rpmbuild/BUILD" \
        --define "buildserial ${serial}" \
        rpm/customs.spec
    find rpmbuild/RPMS -name "customs-*${serial}*.rpm"

rpm-clean:
    rm -rf rpmbuild
