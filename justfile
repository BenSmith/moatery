# customs — egress inspector + credential broker

set shell := ["bash", "-euo", "pipefail", "-c"]

export PYTHONDONTWRITEBYTECODE := "1"

# all unit tests
test:
    python3 -B -m unittest discover -t . -s tests -p 'test_*.py'

# the unit suite under coverage, of the shipped code only (customs/ and
# the entrypoints; see .coveragerc). Subprocess children measure
# themselves, so the scripts load_script execs and the sidecar's forks are
# counted too. Reports and fails under the configured floor.
coverage:
    #!/usr/bin/env bash
    set -euo pipefail
    # The parent and every Python child import tests/sitecustomize.py,
    # which calls coverage.process_startup() when this is set.
    export COVERAGE_PROCESS_START="$(pwd)/.coveragerc"
    export PYTHONPATH="$(pwd):$(pwd)/tests"
    coverage erase
    # --parallel-mode so the parent's data file does not collide with the
    # children's; combine merges them and reports the sum.
    coverage run --parallel-mode -m unittest discover \
        -t . -s tests -p 'test_*.py'
    coverage combine
    coverage report

coverage-clean:
    coverage erase

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

# the RPM as an image, localhost/customs-rpm:VERSION, built and tested in
# a container from this checkout
rpm-image:
    podman build --ignorefile rpm/containerignore -f rpm/Containerfile \
        -t "localhost/customs-rpm:$(cat VERSION)" .

rpm-clean:
    rm -rf rpmbuild
