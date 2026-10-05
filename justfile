# moatery — egress inspector + credential broker

set shell := ["bash", "-euo", "pipefail", "-c"]

export PYTHONDONTWRITEBYTECODE := "1"

# all unit tests
test:
    python3 -B -m unittest discover -t . -s tests -p 'test_*.py'

# the unit suite under coverage, of the shipped code only (moatery/ and
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

# the RPM, into rpmbuild/RPMS, from the tracked files as they stand
# (uncommitted changes too), archived as Copr's source is
rpm:
    #!/usr/bin/env bash
    set -euo pipefail
    serial="$(date +%Y%m%d%H%M%S)"
    version="$(cat VERSION)"
    mkdir -p rpmbuild/{BUILD,RPMS,SOURCES,SRPMS,SPECS}
    # A commit of the working tree, made and left unreferenced; HEAD when
    # there is nothing uncommitted.
    tree="$(git stash create)"
    git archive --prefix="moatery-${version}/" \
        -o "rpmbuild/SOURCES/moatery-${version}.tar.gz" "${tree:-HEAD}"
    rpmbuild -bb \
        --define "_topdir $(pwd)/rpmbuild" \
        --define "buildserial ${serial}" \
        rpm/moatery.spec
    find rpmbuild/RPMS -name "moatery-*${serial}*.rpm"

# the RPM as an image, localhost/moatery-rpm:VERSION, built and tested in
# a container from this checkout
rpm-image:
    podman build --ignorefile rpm/containerignore -f rpm/Containerfile \
        -t "localhost/moatery-rpm:$(cat VERSION)" .

rpm-clean:
    rm -rf rpmbuild
