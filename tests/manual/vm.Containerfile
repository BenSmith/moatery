# The VM rig's VM host: qemu and the passt backend qemu starts
# itself, both from the same Fedora the proving host runs. Built by
# tests/manual/vm_rig.py, not shipped.
ARG BASE=registry.fedoraproject.org/fedora:44
FROM ${BASE}
RUN dnf -y install qemu-system-x86-core passt && dnf clean all
