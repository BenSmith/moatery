# Example: a bootc image

moatery from the RPM, over a stock bootc base, with the packages the
RPM recommends (podman, passt, nftables). Nothing is configured in the
image: the units and the one-time setup are the user's, as in
[../README.md](../README.md), and live under `/var/home`, so an update
changes only what the RPM installs: the programs in
`/usr/libexec/moatery`, `/usr/bin/moathut`, and the `moatery` and
`moathut` packages.

```
just rpm
cp rpmbuild/RPMS/noarch/moatery-*.rpm examples/bootc/moatery.rpm
sudo podman build -t localhost/moatery-bootc examples/bootc
```

`BASE` is the base image, `quay.io/fedora/fedora-bootc:44` unless given
with `--build-arg`.

A disk for a VM, with `config.toml`'s `USER` and `KEY` replaced by a
login and its SSH public key:

```
mkdir -p output
sudo podman run --rm --privileged \
    --security-opt label=type:unconfined_t \
    -v ./examples/bootc/config.toml:/config.toml:ro -v ./output:/output \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    quay.io/centos-bootc/bootc-image-builder:latest \
    --type qcow2 --rootfs xfs localhost/moatery-bootc
```

The user needs lingering for the units to start at boot rather than at
the first login: `sudo loginctl enable-linger USER`.

## The rigs in the VM

`Containerfile.rig` adds `ip` and passwordless sudo for wheel, which
the rigs use for the container's rules. It is for a test VM only.

```
sudo podman build -t localhost/moatery-bootc:rig \
    --build-arg IMAGE=localhost/moatery-bootc \
    -f examples/bootc/Containerfile.rig examples/bootc
```

With the checkout copied into the VM, the rigs run against the
installed programs:

```
export MOATERY_LIBEXEC=/usr/libexec/moatery
python3 tests/manual/host_rig.py
python3 tests/manual/netns_rig.py
```
