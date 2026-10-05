# Example: a bootc image

moatery from the RPM, over a stock bootc base, with the packages the
RPM recommends (podman, passt, nftables; fedora-bootc has them already,
and the image keeps them on a base that does not). Nothing is
configured in the
image: the units and the one-time setup are the user's, as in
[../README.md](../README.md), and live under `/var/home`, so an update
changes only what the RPM installs: the programs in
`/usr/libexec/moatery`, `/usr/bin/moathut`, and the `moatery` and
`moathut` packages.

From the checkout's root:

```
just rpm
cp rpmbuild/RPMS/noarch/moatery-*.rpm examples/bootc/moatery.rpm
sudo podman build -t localhost/moatery-bootc examples/bootc
```

The image is built into root's storage, where bootc-image-builder
reads it.

`BASE` is the base image, `quay.io/fedora/fedora-bootc:44` unless given
with `--build-arg`.

A disk for a VM, with `config.toml`'s `USER` replaced by a login and
`KEY` by its SSH public key, the whole line of a `.pub` file:

```
mkdir -p output
sudo podman run --rm --privileged \
    --security-opt label=type:unconfined_t \
    -v ./examples/bootc/config.toml:/config.toml:ro -v ./output:/output \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    quay.io/centos-bootc/bootc-image-builder:latest \
    --type qcow2 --rootfs xfs localhost/moatery-bootc
```

The disk is `output/qcow2/disk.qcow2`, owned by root, as is everything
under `output/`. The login has no password: it is reached with `ssh
USER@` the VM, and is in wheel.

The user needs lingering for the units to start at boot rather than at
the first login: `sudo loginctl enable-linger USER`.

## The rigs in the VM

`Containerfile.rig` gives wheel sudo without a password, and installs
`ip` and sudo where the base lacks them; the rigs use them for the
container's rules. It is for a test VM only.

```
sudo podman build -t localhost/moatery-bootc:rig \
    --build-arg IMAGE=localhost/moatery-bootc \
    -f examples/bootc/Containerfile.rig examples/bootc
```

Its disk is the command above with `localhost/moatery-bootc:rig` as
the last word.

With the checkout copied into the VM, the rigs run against the
installed programs:

```
export MOATERY_LIBEXEC=/usr/libexec/moatery
python3 tests/manual/host_rig.py
python3 tests/manual/netns_rig.py
```
