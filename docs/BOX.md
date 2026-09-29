# customs-box

A command line for long-lived, inspected containers for command-line
workloads: `customs-box create NAME --policy FILE`, then `customs-box
enter NAME`. Each box is shape 1n ([DESIGN.md](DESIGN.md)) laid out as
[examples/quadlet/](../examples/quadlet/): a pod that holds the network
namespace and loads the rules when it starts, the inspector's and the
responder's listeners bound in that namespace, and the workload started
after them. The name is a placeholder.

Designed, not built.

## What a box is for

An agent or a toolchain run from a terminal. It reaches the hosts its
policy lists, over HTTPS and HTTP; it holds a placeholder where a
provider's key would be; and it shares with the host only the
directories `create` was told to mount. Every other port is dropped,
so git over ssh cannot leave a box, and git over https can.

Not for a display, audio or a GPU; the host's network or a custom one;
devices; or the user's home directory.

## Commands

```
customs-box create NAME --policy FILE [--image IMAGE]
                   [--mount SRC[:DST][:ro]]...
customs-box enter NAME [--root] [-- COMMAND...]
customs-box log NAME [--refused]
customs-box allow NAME HOST [--method M]... [--path P]...
customs-box policy NAME
customs-box credential add ID --host HOST... --env VAR
                   [--header FIELD] [--format FORMAT]
customs-box stop NAME
customs-box rm NAME [--home]
customs-box ls
```

**create** writes the box's files (below), mints its CA with
`customs-mint-ca`, builds its bundle, and runs `systemctl --user
daemon-reload`. Nothing starts. The image defaults to
`registry.fedoraproject.org/fedora-toolbox:44`, Fedora's own, which has
the git, Python, ssh client and manual pages `fedora:44` leaves out.

**enter** starts the workload's unit if it is inactive, which starts,
in order, the pod, the rules, the broker and the listeners, and the
workload. It then checks that the pod's namespace holds both customs
tables, and refuses if it does not, before `podman exec -it` as the
user (or uid 0 with `--root`). The working directory is the host's
current one if that is inside a mount, and the box's home otherwise.

**stop** stops the pod's unit; everything bound to it stops too.
**rm** stops the box and removes its units, container and pod; its home
and its record stay unless `--home`.

## The policy loop

The command line is simple. The policy is where the effort goes: every
host the workload reaches has to be listed.

- **log** tails the box's record. With `--refused` it prints the lines
  whose decision is `drop`, grouped by host and reason, and the
  responder's `unlisted_names`: the hosts the workload asked for and was
  refused.
- **allow** adds HOST to `hosts`, or, with `--method` or `--path`, a
  policy entry for it. **policy** opens the document in `$EDITOR`.
- Either checks the edited document with the inspector's own loader
  (`customs.inspect_policy.load_policy`) before it replaces the file, so
  a mistake is an error at the command and not a box whose inspector
  will not start. Then it restarts the box's inspector and responder.
  The policy is read at start ([POLICY.md](POLICY.md)). The restart
  binds again in the same namespace, and a connection in the gap is
  refused, not let through.

Package installs inside a box are the hard case: a mirror list spreads
over many hosts, and the install does not outlive a stop (next
section). A box's tools are better built into its image.

## What persists

Quadlet runs the workload with `--replace --rm`, and removes it at
stop: every start is a new container from the image. The box's home is
a mount, so it persists, and with it anything installed under it (`pip
install --user`, an installer that writes to `~/.local`). The image's
filesystem does not, and neither does a `dnf install`.

## Credentials

**credential add** reads the secret from standard input and seals it
to this user and host (`systemd-creds --user encrypt`), and records the
hosts, the variable, the header and format, and a generated
placeholder beside it. A credential is sealed once and serves every box
whose policy names it.

Each box has its own broker, holding only the credentials its policy
names. The broker picks a credential by `Host`, so a broker for every
box lets two boxes hold different keys for one provider, and `rm` takes
the box's broker with it. The workload's environment gets each named
credential's variable, set to its placeholder.

## Files

For box NAME, credential ID:

| what | where |
|---|---|
| policy | `~/.config/customs/box/NAME/policy.json` |
| bundle | `~/.config/customs/box/NAME/bundle.pem` |
| CA, certificates, status files | `~/.local/state/customs/box/NAME/` |
| record | `~/.local/state/log/customs/box/NAME/requests.log` |
| the box's home | `~/.local/share/customs/box/NAME/home/` |
| pod, workload | `~/.config/containers/systemd/customs-box-NAME.{pod,container}` |
| inspector, responder, broker | `~/.config/systemd/user/customs-box-NAME-{inspect,resolve,broker}.service` |
| broker's socket | `$XDG_RUNTIME_DIR/customs-box/NAME/broker.sock` |
| credential | `~/.config/customs/box/credentials/ID.{cred,json}` |

The pod and the container are both named NAME, so `podman` commands
take the box's name; `create` refuses a name either already has.

## The units

As in examples/quadlet, with these differences:

- The pod is created with `--hosts-file image`, so the host's hosts file
  does not answer the workload's names.
- The rules are loaded by the tool (`customs-box netns rules NAME`, for
  the units' use). The egress device is read inside the namespace.
- The broker is `PartOf=` the pod, and the inspector `Wants=` and is
  ordered `After=` it.
- The bundle is mounted read-only over the image's own system bundle,
  found at `create`, and pointed at by `SSL_CERT_FILE`,
  `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO` and
  `PIP_CERT`. The mount is what root sees under sudo, which drops the
  variables.
- The box's home is mounted at the user's home path; the pod maps the
  user to the same uid inside (`UserNS=keep-id`).
- At each start the workload's unit writes a sudoers drop-in, as root in
  the container (`ExecStartPost=`), giving the user sudo without a
  password: the image's own rule asks for one, and the user has none.
  Root in a box is filtered as the user is.
- No `[Install]`: a box runs from `enter` to `stop`.

What starts what: `enter` starts `customs-box-NAME.service`, which
`Requires=` and is `After=` the inspector and the responder; they are
`BindsTo=` and `After=` the pod, whose unit is active only once its
`ExecStartPost=` has loaded the rules. A rules load that fails fails
the pod, and nothing after it starts. The pod `Wants=` the listeners, so
a restart of the pod brings them back into its new namespace.

## Refused

`create` refuses:

- a mount that is, or contains, `$HOME`, `$XDG_RUNTIME_DIR`, or a
  customs directory above: those hold the broker's socket, the CA's
  key and the sealed credentials;
- a name outside `[a-z0-9-]`, or one a container or pod already has.

Nothing is passed to podman that the tool does not write itself: no
network, capability, device, `--privileged` or hosts flag. The
workload's capabilities are written in its unit, podman's default set,
which has no `NET_ADMIN`, so a `containers.conf` cannot widen them.

## What is not closed

A workload restart, by anything, keeps the pod's namespace and its
rules. A pod started outside systemd (`podman pod start NAME`, or
`podman start NAME` while the pod is down) is a new namespace with no
rules, and its egress is not inspected. `enter` refuses such a box, but
a process started in it some other way is not caught. A pod that joins a
namespace the tool holds (`Network=ns:PATH`) would turn that start into
a failure; that is untested.

## Where it lives

`customs-box` is a host layout, the thing DESIGN.md says customs is not.
Its code is its own package, `customs_box`, beside `customs`; the
programs never import it, and `tests/test_closure.py` holds them to that
unchanged. It may import `customs` (the policy loader).

## Requirements

The customs programs; podman 5.0 or later (quadlet `.pod` units);
systemd 256 or later (`LoadCredentialEncrypted=` in a user unit); a
lingering user (`loginctl enable-linger`) for a box to outlive the login
session.

## Proving it

A rig, `tests/manual/box_rig.py`, on a real host, through the command
line alone:

- a listed host answers, an unlisted one is refused 403, and a brokered
  request reaches a stub provider carrying the sealed key while the
  box's environment holds the placeholder;
- from inside, the broker's socket path is ENOENT, root cannot flush the
  rules, and UDP 443 is dropped and counted;
- the first connection after a workload restart, and after a pod
  restart, is redirected and served;
- `allow` admits a host; a malformed edit is refused by the command, and
  the running box keeps its listeners;
- `enter` refuses a box whose pod was started by `podman pod start`;
- `rm` leaves no unit, container, pod or socket.

Unit tests hold the generated units' dependencies to the chain above,
each one broken on purpose once, and the refusals.

## Open

- The name.
- Whether the image's filesystem should persist until `rm`, as
  distrobox's does. Then neither the workload nor the pod can be a
  quadlet unit: quadlet creates the pod with `--replace` at each start
  and removes it, and every container in it, at stop. `create` would
  make both once, and units of the tool's own would start them.
- A subpackage (`customs-box`, requiring the same version of customs),
  so a host that only runs the programs does not carry it.
- Starting boxes at login (`create --autostart`).
- Rotating the records: the inspector stops writing one past 512 MiB.
- DESIGN.md: "What customs does not do" to say the programs do not, and
  the cosy shape to keep, replace or drop.
