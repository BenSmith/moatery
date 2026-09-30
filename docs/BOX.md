# customs-box

A command line for long-lived, inspected containers for command-line
workloads: `customs-box create NAME --policy FILE`, then `customs-box
enter NAME`. Each box is shape 1n ([DESIGN.md](DESIGN.md)) laid out as
[examples/quadlet/](../examples/quadlet/): a pod that holds the network
namespace and loads the rules when it starts, the inspector's and the
responder's listeners bound in that namespace, and the workload started
after them.

`create`, `enter`, `stop`, `rm`, `ls` and the credentials are built, and
a rig proves them on a real host (below); the policy commands and the
packaging are designed, not built.

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
customs-box credential add ID [--host HOST]... [--env VARIABLE]
                   [--auth-header FIELD] [--auth-format FORMAT]
customs-box credential ls
customs-box credential rm ID
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
user (or uid 0 with `--root`). A box with a broker has it started again
if it had stopped. If it does not start, `enter` says so and enters
anyway: a request with its credentials is then refused, not sent
without, and the rest of the box works. The working directory is the
host's current one if that is inside a mount, and the box's home
otherwise.

**stop** stops the pod's unit, and the broker's; everything bound to
the pod stops too.
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

**credential add** reads the secret from standard input, or the
terminal without echo, and seals it to this user and host
(`systemd-creds --user encrypt`). Beside it, it records the hosts, the
variable, the header and format (the broker's defaults are `x-api-key`
and `{secret}`), and a placeholder. `--auth-header` and `--auth-format`
are the broker's own flags, so its refusals name the flag that was
given. The placeholder is always generated, never given: it is written
into the box's units and environment, where nothing secret belongs. All
of it is checked by the broker's own `build_profiles` with the real
secret first, so a key the broker would refuse is refused here. A
credential is sealed once and serves every box whose policy names it.

Adding an ID that exists replaces it: the secret, and whichever of the
hosts, variable, header and format are given; the placeholder stays.
The units of every box whose policy names it are written again and a
running broker is restarted, which a request in the gap finds refused.
A changed variable reaches a running workload at its next start. A
replacement a box could no longer hold is refused, and nothing changes.
**credential rm** refuses while a box's policy names the credential.

A credential's hosts are the most it is sent to. Each box has its own
broker, holding the credentials its policy names, for those of their
hosts the policy brokers with them: the inspector's own choice of
credential for a host, among the hosts `credential add` named. The
broker picks a credential by `Host`, so a broker for every box lets two
boxes hold different keys for one provider, and `rm` takes the box's
broker with it. The workload's environment gets each named credential's
variable, set to its placeholder.

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
| credential | `~/.config/customs/credentials/ID.{cred,json}` |

The pod and the container are both named NAME, so `podman` commands
take the box's name; `create` refuses a name either already has. The
credentials are beside the boxes, not among them, where they would be a
box's directory.

## The units

As in examples/quadlet, with these differences:

- The pod is created with `--hosts-file image`, so the host's hosts file
  does not answer the workload's names.
- The rules are loaded by the tool (`customs-box unit rules NAME`, one
  of the commands for the units' use). The egress device is read inside
  the namespace.
- The broker is Type=notify, started once it is listening, and the
  inspector `Wants=` and is ordered `After=` it: not `Requires=`, which
  would restart the inspector, and with it the workload, at every new
  key. Its start takes as long as the decryption, over a second on the
  proving host. It is bound to nothing: a restart of the pod is a new
  namespace, which is nothing to the broker, and `stop` and `rm` stop it.
- systemd leaves a credentialed unit's workspace behind when it stops
  the unit while its credentials are being decrypted, and every start
  after fails on it. `enter` and `credential add` stop a broker that is
  not active, remove the workspace, and forget its failures before they
  start it.
- The bundle is mounted read-only over the image's own system bundle,
  found at `create`, and pointed at by `SSL_CERT_FILE`,
  `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO` and
  `PIP_CERT`. The mount is what root sees under sudo, which drops the
  variables.
- Each box has a home of its own, a directory on the host that only it
  mounts, at the path the user's home has on the host: the pod maps the
  user to the same name and uid inside (`UserNS=keep-id`). The user's
  own home directory is never mounted. The workload's working directory
  is that path too: podman writes the passwd entry of a user the pod's
  keep-id brings in with the working directory as its home, and `HOME`
  from it.
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
a restart of the pod brings them back into its new namespace. The
inspector `Wants=` the broker and starts after it is listening.

## Refused

`create` refuses:

- a mount that is, or contains, `$HOME`;
- a mount that overlaps `$XDG_RUNTIME_DIR`, a customs directory above,
  or podman's or systemd's user configuration and storage: those hold
  the broker's socket, the CA's key, the sealed credentials, and the
  units that load a box's rules, which a box able to write them could
  drop;
- a name outside `[a-z0-9-]`, or one a container or pod already has;
- a policy naming a credential that has not been added, an entry naming
  one for a host `credential add` did not name, a credential an earlier
  entry takes every host of, and two credentials setting one variable;
- a credential in a box when `XDG_RUNTIME_DIR` is not set, since the
  broker's socket is in it.

`credential add` refuses a host that is not a name, a variable the box
sets itself (the CA variables, `TERM`, `COLORTERM`, `LANG`), a format
without `{secret}`, and whatever the broker would refuse at its start: a
header that is not one, a secret with a line break, a placeholder equal
to it.

Nothing is passed to podman that the tool does not write itself: no
network, capability, device, `--privileged` or hosts flag. The
workload's unit drops every capability outside podman's default set,
which has no `NET_ADMIN`, so a `containers.conf` cannot widen root's in
the box. It adds none, and names the box's user: podman gives the user
the capabilities a unit adds, and root's when the unit names no user.
The user holds none.

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
unchanged. It may import `customs` (the policy loader). The customs RPM
carries it, `/usr/bin/customs-box` and the package beside `customs` in
site-packages; there is no separate package.

## Requirements

The customs programs; podman 5.0 or later (quadlet `.pod` units);
systemd 256 or later (`LoadCredentialEncrypted=` in a user unit); a
lingering user (`loginctl enable-linger`) for a box to outlive the login
session.

## Proving it

A rig, `tests/manual/box_rig.py`, on a real host, through the command
line ([tests/manual/README.md](../tests/manual/README.md)):

- the workload's first request at every start, the box's first, each
  restart of the workload and of the pod, and `enter` after `stop`, is
  inspected: the rules and the listeners are in place before it;
- a rules load that fails starts nothing, and `enter` refuses the box;
- a listed host answers and an unlisted one is refused 403, as the user
  and as root by sudo; the workload's DNS is the responder's; UDP 443,
  TCP 22 and a stray datagram are dropped and counted;
- root in the box holds no `CAP_NET_ADMIN`, and the user no capability;
- `enter` runs in the box's home, or the mount the host's directory is
  in; the user's own home is not the box's; a file outside the home is
  gone after a restart;
- `enter` refuses a box whose pod `podman pod restart` started;
- a brokered request reaches a stub provider carrying the sealed key,
  at every start of the broker as well, while the box holds the
  placeholder and has no path to the broker's socket; a stopped broker's
  request is refused, never sent without the key, and `enter` starts it
  again, even after a stop while it started; a new key with `credential
  add` is the next request's, and neither the inspector nor the workload
  restarted;
- `rm` leaves no unit, container or pod, nor the broker's socket, and
  keeps the home and the record, which `create` finds again; `rm --home`
  removes the home; `credential rm` is refused while a box names the
  credential.

With the policy commands the rig gains `allow` admitting a host, and a
malformed edit refused while the running box keeps its listeners.

Unit tests hold the generated units' dependencies to the chain above,
each one broken on purpose once, and the refusals.

## Open

- Starting boxes at login (`create --autostart`).
- Rotating the records: the inspector stops writing one past 512 MiB.
- DESIGN.md: "What customs does not do" to say the programs do not,
  once the RPM carries customs-box.
