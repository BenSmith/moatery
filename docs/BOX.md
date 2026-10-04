# moathut

moathut makes long-lived, inspected containers, called boxes:
`moathut create NAME --policy FILE`, then `moathut enter NAME`.
Each box is the netns placement ([DESIGN.md](DESIGN.md)) laid out as
[examples/quadlet/](../examples/quadlet/): a unit that holds the
network namespace and loads the rules when it starts (a quadlet `.pod`,
with the workload its only container), the inspector's and the
responder's listeners bound in that namespace, and the workload started
after them.

[BOX-GUIDE.md](BOX-GUIDE.md) is the user's guide; this is the
reference.

## What a box is for

An agent or a toolchain run from a terminal. It reaches the hosts its
policy lists, over HTTPS and HTTP; it holds a placeholder where a
provider's key would be; and it shares with the host only the
directories `create` was told to mount. Every other port is dropped,
so git over ssh cannot leave a box, and git over https can.


## Commands

```
moathut create NAME --policy FILE [--image IMAGE]
                   [--mount SRC[:DST][:ro]]... [--autostart] [--dry-run]
moathut enter NAME [--root] [-- COMMAND...]
moathut log NAME [--refused]
moathut allow NAME HOST [--method M]... [--path P]...
moathut policy NAME
moathut credential add ID [--host HOST]... [--env VARIABLE]
                   [--auth-header FIELD] [--auth-format FORMAT]
moathut credential ls
moathut credential rm ID
moathut stop NAME
moathut rm NAME [--home]
moathut ls
```

**create** writes the box's files (below), mints its CA with
`moat-mint-ca`, builds its bundle, and runs `systemctl --user
daemon-reload`. Nothing starts. The image defaults to
`registry.fedoraproject.org/fedora-toolbox:44`, Fedora's own, which has
the git, Python, ssh client and manual pages `fedora:44` leaves out.
With `--autostart` the workload's unit is wanted by `default.target`,
so the user's manager starts the box when it starts: at login, or at
boot for a lingering user. It starts the same chain `enter` does, and
`ls` marks the box `autostart`. A box stopped with `stop` starts again
at the next login. With `--dry-run` it prints each file it would write,
its path first, and writes none and mints nothing; it still refuses
what `create` would refuse, and pulls the image to find its trust
store.

**enter** starts the workload's unit if it is inactive, which starts, in
order, the namespace's unit, the rules, the broker and the listeners,
and the workload. It then checks that the namespace holds both moatery
tables, and refuses if it does not, before `podman exec -it` as the user
(or uid 0 with `--root`). A listener that is not running is started
again, and so is a box's broker. If one does not start, `enter` says so
and enters anyway: without the inspector the workload's connections are
refused, without the responder its names do not resolve, and without the
broker a request with its credentials is refused, not sent without. The
working directory is the host's current one if that is inside a mount,
and the box's home otherwise.

**stop** stops the namespace's unit, and the broker's; everything bound
to it stops too.
**ls** lists each box, whether its workload is active, its image, and
`autostart` if it has it.
**rm** stops the box and removes its units and what podman made from
them; its home and its record stay unless `--home`.

## The policy loop

The command line is simple. The policy is where the effort goes: every
host the workload reaches has to be listed.

- **log** follows the box's record, one line per request or refused
  connection, from its last twenty, and on into the next file when it is
  rotated. With `--refused` it prints instead the lines, in the record
  and the rotated ones it keeps, whose decision is `drop`, counted by host and reason, with the method and path of a
  request the entries refused; and the responder's `unlisted_names`, the
  names the workload asked for that no list admits. Both leave out what
  the policy now lets through.
- **allow** only widens. A host no list names goes into `hosts`, or,
  with `--method` or `--path`, into an entry of its own. A host `hosts`
  admits is left alone: an entry for it would confine it to the entry. A
  host entries govern takes another entry, since `hosts` is not
  consulted for it, and so needs `--method` or `--path`; if it is
  brokered, `--path`, or its key would go with every request. HOST is a
  name; a pattern is written with `policy`.
- **policy** opens a copy of the document in `$VISUAL`, `$EDITOR` or
  `vi`. A copy that comes back unchanged changes nothing; one that does
  not load is refused, and opened again if there is a terminal to ask
  on.
- Either checks the edited document with the inspector's own loader
  (`moatery.inspect_policy.load_policy`), and its credentials as
  `create` does, before it replaces the file, so a mistake is an error
  at the command and not a box whose inspector will not start. A policy
  that names a credential for the first time gains a broker, and one that
  names none loses it: the box's units are written again. Then, if they
  are running, the inspector and the responder are reloaded
  ([POLICY.md](POLICY.md)): a request already relaying finishes, and
  the next is decided against the new document. Nothing is cut, and
  the command waits until the inspector's status file names the new
  document. The inspector is restarted instead when its unit changed,
  which a broker gained or lost does, when `tls` changed, or when it
  did not take the reload; a restart binds again in the same namespace,
  a connection in the gap is refused, not let through, and one open is
  cut. The command says which it did. A stopped box has the policy from
  its next start; a running workload has a new credential's variable
  from its next start.

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
| policy | `~/.config/moatery/box/NAME/policy.json` |
| bundle | `~/.config/moatery/box/NAME/bundle.pem` |
| prompt | `~/.config/moatery/box/NAME/prompt.sh` |
| CA, certificates, status files | `~/.local/state/moatery/box/NAME/` |
| record | `~/.local/state/log/moatery/box/NAME/requests.log`, and `.1` to `.4.gz` |
| the box's home | `~/.local/share/moatery/box/NAME/home/` |
| namespace, workload | `~/.config/containers/systemd/moathut-NAME.{pod,container}` |
| inspector, responder, broker | `~/.config/systemd/user/moathut-NAME-{inspect,resolve,broker}.service` |
| the record's rotation | `~/.config/systemd/user/moathut-NAME-rotate.{service,timer}` |
| broker's socket | `$XDG_RUNTIME_DIR/moathut/NAME/broker.sock` |
| credential | `~/.config/moatery/credentials/ID.{cred,json}` |

The container is named NAME, and so is podman's object for its
namespace, so `podman` commands take the box's name; `create` refuses a
name podman already uses. The credentials are beside the boxes, not
among them, where they would be a box's directory.

## The units

moathut writes, for each box, the units
[examples/quadlet/](../examples/quadlet/) has as files:
`moathut-NAME.pod` for `example.pod`, `moathut-NAME.container`
for `example.container`, `moathut-NAME-inspect.service` and
`-resolve.service` for the example's two listener units, and
`-broker.service` for `moat-broker.service`. The namespace is made
as the example's is: pasta, `UserNS=keep-id`, `--hosts-file=image`, so
the host's hosts file does not answer the workload's names, and no
cgroup of its own. The units differ from the example's in these ways:

- The tool loads the rules (`moathut unit rules NAME`) and starts
  the listeners in the namespace (`moathut unit exec NAME`), where
  the example has `moat-pod-netns`; both are among the commands for
  the units' use. The egress device is read inside the namespace, not
  on the host.
- The workload `Wants=` the listeners, where the example's `Requires=`
  them, and a listener that dies is started again
  (`Restart=on-failure`); below says why.
- Each box has a broker of its own, written only if its policy names a
  credential, and with no `[Install]`. The inspector `Wants=` and is
  ordered `After=` it, as in the example: not `Requires=`, which would
  restart the inspector, and with it the workload, at every new key.
  Its start takes as long as the decryption, over a second on the
  proving host. It is bound to nothing: a restart of the namespace's
  unit is a new namespace, which is nothing to the broker, and `stop`
  and `rm` stop it.
- systemd's user manager leaves a credentialed unit's workspace behind
  when it stops the unit while its credentials are being decrypted, and
  every start after fails on it; the system manager's leaves nothing.
  `enter` and `credential add` stop a broker that is not active, remove
  the workspace, and forget its failures before they start it.
- The bundle is mounted read-only over the image's own system bundle,
  as in the example, at the path found at `create`, and is pointed at
  by `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`,
  `GIT_SSL_CAINFO` and `PIP_CERT` as well. The mount is what root sees
  under sudo, which drops the variables. Each credential's placeholder
  is set in the workload's environment from `credential add`.
- Each box has a home of its own, a directory on the host that only it
  mounts, at the path the user's home has on the host: keep-id maps the
  user to the same name and uid inside. The user's own home directory
  is never mounted. The workload's working directory is that path too:
  podman writes the passwd entry of a user keep-id brings in with the
  working directory as its home, and `HOME` from it.
- The workload's unit names the box's user and drops every capability
  outside podman's default set ("Refused", below).
- At each start the workload's unit writes a sudoers drop-in, as root in
  the container (`ExecStartPost=`), giving the user sudo without a
  password: the image's own rule asks for one, and the user has none.
  Root in a box is filtered as the user is.
- The record is rotated by the tool (`moathut unit rotate NAME`),
  from a timer the namespace's unit `Wants=` and that is `PartOf=` it, a
  minute after that unit starts and every ten after, where the example
  has logrotate. Past 32 MiB the record is moved to `.1`, and the
  inspector's main process alone is sent `SIGHUP`, on which it opens the
  path again at its next write; the other processes in its unit are
  openssl mints, which a HUP ends. Four are kept, all but `.1`
  compressed: a line being written as the record moved lands in `.1`,
  which is compressed at the rotation after. The inspector stops writing
  a record past 512 MiB, and a box writing that much in ten minutes
  loses its lines until the next rotation. The tool, not logrotate,
  which neither the image nor every host has.
- The programs run with python's `-s`, so the user's own site-packages
  cannot come ahead of the installed package.
- No `[Install]` unless `--autostart`: without it a box runs from
  `enter` to `stop`.
- `Timezone=local`: the workload's clock reads in the host's zone, not
  the image's (UTC in Fedora's).
- The prompt is mounted read-only at `/etc/profile.d/moathut.sh`, and
  puts `[NAME]` before bash's prompt, magenta, or red as root. Fedora's
  `/etc/bashrc` reads it, so root's shell has it from the image's
  `/root/.bashrc`; `create` gives a home with no `.bashrc` one that reads
  `/etc/bashrc` and then the prompt, which an image whose `bashrc` does
  not read `/etc/profile.d` needs. A `.bashrc` the home has is kept. It
  is written with the units, so a box from before it gains it when
  `allow`, `policy` or `credential add` writes its units again. A mount
  may not cover it.

What starts what: `enter` starts `moathut-NAME.service`, which
`Wants=` and is `After=` the inspector and the responder; they are
`BindsTo=` and `After=` the namespace's unit, which is active only once
its `ExecStartPost=` has loaded the rules. A rules load that fails fails
that unit, and nothing after it starts. It `Wants=` the listeners, so
its restart brings them back into its new namespace. The inspector
`Wants=` the broker and starts after it is listening.

Nothing `Requires=` a listener: a restart of a required unit restarts
what requires it, and the inspector's restart would restart the
workload. A listener that is not running leaves the rules sending the
workload's connections to a port nothing listens on, which refuses
them; one that dies is started again (`Restart=on-failure`).

## Refused

`create` refuses:

- a mount that is, or contains, `$HOME`;
- a mount that overlaps `$XDG_RUNTIME_DIR`, a moatery directory above,
  or podman's or systemd's user configuration and storage: those hold
  the broker's socket, the CA's key, the sealed credentials, and the
  units that load a box's rules, which a box able to write them could
  drop;
- a name outside `[a-z0-9-]`, or one podman already uses;
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

A workload restart, by anything, keeps the namespace and its rules. A
box started outside systemd (`podman pod start NAME`, or `podman start
NAME` while the namespace's unit is down) has a new namespace with no
rules, and its egress is not inspected. `enter` refuses such a box, but
a process started in it some other way is not caught. Joining a
namespace the tool holds (`Network=ns:PATH`), instead of making one,
would turn that start into a failure; that is untested.

## Where it lives

`moathut` is a host layout, the thing DESIGN.md says moatery is not.
Its code is its own package, `moathut`, beside `moatery`. It may
import `moatery` (the policy loader); the programs never import it,
which `tests/test_closure.py` holds. The moatery RPM
carries it, `/usr/bin/moathut` and the package beside `moatery` in
site-packages; there is no separate package. `tests/test_closure.py`
holds the RPM's spec to installing both packages and every program.

## Requirements

The moatery programs; podman 5.0 or later (quadlet `.pod` units);
systemd 256 or later (`LoadCredentialEncrypted=` in a user unit); a
lingering user (`loginctl enable-linger`) for a box to outlive the login
session.

## Proving it

A rig, `tests/manual/box_rig.py`, on a real host, through the command
line ([tests/manual/README.md](../tests/manual/README.md)):

- the workload's first request at every start, the box's first, each
  restart of the workload and of the namespace's unit, and `enter` after
  `stop`, is inspected: the rules and the listeners are in place before
  it;
- a rules load that fails starts nothing, and `enter` refuses the box;
- a listed host answers and an unlisted one is refused 403, as the user
  and as root by sudo; the workload's DNS is the responder's; UDP 443,
  TCP 22 and a stray datagram are dropped and counted;
- root in the box holds no `CAP_NET_ADMIN`, and the user no capability;
- `enter` runs in the box's home, or the mount the host's directory is
  in; the user's own home is not the box's; a file outside the home is
  gone after a restart;
- `enter` refuses a box `podman pod restart` started;
- a brokered request reaches a stub provider carrying the sealed key,
  at every start of the broker as well, while the box holds the
  placeholder and has no path to the broker's socket; a stopped broker's
  request is refused, never sent without the key, and `enter` starts it
  again, even after a stop while it started; a new key with `credential
  add` is the next request's, and neither the inspector nor the workload
  restarted;
- `rm` leaves no unit, container or namespace, nor the broker's socket,
  and keeps the home and the record, which `create` finds again; `rm
  --home` removes the home; `credential rm` is refused while a box names
  the credential;
- `log --refused` names a host the box was refused; `allow` lists it and
  reloads the listeners, a download running through it finishing whole,
  and the host is dialled after;
- a `policy` edit the loader refuses changes and restarts nothing;
- a killed inspector is started again, and a stopped one leaves the
  workload running until `enter` starts it;
- `log` follows a request as it is made;
- the rotation's timer runs with the namespace's unit, and a record
  past its size is moved aside and the next request's line is in a new
  one.

Unit tests hold the generated units' dependencies to the chain above,
each one broken on purpose once, and the refusals.
