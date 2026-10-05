# moathut

moathut makes long-lived, inspected containers, called huts:
`moathut create NAME --policy FILE`, then `moathut enter NAME`.
Each hut is the netns placement ([DESIGN.md](DESIGN.md)) laid out
much as [examples/quadlet/](../examples/quadlet/) is: a unit that makes
the network namespace in the user's own user namespace, holds it, and
loads the rules into it when it starts; a quadlet `.pod` that joins it,
with the workload its only container; the inspector's and the
responder's listeners bound in that namespace; and the workload started
after them.

[MOATHUT-GUIDE.md](MOATHUT-GUIDE.md) is the user's guide; this is the
reference.

## What a hut is for

An agent or a toolchain run from a terminal. It reaches the hosts its
policy lists, over HTTPS and HTTP; it holds a placeholder where a
provider's key would be; and it shares with the host only the
directories `create` was told to mount. Every other port is dropped,
so git over ssh cannot leave a hut, and git over https can.

## Commands

```
moathut create NAME (--policy FILE | --like HUT) [--image IMAGE]
                   [--mount SRC[:DST][:ro]]... [--seccomp PROFILE]
                   [--autostart] [--dry-run]
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
moathut ptyxis NAME [--remove]
moathut ls
moathut --version
```

**create** writes the hut's files (below), mints its CA with
`moat-mint-ca`, builds its bundle, and runs `systemctl --user
daemon-reload`. Nothing starts. The image defaults to
`registry.fedoraproject.org/fedora-toolbox:44`, Fedora's own, which has
the git, Python, ssh client and manual pages `fedora:44` leaves out.

- `--autostart`: the workload's unit is wanted by `default.target`, so
  the user's manager starts the hut when it starts: at login, or at boot
  for a lingering user. It starts the same chain `enter` does, and `ls`
  marks the hut `autostart`. A hut stopped with `stop` starts again at
  the next login.
- `--dry-run`: it prints each file it would write, its path first, and
  writes none and mints nothing. It still refuses what `create` would
  refuse, and pulls the image to find its trust store.
- `--seccomp`: the workload's seccomp profile ("Seccomp", below):
  `strict`, the default, `debug`, or a file, copied in.
- `--like HUT`: it starts from another hut's policy, as edited since,
  its image, its mounts and its seccomp profile. `--policy`, `--image`
  and `--seccomp` replace its, and a `--mount` joins its, replacing one
  at the same target. The new hut gets a home and an SELinux level of
  its own, and is not autostarted without `--autostart`. A mount whose
  source has gone since is refused, naming the hut it came from.

**enter** starts the workload's unit if it is inactive, which starts, in
order, the namespace's unit, which loads the rules, the pod, the broker
and the listeners, and the workload. A stopped hut whose files this
moathut would write otherwise has them written again first (The units,
below). It then checks that the namespace holds both moatery tables,
and refuses if it does not, before `podman exec -it` as the user (or
uid 0 with `--root`). A listener that is not running is started
again, and so is a hut's broker. If one does not start, `enter` says so
and enters anyway: without the inspector the workload's connections are
refused, without the responder its names do not resolve, and without the
broker a request with its credentials is refused, not sent without. The
working directory is the host's current one if that is inside a mount,
and the hut's home otherwise.

**stop** stops the namespace's unit, and the broker's; everything bound
to it stops too, and the namespace goes.

**ls** lists each hut, whether its workload is active, its image, its
seccomp profile if not `strict` (`seccomp:debug`, or `seccomp:own` for a
file), `autostart` if it has it, and `unprotected` if its pod runs in a
namespace without the rules, with a warning on stderr.

**rm** stops the hut and removes its units and what podman made from
them; its home and its record stay unless `--home`. With `--home`, a
hut already removed has the home it left removed. It removes the hut's
Ptyxis profile too.

**ptyxis** writes a Ptyxis profile, `moathut NAME`, whose tabs run
`moathut enter NAME` on the host (`default-container` `session`) and
whose new tabs do the same whatever the hut has printed
(`preserve-container` `never`). It sets the profile's keys with
`gsettings` at `/org/gnome/Ptyxis/Profiles/UUID/`, the UUID one derived
from the hut's name, and adds it to `profile-uuids`. Ptyxis's default is
the listed profile `default-profile-uuid` names, else the first listed,
so it refuses unless Ptyxis has a default of its own. `--remove`
removes the profile; a Ptyxis from Flatpak, whose settings are its own,
is not reached.

## The policy loop

The command line is simple. The policy is where the effort goes: every
host the workload reaches has to be listed.

- **log** follows the hut's record, one line per request or refused
  connection, from its last twenty, and on into the next file when it is
  rotated. With `--refused` it prints instead the lines, in the record
  and the rotated ones it keeps, whose decision is `drop`, counted by
  host and reason, with the method and path of a request the entries
  refused; and the responder's `unlisted_names`, the names the workload
  asked for that no list admits. Both leave out what the policy now lets
  through.
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
  at the command and not a hut whose inspector will not start. A policy
  that names a credential for the first time gains a broker, and one that
  names none loses it: the hut's units are written again. Then, if they
  are running, the inspector and the responder are reloaded
  ([POLICY.md](POLICY.md)): a request already relaying finishes, and
  the next is decided against the new document. Nothing is cut, and
  the command waits until the inspector's status file names the new
  document. The inspector is restarted instead when its unit changed,
  which a broker gained or lost does, when `tls` changed, or when it
  did not take the reload; a restart binds again in the same namespace,
  a connection in the gap is refused, not let through, and one open is
  cut. The command says which it did. A stopped hut has the policy from
  its next start; a running workload has a new credential's variable
  from its next start.

Package installs inside a hut are the hard case: a mirror list spreads
over many hosts, and the install does not outlive a stop (next
section). A hut's tools are better built into its image.

## What persists

Quadlet runs the workload with `--replace --rm`, and removes it at
stop: every start is a new container from the image. The hut's home is
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
into the hut's units and environment, where nothing secret belongs. All
of it is checked by the broker's own `build_profiles` with the real
secret first, so a key the broker would refuse is refused here. A
credential is sealed once and serves every hut whose policy names it.

Adding an ID that exists replaces it: the secret, and whichever of the
hosts, variable, header and format are given; the placeholder stays.
The units of every hut whose policy names it are written again and a
running broker is restarted, which a request in the gap finds refused.
A changed variable reaches a running workload at its next start. A
replacement a hut could no longer hold is refused, and nothing changes.

**credential ls** lists each credential: its ID, its variable, its
hosts, and the huts whose policy names it. **credential rm** refuses
while a hut's policy names the credential.

A credential's hosts are the most it is sent to. Each hut has its own
broker, holding the credentials its policy names, for those of their
hosts the policy brokers with them: the inspector's own choice of
credential for a host, among the hosts `credential add` named. The
broker picks a credential by `Host`, so a broker for every hut lets two
huts hold different keys for one provider, and `rm` takes the hut's
broker with it. The workload's environment gets each named credential's
variable, set to its placeholder.

## Files

For hut NAME, credential ID:

| what | where |
|---|---|
| what `create` decided, the level among it | `~/.config/moatery/hut/NAME/hut.json` |
| policy | `~/.config/moatery/hut/NAME/policy.json` |
| bundle | `~/.config/moatery/hut/NAME/bundle.pem` |
| prompt | `~/.config/moatery/hut/NAME/prompt.sh` |
| podman's override for the pod | `~/.config/moatery/hut/NAME/containers.conf` |
| seccomp profile | `~/.config/moatery/hut/NAME/seccomp.json` |
| CA, certificates, status files, the namespace's name | `~/.local/state/moatery/hut/NAME/` |
| record | `~/.local/state/log/moatery/hut/NAME/requests.log`, and `.1` to `.4.gz` |
| the hut's home | `~/.local/share/moatery/hut/NAME/home/` |
| namespace | `~/.config/systemd/user/moathut-NAME-netns.service` |
| the namespace, held | `$XDG_RUNTIME_DIR/moathut-netns/NAME` |
| pod, workload | `~/.config/containers/systemd/moathut-NAME.{pod,container}` |
| inspector, responder, broker | `~/.config/systemd/user/moathut-NAME-{inspect,resolve,broker}.service` |
| the record's rotation | `~/.config/systemd/user/moathut-NAME-rotate.{service,timer}` |
| broker's socket | `$XDG_RUNTIME_DIR/moathut/NAME/broker.sock` |
| credential | `~/.config/moatery/credentials/ID.{cred,json}` |

The container is named NAME, and so is its pod, so `podman` commands
take the hut's name; `create` refuses a name podman already uses. The
credentials are beside the huts, not among them, where they would be a
hut's directory.

## The units

moathut writes, for each hut, the units
[examples/quadlet/](../examples/quadlet/) has as files:
`moathut-NAME.pod` for `example.pod`, `moathut-NAME.container`
for `example.container`, `moathut-NAME-inspect.service` and
`-resolve.service` for the example's two listener units, and
`-broker.service` for `moat-broker.service`; and one the example does
not have, `moathut-NAME-netns.service`, the namespace's. The pod has
`UserNS=keep-id` and `--hosts-file=image`, so the host's hosts file
does not answer the workload's names, and no cgroup of its own. The
units differ from the example's in these ways:

- The namespace is not the pod's. The namespace's unit makes it
  (`moathut unit netns NAME`, under `podman unshare`) in the user
  namespace `podman unshare` is root in, and binds it at
  `$XDG_RUNTIME_DIR/moathut-netns/NAME` in podman's mount namespace; a
  path outside the broker's runtime directory, which the manager removes
  when the broker stops. It connects the namespace with pasta, given the
  arguments podman gives a pod's, loads the rules, writes the
  namespace's name (below), then forks a holder and names it the unit's
  main process (`MAINPID=`), so that podman exits and the holder, the
  manager's child then, is one whose end the manager sees: the unit
  fails, and the pod with it. Stopped, the holder unmounts the namespace
  and removes the file, at which pasta exits. A holder killed leaves
  them, and the next start lets them go first.
- The pod joins that namespace (`Network=ns:%t/moathut-netns/NAME`),
  and is `BindsTo=` and `After=` its unit. The pod's user namespace
  (keep-id) is a child of the one that owns the network namespace, so
  root in the hut, even with every capability `podman exec
  --privileged` gives, cannot change it, and the rules stay.
  `DNS=169.254.1.1` keeps the hut's `resolv.conf` as pasta's would be;
  the rules send port 53 to the responder whatever the address. podman
  applies `containers.conf`'s default net sysctls to a container joining
  a namespace by path, and the pod's infra container may not set them in
  one its user namespace does not own, so the pod's unit points
  `CONTAINERS_CONF_OVERRIDE` at the hut's `containers.conf`, which
  empties `default_sysctls`. The workload joins the pod's namespace,
  which podman sets none in.
- The tool starts the listeners in the namespace (`moathut unit exec
  NAME`), where the example has `moat-pod-netns`; it and `unit netns`
  are among the commands for the units' use. The egress device is read
  inside the namespace, not on the host.
- The workload `Wants=` the listeners, where the example's `Requires=`
  them, and a listener that dies is started again
  (`Restart=on-failure`); below says why.
- Each hut has a broker of its own, written only if its policy names a
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
  A package that rebuilds the system bundle cannot replace it: the
  rebuild renames a new file over the mount point, which fails with
  `EBUSY`. Upgrading Fedora's `ca-certificates` in a hut therefore fails
  its `%posttrans`, and dnf reports the transaction failed, with the
  packages installed and the hut's bundle unchanged.
- Each hut has a home of its own, a directory on the host that only it
  mounts, at the path the user's home has on the host: keep-id maps the
  user to the same name and uid inside. The user's own home directory
  is never mounted. The workload's working directory is that path too:
  podman writes the passwd entry of a user keep-id brings in with the
  working directory as its home, and `HOME` from it.
- Each hut has an SELinux level of its own, two categories no other hut
  has, drawn at `create` and kept in `hut.json`. Its pod and its
  workload run at it (the pod's `--security-opt label=level:`, the
  workload's `SecurityLabelLevel=`): the workload joins the pod's IPC
  namespace, and its `/dev/shm` is labelled at the pod's level. Its
  home, bundle, prompt and mark are mounted `:Z`, labelled at that
  level, which a container at any other is refused: another hut's, or
  one run by hand. A start that finds them labelled at it relabels
  nothing. A mount is `:z`, the label every container reads, so huts
  can share a project. A hut with no level in `hut.json` is given one
  by the next command that reads it, and runs at it from its next
  start.
- The workload's unit names the hut's user and drops every capability
  outside podman's default set ("Refused", below).
- At each start the workload's unit writes a sudoers drop-in, as root in
  the container (`ExecStartPost=`), giving the user sudo without a
  password: the image's own rule asks for one, and the user has none.
  Root in a hut is filtered as the user is.
- The record is rotated by the tool (`moathut unit rotate NAME`),
  from a timer the pod's unit `Wants=` and that is `PartOf=` it, a
  minute after that unit starts and every ten after, where the example
  has logrotate. Past 32 MiB the record is moved to `.1`, and the
  inspector's main process alone is sent `SIGHUP`, on which it opens the
  path again at its next write; the other processes in its unit are
  openssl mints, which a HUP ends. Four are kept, all but `.1`
  compressed: a line being written as the record moved lands in `.1`,
  which is compressed at the rotation after. The inspector stops writing
  a record past 512 MiB, and a hut writing that much in ten minutes
  loses its lines until the next rotation. The tool, not logrotate,
  which neither the image nor every host has.
- The programs run with python's `-s`, so the user's own site-packages
  cannot come ahead of the installed package.
- No `[Install]` unless `--autostart`: without it a hut runs from
  `enter` to `stop`.
- `Timezone=local`: the workload's clock reads in the host's zone, not
  the image's (UTC in Fedora's).
- The prompt is mounted read-only at `/etc/profile.d/moathut.sh`, and
  puts `⬢ NAME` before bash's prompt, magenta, or red as root. Fedora's
  `/etc/bashrc` reads it, so root's shell has it from the image's
  `/root/.bashrc`. `create` gives a home without them a `.bash_profile`
  that reads `.bashrc`, and a `.bashrc` that reads `/etc/bashrc`, puts
  `~/.local/bin` and `~/bin` on `PATH`, and reads the prompt, which an
  image whose `bashrc` does not read `/etc/profile.d` needs; `enter`'s
  shell is a login shell, which reads only the first. Files the home has
  are kept. The prompt is written with the units. A mount may not cover
  it.
- The prompt also warns, in an interactive shell only, when the shell is
  in another namespace than the rules were loaded into, as one in a
  container run by hand from the hut's image and files is. Its prompt
  then reads `⬢ NAME UNPROTECTED`, white on red. The namespace's unit,
  after loading the rules, writes the namespace's name (`net:[INODE]`,
  as `/proc/self/ns/net` reads) to `netns` in the hut's state
  directory, in place, since the workload mounts that file read-only at
  `/run/moathut/netns`, and leaves it there when it stops. It is made
  empty with the units, since podman will not start a container whose
  mount source is missing, and a shell reads an empty one as not
  knowing. A mount may not cover it. A shell `podman exec --privileged`
  opens is not warned: it is in the namespace with the rules, and
  cannot change them.
- Units written while the hut's pod runs, by `allow`, `policy` or
  `credential add`, leave the namespace's, the pod's, the override and
  the prompt as they are: after a reload, the manager stops a running
  unit that has gained a `BindsTo=` on one that is not running. `enter`
  writes every file when it starts a stopped hut, so its next `enter`
  after a `stop` brings every unit up to date; a hut started at login
  is not.

What starts what: `enter` starts `moathut-NAME.service`, which
`Wants=` and is `After=` the inspector and the responder; they are
`BindsTo=` and `After=` the pod's unit, which is `BindsTo=` and
`After=` the namespace's, active only once the namespace is connected
and has the rules. A rules load that fails fails that unit, and nothing
after it starts. The pod's unit `Wants=` the listeners, so its restart
brings them back, into the same namespace, with the same rules. A stop
of the namespace's unit stops the pod's, and what is bound to it. The
inspector `Wants=` the broker and starts after it is listening.

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
  units that load a hut's rules, which a hut able to write them could
  drop;
- a name outside `[a-z0-9-]`, or one podman already uses;
- a policy naming a credential that has not been added, an entry naming
  one for a host `credential add` did not name, a credential an earlier
  entry takes every host of, and two credentials setting one variable;
- a credential in a hut when `XDG_RUNTIME_DIR` is not set, since the
  broker's socket is in it.

`credential add` refuses a host that is not a name, a variable the hut
sets itself (the CA variables, `TERM`, `COLORTERM`, `LANG`), a format
without `{secret}`, and whatever the broker would refuse at its start: a
header that is not one, a secret with a line break, a placeholder equal
to it.

Nothing is passed to podman that the tool does not write itself: no
network but the namespace the tool holds, and no capability, device,
`--privileged` or hosts flag. The workload's unit drops every
capability outside podman's default set,
which has no `NET_ADMIN`, so a `containers.conf` cannot widen root's in
the hut. It adds none, and names the hut's user: podman gives the user
the capabilities a unit adds, and root's when the unit names no user.
The user holds none.

## Seccomp

The workload's unit names the hut's profile (`SeccompProfile=`), and
crun loads it for every process in the container and every `podman
exec`, a privileged one too: an exec changes capabilities, not the
filter.

`strict`, the default, is podman's default profile (containers-common)
with its capability conditions resolved for the hut's capabilities,
refusing more:

| refused | fails with | why |
|---|---|---|
| `unshare` and `clone` with a `CLONE_NEW*` flag; `setns` | EPERM | nothing in the hut is root in a namespace of its own, where the kernel's network and mount code is open to it |
| `clone3` | ENOSYS | glibc falls back to `clone`, whose flags the filter can read; `clone3`'s are behind a pointer |
| `mount`, `umount2`, `pivot_root`, `fsopen`, `fsmount`, `fsconfig`, `fspick`, `open_tree`, `move_mount`, `mount_setattr` | EPERM | |
| `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd` | EPERM | `debug` allows them |
| `keyctl`, `add_key`, `request_key`, `io_uring_*`, `socketcall` | ENOSYS | programs do without a keyring or io_uring a kernel lacks; io_uring's and socketcall's operations are out of the filter's sight |
| `socket(AF_VSOCK, ...)`, however the family is written | ENOSYS | a vsock reaches the host, or a VM's hypervisor, around the network namespace |

A call the profile does not name fails with ENOSYS, as one the kernel
lacks would. Under `strict`, gdb says "During startup program exited
with code 127", strace "ptrace(PTRACE_SEIZE, ...): Operation not
permitted", and `unshare -Ur` "unshare failed: Operation not
permitted". `debug` is `strict` with the four ptrace calls allowed, for
gdb, strace and profilers; neither makes a namespace. A named profile is
written again with the units, so a hut takes the profile of the moathut
that starts it; a file given to `--seccomp` is kept as it was copied.

`strict` breaks containers inside a hut (podman, buildah), bubblewrap
and the sandboxes built on it (Flatpak's, Claude Code's on Linux),
Chromium's sandbox, and anything that runs `unshare`. A hut that needs
them takes a profile of its own; `--seccomp
/usr/share/containers/seccomp.json` is podman's default.

Refusing ptrace narrows the kernel a hut reaches. It does not keep the
hut's processes from one another: they share a user, and
`/proc/PID/mem` is a file, not a call the filter sees.

podman's default refuses a vsock by comparing the whole register, while
the kernel reads the family as an int, so a family with an upper bit
set gets a vsock under it. `strict` allows families by masked blocks
that keep the upper half, and a vsock by none. moathut/seccomp.py says
which of libseccomp's readings the rules are shaped around.

## What is not closed

A workload restart, by anything, keeps the namespace and its rules, and
so does a restart of the pod, by the manager or by podman (`podman pod
restart NAME`): the pod joins the namespace the namespace's unit holds.
A pod started while that unit is stopped does not start, since the
namespace's file is gone; and a stopped hut leaves no pod or container
to start: quadlet removes them. A shell opened with `podman exec
--privileged`, as Ptyxis opens every container's tab, runs as the hut's
user with no capability in effect, but its bounding set is every
capability (`000001ffffffffff`, where a moathut shell's is
`00000000800405fb`), so root in it, by sudo, holds every capability in
the hut's user namespace. That namespace does not own the network
namespace, so even that root cannot change the rules. It keeps the
hut's seccomp profile and SELinux label, which podman's exec does not
change, so it makes no namespace and mounts nothing, but it is still a
shell whose sudo has every capability in the hut, and Ptyxis lists
huts in its container menu and opens a new tab in the container a
tab's text last named (OSC 777 or 666), which a workload can print;
`moathut ptyxis NAME` writes a profile that opens the hut without it.

What stays open, and is warned about:

- The user, on the host, is root over the namespace (`podman unshare`),
  and can remove the rules. `enter` refuses such a hut and `ls` marks it
  `unprotected`, but shells already in it cannot tell.
- A hut's mounts are labelled for every container to read, so huts
  can share them, and so can any container the user runs. Podman draws
  an ordinary container's level from the same pairs of categories as a
  hut's, without knowing a stopped hut's: the chance of one drawn twice
  is one in 523776.
- A container run by hand from the hut's image is not the hut: podman
  gives it a network of its own, without the rules. An interactive shell
  in one that mounts the hut's prompt and mark warns; one that mounts
  neither cannot know it is the hut's.

## Where it lives

`moathut` is a host layout, the thing DESIGN.md says moatery is not.
Its code is its own package, `moathut`, beside `moatery`. It may
import `moatery` (the policy loader); the programs never import it.
The moatery RPM carries it, `/usr/bin/moathut` and the package beside
`moatery` in site-packages; there is no separate package.
`tests/test_closure.py` holds both: the imports, and the RPM's spec
installing both packages and every program.
Its bash completion, `completions/moathut.bash`, is installed where
bash-completion loads it; it completes commands, options, hut names
from `~/.config/moatery/hut` and credential names, and
`tests/test_completion.py` holds it to the parser and those paths.

## Requirements

The moatery programs; podman 5.3 or later (quadlet `.pod` units with
`DNS=`), with pasta; util-linux's `unshare`, `nsenter` and `umount`;
systemd 256 or later (`LoadCredentialEncrypted=` in a user unit); a
lingering user (`loginctl enable-linger`) for a hut to outlive the login
session.

## Proving it

A rig, `tests/manual/hut_rig.py`, on a real host, through the command
line ([tests/manual/README.md](../tests/manual/README.md)):

- the workload's first request at every start, the hut's first, each
  restart of the workload and of the pod, and `enter` after `stop`, is
  inspected: the rules and the listeners are in place before it;
- a rules load that fails starts nothing, and `enter` refuses the hut;
- a listed host answers and an unlisted one is refused 403, as the user
  and as root by sudo; the workload's DNS is the responder's; UDP 443,
  TCP 22 and a stray datagram are dropped and counted;
- root in the hut holds no `CAP_NET_ADMIN`, and the user no capability;
  root in a shell `podman exec --privileged` opens, and root with every
  capability in the hut's user namespace, are refused changes to the
  namespace and its rules, and the shell is not warned; the pod is in
  the namespace the namespace's unit holds, whose pasta has the
  arguments podman gives a pod's;
- the hut's user, and root in a privileged exec, are refused by the
  profile a namespace, a mount, ptrace, the keyring and a vsock however
  its family is written, while a thread, an inet and a netlink socket
  reach the kernel; in a stock container the same calls reach the
  kernel; under `debug`, ptrace does;
- the workload runs at the hut's level, and its home, bundle, prompt and
  mark are labelled at it; its `/dev/shm` is writable; a container at
  podman's own level is refused the hut's home, and one at the hut's
  reads it; two huts share a mount, at their two levels;
- `enter` runs in the hut's home, or the mount the host's directory is
  in; the user's own home is not the hut's; a file outside the home is
  gone after a restart;
- `podman pod restart` keeps the namespace and its rules; a pod the hut
  left does not start while the namespace's unit is stopped; with a
  table removed from the host, `ls` marks the hut unprotected and
  `enter` refuses it; a container run by hand from the hut's image and
  files warns;
- a brokered request reaches a stub provider carrying the sealed key,
  at every start of the broker as well, while the hut holds the
  placeholder and has no path to the broker's socket; a stopped broker's
  request is refused, never sent without the key, and `enter` starts it
  again, even after a stop while it started; a new key with `credential
  add` is the next request's, and neither the inspector nor the workload
  restarted;
- `rm` leaves no unit, container or namespace, nor the broker's socket,
  and keeps the home and the record, which `create` finds again; `rm
  --home` removes the home; `credential rm` is refused while a hut names
  the credential;
- `log --refused` names a host the hut was refused; `allow` lists it and
  reloads the listeners, a download running through it finishing whole,
  and the host is dialled after;
- a `policy` edit the loader refuses changes and restarts nothing;
- a killed inspector is started again, and a stopped one leaves the
  workload running until `enter` starts it;
- `log` follows a request as it is made;
- the rotation's timer runs with the pod's unit, and a record
  past its size is moved aside and the next request's line is in a new
  one.

Unit tests hold the generated units' dependencies to the chain above,
each one broken on purpose once, and the refusals.
