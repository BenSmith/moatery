# Using moathut

A box is a long-lived container for an agent or a toolchain you run
from a terminal. Everything it sends out over HTTPS or HTTP passes
through an inspector that checks it against a policy you write. Other
traffic is dropped. The box can hold a placeholder in place of an API
key, and the real key is added on the way out, so the box never sees
it.

This guide is the how-to. [MOATHUT.md](MOATHUT.md) is the reference: what each
command does exactly, the files and units, and what is refused and why.

## Before you start

You need, on the host:

- Python 3.14 and OpenSSL 3.5 or later;
- podman 5.3 or later, with pasta, and nftables;
- systemd 256 or later;
- the moatery RPM, which carries `moathut` and the programs it
  runs, and with bash-completion installed, tab completion of its
  commands and box names.

To run it from a checkout of this repository instead, point it at the
checkout's programs:

```
export PYTHONPATH=~/src/moatery MOATERY_LIBEXEC=~/src/moatery/libexec
alias moathut='python3 ~/src/moatery/bin/moathut'
```

A box's units remember these paths when it is created, so they keep
working in a shell that doesn't have them set.

For a box to keep running after you log out, turn on lingering once:
`sudo loginctl enable-linger $USER`.

## Your first box

**1. Write a policy.** It lists the hosts the box may reach, as JSON.
This one allows Python packages and GitHub:

```json
{
  "hosts": ["pypi.org", "files.pythonhosted.org",
            "github.com", "*.githubusercontent.com"]
}
```

Save it anywhere, say `~/policy.json`. `create` takes a copy, so later
edits to this file don't reach the box. [POLICY.md](POLICY.md) explains
every key; the ones you need most are shown in this guide.

**2. Create the box.**

```
moathut create work --policy ~/policy.json --mount ~/src/project
```

Box names use lowercase letters, digits and `-`. `create` pulls the
image if it has to, mints the box's certificate authority and writes
its units. Nothing starts yet.

The default image is Fedora's toolbox image (`fedora-toolbox:44`),
which has git, Python, an ssh client and manual pages. Use `--image` to
choose another.

`--autostart` starts the box whenever you log in, and, with lingering
on, when the host boots. Without it, a box starts at its first `enter`.

`--dry-run` prints the files `create` would write, and writes nothing.

`--like` makes a box like one you already have: the same policy, image
and mounts, and a new home. The two share the mounts.

```
moathut create work2 --like work
```

`--mount` shares a host directory with the box. Repeat it for more
directories. `SRC:DST` puts it at a different path inside, and a
trailing `:ro` makes it read-only. Your home directory itself can't be
mounted, but a directory inside it can.

**3. Enter it.**

```
moathut enter work
```

The first `enter` starts the box, which takes a few seconds, and opens
a login shell as you. After that, `enter` opens another shell in the
running box. If you run it from inside a mounted directory, the shell
starts in that directory; otherwise it starts in the box's home.

To run one command instead of a shell, put it after `--`:

```
moathut enter work -- git clone https://github.com/example/repo
```

`--root` enters as root. `sudo` also works inside the box, with no
password. Root in a box is filtered the same way you are.

In bash, the prompt starts with `⬢ work`, so you can tell which box a
terminal is in: magenta for you, red for root. If the ⬢ shows as a
box, your terminal's font lacks it; Fedora's
`google-noto-sans-symbols-2-fonts` has it, and a terminal started after
it is installed falls back to it. The box keeps your host's time zone.

## What the box keeps

Every start is a fresh container from the image. What survives a stop:

- **The box's home.** It has its own home directory, separate from
  yours, so anything installed under it (`pip install --user`, tools in
  `~/.local`) is kept. SELinux keeps every other box and container out
  of it; you can still reach it from the host.
- **Your mounts.** These are your own directories. Any box can mount
  the same directory, so two boxes can work on one project.

What doesn't survive: anything else written to the container, such as a
`dnf install`. If a box needs a tool every time, build an image that
has it and pass it with `--image`. Installing packages in a box is also
awkward for a second reason: mirrors spread across many hosts, and each
has to be allowed.

The trust settings are already done for you. The box's certificate
authority replaces the image's system bundle, and `SSL_CERT_FILE`,
`NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO` and
`PIP_CERT` point at it, so curl, git, pip, Python and Node trust the
inspector without any setup.

## Coming from toolbx or distrobox

The commands will look familiar, and the default image is the one
toolbx uses, but the aim is the opposite. toolbx and distrobox make a
container part of your desktop: your home, the host's network, its
devices, its D-Bus and its root filesystem are all inside. A box is
kept apart from your desktop, and what it sends out is checked.

| toolbx / distrobox | moathut |
|---|---|
| `toolbox create` / `distrobox create` | `moathut create NAME --policy FILE` |
| `distrobox create --clone` | `moathut create NAME --like BOX` (not its home) |
| `toolbox enter` / `distrobox enter` | `moathut enter NAME` |
| `toolbox run CMD` / `distrobox enter -- CMD` | `moathut enter NAME -- CMD` |
| `toolbox list` / `distrobox list` | `moathut ls` |
| `distrobox stop` | `moathut stop NAME` |
| `toolbox rm` / `distrobox rm` | `moathut rm NAME` |

What you will notice first:

- **Your home isn't there.** The box has a home of its own, at the same
  path as yours, so your dotfiles, ssh keys and tokens are out of its
  reach. Mount the project directories you work in with `--mount`, and
  copy in any configuration the box should have, at
  `~/.local/share/moatery/box/NAME/home/` on the host.
- **`dnf install` doesn't last.** Every start is a fresh container, so
  build the tools into an image (below), or install them under the
  home.
- **The network isn't the host's.** The box reaches only the hosts its
  policy lists, over HTTPS and HTTP. Nothing on your host or your LAN
  answers it unless the policy lists it, and a server started in the
  box can't be reached from outside it. Use HTTPS git remotes.
- **No display, audio, GPU or devices,** and none of `/run/host`,
  `distrobox-export`, `distrobox-host-exec` or `flatpak-spawn --host`.
  These would let the box reach the host.
- **sudo works,** but root in a box has no more network access than
  you do, and can't change the rules.
- **Enter it with moathut,** not with a terminal's container menu. See
  "When the moat doesn't cover you", below.

To build an image with your tools:

```
cat > Containerfile <<'EOF'
FROM registry.fedoraproject.org/fedora-toolbox:44
RUN dnf -y install ripgrep nodejs && dnf clean all
EOF
podman build -t localhost/work .
moathut create work --policy ~/policy.json --image localhost/work
```

The build runs on the host, so it doesn't need the box's policy.

## Debuggers, nested containers and sandboxes

A box also limits which kernel calls run in it. Nothing in it can make
a namespace or mount a filesystem, so podman, buildah, bubblewrap
(Flatpak, Claude Code's sandbox) and Chromium's sandbox don't work in a
box, and `unshare` fails with "Operation not permitted". Debuggers are
refused too: gdb says "During startup program exited with code 127",
and strace "Operation not permitted".

For a box you debug in, allow them:

```
moathut create dbg --like work --seccomp debug
```

`debug` allows gdb, strace and profilers, and still no namespace. For
anything else, pass a seccomp profile of your own, which is copied in;
`--seccomp /usr/share/containers/seccomp.json` is podman's default,
which allows the namespaces nested containers need. A box made `--like` another gets its
profile. `moathut ls` names a box's profile if it isn't the default.
[MOATHUT.md](MOATHUT.md), "Seccomp", lists what is refused.

## When the moat doesn't cover you

The box's network belongs to moathut, not to the box, so nothing in
the box can change its rules: not root, and not a shell opened with
`podman exec --privileged`, as Ptyxis opens every container's tabs. A
box restarted with `podman pod restart` keeps its network and its rules,
and a box moathut stopped can't be started by podman at all.

**Ptyxis.** It lists your boxes in its container menu, and a tab
opened from there is a privileged shell. The shell is you, but `sudo`
in it gets every capability inside the box, where `sudo` in a moathut
shell gets fewer. It still can't change the rules, but prefer `moathut
enter work`. Text printed in a tab can also make Ptyxis open
the next new tab this way, and a program in the box can print it.

To open the box from Ptyxis the moathut way, give it a profile:

```
moathut ptyxis work
```

This adds a profile, `moathut work`, to Ptyxis. Its tabs run `moathut
enter work`, which starts the box if it is stopped, and a new tab from
one of them enters the box again, whatever the box has printed.
`moathut ptyxis work --remove` removes it, and so does `moathut rm
work`. Open Ptyxis once before the first, so it has a default profile
of its own; a Ptyxis from Flatpak isn't reached.

**A container you run yourself** from the box's image isn't the box:
podman gives it a network of its own, with none of the rules. If it
mounts the box's files, its shells print

```
moathut: box work is not protected by the moat.
```

and its prompt reads `⬢ work UNPROTECTED`. Close it, and use `moathut
enter work`.

**Rules removed from the host.** You are root over the box's network
from the host (`podman unshare`), so you can remove its rules. `moathut
ls` then marks the box `unprotected`, and `enter` refuses it. Run
`moathut stop work`, then `moathut enter work`.

Only interactive shells warn: a command run with `podman exec work CMD`
gets no warning.

## When something is refused

A host that isn't allowed gets a `403 Forbidden` from the inspector.
Other ports (ssh, and UDP other than DNS, such as QUIC) are dropped;
DNS goes to the box's own responder.
Git over ssh won't work from a box; use HTTPS remotes.

**See what happened.** `log` follows the box's record, one line per
request or refused connection:

```
moathut log work
```

```
2026-09-30T14:02:11.482Z  forward 200  GET     pypi.org/simple/requests/
2026-09-30T14:02:15.907Z  drop    403  terminate example.org  (not allowlisted)
```

It starts from the last twenty lines and keeps following. Press Ctrl-C
to stop. A line ending `suspect` is a refusal no ordinary client
causes, such as something other than TLS on the HTTPS port; it needs no
change to the policy, but is worth a look. [LOGGING.md](LOGGING.md)
lists every reason. The record is rotated at 32 MiB, and the four before it are
kept beside it.

**See what is still refused.** `log --refused` sums up, by host and
reason, what the record holds that the current policy would still
refuse. It also lists the names the box looked up that no list admits:

```
moathut log work --refused
```

```
refused, and refused by the policy now:
       2  example.org  (not allowlisted)
names asked for that no list admits:
       4  example.org
to allow one: moathut allow work HOST [--method M]... [--path P]...
```

Some names in that last list are just lookups a tool made and didn't
need. Allow the hosts you want the box to use, not every name listed.

**Allow a host.**

```
moathut allow work example.org
```

This adds the host to `hosts`, which allows any method and any path. To
allow less, give the methods or paths:

```
moathut allow work api.example.org --method GET --path '/v2/*'
```

`--method` and `--path` can be repeated. In a path pattern, `*` also
matches `/`, so `/v2/*` covers everything under `/v2/`. `allow` only
ever adds. It takes a host name; to allow a pattern such as
`*.example.org`, edit the policy.

**Edit the policy.**

```
moathut policy work
```

This opens the box's policy in `$VISUAL`, `$EDITOR` or `vi`. When you
save and quit, the document is checked before it replaces the old one.
If it has a mistake, you're told what's wrong and offered the editor
again. Nothing changes until a document loads.

Either command applies the change to a running box straight away, and
prints what it did:

- `its inspector and responder reloaded` is the usual case. The new
  policy decides the next request. Nothing is interrupted: a download
  already running finishes.
- `its inspector restarted, since ...`: some changes need a restart,
  such as adding the first credential, removing the last one, or
  changing `tls`. Connections open at that moment are cut.
- `it applies from the box's next start`: the box wasn't running.

## API keys

A box can use an API key without ever holding it. You seal the key on
the host once. The box gets a placeholder in an environment variable,
and the real key replaces it on the way out, only on requests to the
hosts you name.

**1. Seal the key.**

```
moathut credential add anthropic --host api.anthropic.com \
    --env ANTHROPIC_API_KEY
```

It asks for the key without echoing it, or reads it from standard input
if you pipe it in. The key is encrypted to your user on this host with
`systemd-creds`.

`--host` is the most the key will ever be sent to; repeat it for more
hosts. By default the key goes in an `x-api-key` header. For a provider
that wants `Authorization: Bearer KEY`, add
`--auth-header Authorization --auth-format 'Bearer {secret}'`.

**2. Name it in the box's policy.** Use `moathut policy work` and
add an entry:

```json
{
  "hosts": ["pypi.org", "files.pythonhosted.org"],
  "policy": [
    {"host": "api.anthropic.com", "methods": ["POST"],
     "paths": ["/v1/messages"], "credential": "anthropic"}
  ]
}
```

Always give a brokered entry `paths`, listing the endpoints the box
actually calls. Without them, the box could call any endpoint with the
real key attached, including one that echoes the request's headers
back, which would hand it the key.

The first credential a box names gives it a broker, the process that
holds the keys, so this edit restarts the inspector. The variable
(`ANTHROPIC_API_KEY` here) is set when the workload starts, so stop the
box and enter it again:

```
moathut stop work
moathut enter work
```

Inside, `echo $ANTHROPIC_API_KEY` shows a placeholder. A client using
it works as if it held the real key.

**Replace a key** by running `credential add` again with the same ID.
Only the new secret is required. Hosts, variable, header and format
stay as they were unless you give them again. The broker of each box
using the key restarts with the new one; neither the inspector nor the
workload does. A request made during that moment is refused, not sent
without a key.

**List and remove.** `moathut credential ls` shows each credential
with its variable, its hosts, and the boxes whose policy names it.
`moathut credential rm ID` removes one, and is refused while any
box's policy still names it.

A key is sealed once and can serve many boxes. Each box has its own
broker, so two boxes can use different keys for the same provider.

## Stopping and removing

```
moathut ls              # each box, whether it is running, its image,
                        # and unprotected if its rules are gone
moathut stop work       # stop it; enter starts it again
moathut rm work         # remove it; keeps its home and its record
moathut rm work --home  # remove its home too
```

`rm` prints the paths it kept. A box created again with the same name
finds its old home and record. `moathut rm work --home` after a plain
`rm` removes the home it kept.

## When things go wrong

**A command fails.** The command prints what went wrong, and usually
the `journalctl --user -u ...` line to run for the details.

**`box work did not start`** means one of the box's units failed. Run
the journalctl command it prints. A common cause is the image lacking
something the box needs.

**`box work's namespace has no moatery rules`** means the rules were
removed from the box's network, from the host. Its traffic would not be
inspected, so `enter` refuses it. Run `moathut stop work`, then enter
it again ("When the moat doesn't cover you", above).

**After upgrading moatery,** a box that was running keeps the setup it
started with until you run `moathut stop work`, then `moathut enter
work`.

**`box work's inspector did not start`** (or responder, or broker):
`enter` still enters, but warns you. Without the inspector, connections
are refused; without the responder, names don't resolve; without the
broker, requests needing a key are refused, never sent without it.
Nothing leaks, but things fail until the unit starts. The journalctl
line in the warning shows why.

**Everything gets 403.** Check `moathut log work --refused` to see
what was refused and why. `not permitted by policy` means the host is
allowed, but not that method or path.

**A tool complains about certificates.** It is probably ignoring the
system bundle and the variables above. Point it at `$SSL_CERT_FILE`.
Some clients pin a certificate or require HTTP/2 only; those need the
host in `splice` ([POLICY.md](POLICY.md), "splice" and "HTTP/2"),
which checks the name only and nothing inside the connection.

**`dnf upgrade` fails in `ca-certificates`,** with `p11-kit: couldn't
complete writing file: .../tls-ca-bundle.pem: Unknown error 16`. The
box's certificate bundle is mounted where that package rebuilds its
own, so its rebuild can't replace it. The other packages are installed,
and the box's trust is unchanged. Leave that package out:

```
sudo dnf upgrade -y --exclude=ca-certificates
```

Or pull a newer image on the host, which lasts beyond the box's next
stop: `podman pull` it, then `moathut stop work` and `moathut enter
work`.

**An upload to a brokered host fails with 411.** The broker needs to
know the request body's length in advance, so a client that streams
its upload in chunks is refused. Provider SDKs send a length and aren't
affected.

## Where things are

For a box named `work`:

| what | where |
|---|---|
| its policy | `~/.config/moatery/box/work/policy.json` |
| its record | `~/.local/state/log/moatery/box/work/requests.log` |
| its home | `~/.local/share/moatery/box/work/home/` |
| its seccomp profile | `~/.config/moatery/box/work/seccomp.json` |
| its units | `systemctl --user status 'moathut-work*'` |

Edit the policy with `moathut policy`, not in place: the command
checks it first and applies it. [MOATHUT.md](MOATHUT.md), "Files", lists the
rest.
