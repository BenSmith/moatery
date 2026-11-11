# GitHub Copilot CLI in a hut

Copilot CLI runs in a hut with your host's GitHub login sealed on the
host; the hut holds only a placeholder. The recipe is
`examples/copilot/copilot_hut.py`, installed with these documents: it
seals the login, writes the policy, and installs a pinned release of
the CLI. Run the commands below from the checkout's root or
`/usr/share/doc/moatery`. [MOATHUT-GUIDE.md](MOATHUT-GUIDE.md) covers
huts in general.

**Provisional.** This policy, and the rig that checks it, have not yet
been run against GitHub. A route Copilot needs may be missing from it;
`moathut log copilot-hut --refused` shows it.

## 1. Your host's login, sealed (once, on the host)

Log in with Copilot CLI on the host first, then:

```
recipe=examples/copilot/copilot_hut.py
python3 "$recipe" enroll
```

It reads the active github.com account's OAuth token from
`~/.copilot/config.json` (`$COPILOT_HOME`, or `--copilot-home DIR`
before `enroll`), and hands it to `moathut credential add copilot` on
its standard input. The credential's hosts are `api.github.com` and
Copilot's four API backends; the hut gets a placeholder in
`COPILOT_GITHUB_TOKEN`, and the broker sends the real token as
`Authorization: Bearer` on the way out.

The placeholder starts with `gho_` (`--placeholder-prefix`), since
Copilot checks a token's shape before it sends a request.

Only a token kept in that file works: not one in a keychain, and not a
GitHub Enterprise account. `enroll` fails, and seals nothing, when it
finds none. The token is the host's own, so revoking it logs out both.

## 2. Create the hut

```
python3 "$recipe" policy > ~/copilot-policy.json
moathut create copilot-hut --network-policy ~/copilot-policy.json \
    --image registry.fedoraproject.org/fedora-toolbox:45
```

- `api.github.com` is brokered, for `GET` on the account and policy
  routes Copilot reads at start, and the CLI's release list.
- The four `*.githubcopilot.com` backends are brokered, for the model
  list, inference, and GitHub's MCP server through `/mcp/readonly`.
  The read-write `/mcp` and remote agent sessions (`/agents/sessions`)
  are refused: either would let the hut act on your repositories with
  your token. So is `/copilot_internal/v2/token`, which trades the
  token for another.
- `github.com` and `*.githubusercontent.com` serve the CLI's download;
  `exp.githubcopilot.com` and `exp.*.githubcopilot.com` are Copilot's
  feature flags.

Add what your work needs with `moathut allow copilot-hut HOST`.

## 3. Install Copilot CLI

```
moathut enter copilot-hut -- python3 - install < "$recipe"
```

It installs the release the recipe pins into the hut's
`~/.local/bin/copilot`, for x86_64 or aarch64. The archive is checked
against the pinned SHA-256 before anything is unpacked, and the binary
must report the pinned version before it replaces the old one. Run
again, it leaves a binary at that version alone.

## 4. Run it

```
moathut enter copilot-hut
copilot --no-auto-update
```

`--no-auto-update` keeps the pinned release. Don't run `/login` in the
hut: it would keep a token in the hut's home.

## Checking

```
moathut log copilot-hut            # every request, as it happens
moathut log copilot-hut --refused  # what was refused, by host and path
```

A route Copilot needs and the policy lacks shows up in `--refused`. On a
brokered host, allow only that method and path
(`moathut allow copilot-hut HOST --method M --path P`), not the whole API.

In a checkout, `tests/manual/copilot_rig.py copilot-hut` runs the wiring
against GitHub: the placeholder, the brokered routes, the refused ones
in the hut's record, one inference request, and no copy of the token
in the hut's home.

## After logging in again on the host

Run `enroll` again. The sealed token is replaced, the placeholder kept,
and the broker of every hut that names `copilot` restarted.

## A newer release

Set `COPILOT_VERSION` and both digests in `ASSETS` in the recipe from
the release's `SHA256SUMS.txt`, and run step 3 again.

## Not covered

- A sandbox of Copilot CLI's own. Leave any namespace-based one off:
  under `strict` it cannot make its namespaces, and the hut is the
  sandbox.
