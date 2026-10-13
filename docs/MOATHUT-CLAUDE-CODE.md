# Claude Code in a hut

Claude Code runs in a hut under the default `strict` seccomp profile.
Leave its own bubblewrap sandbox off: the hut is the sandbox. Your
subscription's token stays sealed on the host; the hut holds only a
placeholder. [MOATHUT-GUIDE.md](MOATHUT-GUIDE.md) covers huts in
general.

## 1. Your subscription's token, sealed (once, on the host)

`claude setup-token` makes a long-lived token for your Claude subscription.
Run it where Claude Code is already logged in, on your desktop say, and
seal what it prints:

```
claude setup-token
moathut credential add claude --host api.anthropic.com \
    --env CLAUDE_CODE_OAUTH_TOKEN \
    --auth-header Authorization --auth-format 'Bearer {secret}'
```

The second command asks for the token without echoing it. The hut gets
a placeholder in `CLAUDE_CODE_OAUTH_TOKEN`; the broker swaps in the
real token on the way out, so nothing in the hut can read it.

Such a token is for inference only. Claude Code in the terminal works;
Remote Control and the Chrome integration don't, and `claude doctor`
says it cannot load your organization's policy.

## 2. The policy

```
cat > ~/claude-policy.json <<'END'
{
  "hosts": ["claude.ai", "downloads.claude.ai",
            "mirrors.fedoraproject.org", "dl.fedoraproject.org",
            "download-ib01.fedoraproject.org",
            "d2lzkl7pfhq30w.cloudfront.net",
            "codecs.fedoraproject.org", "ciscobinary.openh264.org",
            "pypi.org", "files.pythonhosted.org",
            "github.com", "*.githubusercontent.com"],
  "policy": [
    {"host": "api.anthropic.com", "methods": ["GET", "HEAD", "POST"],
     "paths": ["/v1/messages", "/v1/messages/*", "/api/*",
               "/mcp-registry/*"],
     "credential": "claude"},
    {"host": "platform.claude.com", "methods": ["GET"],
     "paths": ["/v1/oauth/hello"]}
  ]
}
END
```

- `claude.ai` serves the installer; remove it once Claude Code is
  installed.
- `downloads.claude.ai` serves the binary, and its updates.
- `api.anthropic.com` is brokered: every request to it carries your
  token, attached on the way out. Its paths are the model and Claude
  Code's own endpoints there (settings, feature flags, event logging,
  the MCP registry).
- `platform.claude.com` is Claude Code's other check at start: it
  stops with "Failed to connect" without it. The check carries no
  token, so it is not brokered, and nothing else there is allowed.
- The Fedora hosts are for `sudo dnf install`. They are Fedora's own:
  `mirrors.fedoraproject.org` lists the mirrors, and three serve the
  packages: `dl.fedoraproject.org` and
  `download-ib01.fedoraproject.org`, Fedora's servers, and the
  CloudFront host, Fedora's mirror on Amazon's CDN. The
  `codecs`/`openh264` pair is the OpenH264 repository Fedora enables by
  default. The list names many other mirrors, which depend on where
  you are; they are refused, and dnf should move on through the list
  (untested). To use a mirror near you, allow one that `moathut log
  claude --refused` shows.
- `pypi.org` to the end is for your own work. Add what your projects
  fetch.
- Claude Code also sends logs to `http-intake.logs.us5.datadoghq.com`.
  It works without it; leave it refused.

## 3. Create the hut and install Claude Code

```
moathut create claude --network-policy ~/claude-policy.json \
    --mount ~/src/project
moathut enter claude -- \
    bash -lc 'curl -fsSL https://claude.ai/install.sh | bash'
```

`--mount` names a project directory of yours, which must exist; leave
it out for a hut with only its own home. Claude Code installs into the
hut's home (`~/.local/bin/claude`), so it survives stops, and updates
itself from `downloads.claude.ai`.

## 4. Run it

```
moathut enter claude
echo '{"hasCompletedOnboarding": true}' > ~/.claude.json
claude
```

It finds the token in `CLAUDE_CODE_OAUTH_TOKEN` and starts logged in;
`claude auth status` says `oauth_token`. The `~/.claude.json` line is
once per hut: without it, the first run of a new home shows the login
menu even though it is logged in. Don't choose from that menu; it would
log in inside the hut, and keep the token in its home.

To open it from Ptyxis instead: `moathut ptyxis claude`, then choose the
`moathut claude` profile.

## Checking

On the host, in another terminal:

```
moathut log claude              # every request, as it happens
moathut log claude --refused    # what was refused, by host
```

A host Claude Code or a tool needs and the policy lacks shows up in
`--refused`; allow it with `moathut allow claude HOST`.

## Logging in inside the hut instead

For Remote Control or the Chrome integration, log in in the hut rather
than seal a token. Leave out `credential add`, and give the policy
`api.anthropic.com` in `hosts`, unbrokered, with `platform.claude.com`
and `console.anthropic.com` beside it: one of them is where the login
trades its code for a token (which, untested; `moathut log claude`
shows it, and the other can go). In the hut, run `claude` and choose
your Claude account: it prints a URL to open on your desktop, and you
paste the code it shows back. The token then lives in the hut's home
(`~/.claude/`), where anything in the hut can read it, though it can
send it only to the hosts the policy allows.

A hut made `--network-policy none` needs no policy for this: its
network is open and nothing is recorded, so the login reaches what it
needs, and so does everything else in the hut.

## With an API key instead

```
moathut credential add anthropic --host api.anthropic.com \
    --env ANTHROPIC_API_KEY
```

and the brokered entry above with `"credential": "anthropic"`. On first
start Claude Code asks whether to use the key it finds; say yes.

## Not covered

- Claude Code's own sandbox. Under `strict`, bubblewrap cannot make its
  namespaces, and Claude Code reports the sandbox unavailable.
