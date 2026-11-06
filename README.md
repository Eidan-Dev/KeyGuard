# keyguard

**Stop committing API keys.** `keyguard` blocks a Git commit when it contains a secret: AWS keys, Stripe live keys, GitHub tokens, private keys, hardcoded passwords.

```bash
pip install keyguard
keyguard install-hook
```

<!-- Put a 10-second recording here: a commit attempt, then the block message. -->

```
$ git commit -m "add config"
✗ keyguard: 4 secret(s) found in staged changes

  config.py:7  AWS access key ID
    AWS_ACCESS_KEY_ID = "AKIA********…"
  config.py:10  Stripe live secret key
    STRIPE_SECRET = "sk_l********…"
  config.py:13  Hardcoded password or API key
    DB_PASSWORD = "hunt********…"

Remove the secret, rotate it (it may already be exposed), then commit again.

Commit blocked by keyguard.
```

Once a key is pushed to a public repository, assume it is compromised. Automated bots scan public GitHub activity for credentials, and the damage can start within minutes, long before you notice. `keyguard` stops the key before it leaves your machine.

## What it catches

- AWS access key IDs (`AKIA…`, `ASIA…`)
- GitHub tokens (`ghp_…`, `gho_…`, and other prefixes)
- Slack tokens (`xoxb-…`, `xoxp-…`)
- Stripe live secret keys (`sk_live_…`)
- Private key blocks (`-----BEGIN … PRIVATE KEY-----`)
- Hardcoded values assigned to `password`, `secret`, `api_key`, or `access_token`

Only the lines you are about to commit are scanned. Secrets already in your history are not flagged again, so the tool is quiet on repositories that are already cleaned up.

## Install the hook

Run this once inside any Git repository:

```bash
keyguard install-hook
```

From now on, `git commit` runs `keyguard staged` and refuses the commit if it finds a secret. Use `--force` to replace an existing pre-commit hook.

## Other commands

```bash
keyguard scan                 # scan every file in the project
keyguard scan src config/     # scan specific paths
keyguard staged               # scan what is about to be committed
```

## False positives

Add the marker on the line that is safe:

```python
TEST_TOKEN = "ghp_0000000000000000000000000000000000AA"  # keyguard: ignore
```

Keep the marker rare. A tool that cries wolf on every commit gets disabled within a week.

## Important

keyguard-x-video
.mp4
MP4


`keyguard` catches common patterns, not every possible secret. It does not replace a secret manager, and it cannot undo a leak. If a key has been pushed, revoke it first, then clean up the history.

## Try it in 30 seconds

```bash
git clone https://github.com/your-handle/keyguard
cd keyguard
pip install -e ".[dev]"
keyguard scan examples/config.py
```

`examples/config.py` contains fake secrets. Note that the AWS key used is the example key that AWS publishes in its own documentation.

## How it works

1. Reads the staged diff with `git diff --cached`.
2. Keeps only the lines added by the commit.
3. Matches them against a small set of specific patterns.
4. Masks the secret in the output, so the report itself never leaks it.
5. Exits with an error code, which makes `git commit` fail.

The patterns live in `keyguard/patterns.py`. Adding one takes a stable id, a title, and a regex.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Roadmap

- [ ] Entropy check for unknown random strings
- [ ] Support for more providers (Google, Azure, OpenAI, Anthropic)
- [ ] `keyguard history` to scan past commits and report exposures
- [ ] GitHub Action for pull requests

## Contributing

Pattern contributions are the most useful. Include at least one test with a realistic fake value and one test that normal code is not flagged.

## License

MIT
