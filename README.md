# @deadrop/cli

Terminal-native client for [Deadrop](https://deadrop.dev) — zero-ceremony one-time secret sharing. Secrets are encrypted client-side (AES-256-GCM via [`@deadrop/crypto`](https://www.npmjs.com/package/@deadrop/crypto)); the server only ever sees ciphertext and burns it on first read.

## Install

```bash
npm install -g @deadrop/cli     # Node 20+
deadrop --help
```

Or run it without installing:

```bash
npx @deadrop/cli send "my-api-key-12345"
```

## Usage

### Send

```bash
deadrop send "my-api-key-12345"            # inline
cat .env | deadrop send                     # stdin pipe
deadrop send "secret" --ttl 5m              # custom TTL: 5m, 1h, 24h, 7d (max 7d)
deadrop send "secret" -p hunter2            # password-protected (PBKDF2, 600k iters)
deadrop send "secret" -p                    # prompt for password (no echo, confirmed)
deadrop send "secret" -p hunter2 --hint "usual dev password"
deadrop send "secret" --json                # machine-readable
deadrop send "secret" --qr                  # QR code after the link
deadrop send "secret" -s https://secrets.mycompany.com
```

Output is a one-time link: `https://deadrop.dev/s/{id}#{key}` (password-protected links use `#p.{key}`). The `#fragment` holds the decryption key and is never sent to any server.

### Receive

```bash
deadrop receive "https://deadrop.dev/s/abc...#kE9x..."
deadrop receive "https://deadrop.dev/s/abc...#p.kE9x..."          # prompts for password
deadrop receive "https://deadrop.dev/s/abc...#p.kE9x..." -p pw    # password via flag
deadrop receive "https://..." --quiet > secret.env                 # exact bytes to file
```

Receiving **burns** the secret — it is deleted server-side in the same atomic step. A wrong password does NOT burn it (the server rejects the key proof without deleting).

### Request a secret (reverse flow)

```bash
deadrop request "the staging DB password"   # ask someone for a secret
deadrop request                              # no prompt text
deadrop request "api key" --ttl 7d           # default TTL for requests: 24h
deadrop request --json                       # machine-readable
deadrop request --qr                         # QR of the request link
```

Prints two links with different jobs:

- **Request link** (`/r/{id}`) — send it to the person with the secret. Carries no key material.
- **Claim link** (`/r/{id}/claim#…`) — keep it. The decryption key lives only in its fragment; lose it and the response can never be read, by anyone.

The optional prompt (max 140 chars) is **semi-public** — anyone with the request link can read it, so never put secrets in it.

```bash
deadrop fulfill "https://deadrop.dev/r/abc..." "hunter2"   # answer a request
cat secret.txt | deadrop fulfill "https://deadrop.dev/r/abc..."
```

Fulfill encrypts locally to the requester's public key (ECDH P-256 + HKDF-SHA256 + AES-256-GCM) and shows a **key fingerprint** — ask the requester out-of-band to confirm theirs matches. Each request takes exactly one response; a second fulfill is rejected without touching the first.

```bash
deadrop claim "https://deadrop.dev/r/abc.../claim#MIGH..."
deadrop claim "$CLAIM_URL" --quiet > secret.txt
```

Claiming **burns** the response in the same atomic step. If nobody has answered yet, claim reports pending and burns nothing — check again any time before the request expires.

### Revoke

```bash
deadrop revoke "https://deadrop.dev/s/abc...#kE9x..."
```

Revoke requires the **full URL**: the server demands the same key-hash proof as retrieval (`DELETE /api/secrets/{id}?k=...`), which can only be computed from the URL key — and the password, for password-protected links (you'll be prompted).

### QR

```bash
deadrop qr                                  # last sent link
deadrop qr "https://deadrop.dev/s/abc...#kE9x..."
```

Note: `deadrop qr` with no argument uses the last sent URL, which is stored at `<config dir>/last-url` for this purpose. That file contains the decryption key — `deadrop config reset` removes it.

### Config

```bash
deadrop config set server https://secrets.mycompany.com
deadrop config set default-ttl 24h
deadrop config set output json              # human | json | quiet
deadrop config get server
deadrop config list
deadrop config reset
```

Config file: `$XDG_CONFIG_HOME/deadrop/config.json`, falling back to `~/.config/deadrop/config.json` (POSIX) or `~/.deadrop/config.json` (Windows).

## Precedence

Flags > environment > config file > defaults.

| Setting | Flag | Env var | Config key | Default |
|---------|------|---------|------------|---------|
| Server | `-s, --server` | `DEADROP_SERVER` | `server` | `https://deadrop.dev` |
| TTL | `-t, --ttl` | `DEADROP_TTL` | `default-ttl` | `1h` (`24h` for `request`) |
| Output | `-j` / `-q` | `DEADROP_OUTPUT` | `output` | `human` |

## Pipes & scripting

- `!stdin.isTTY` → the secret is read from stdin (`cat .env | deadrop send`)
- `!stdout.isTTY` → human decoration is suppressed automatically (quiet behavior)
- `--quiet` receive writes the secret content byte-exact (no added newline) — safe for `> file`
- `--json` always prints exactly one JSON object
- Password prompts go to **stderr**; secret material is never written to stderr
- Exit codes: `0` success · `1` user error (bad input, wrong password, secret gone) · `2` network/server error (unreachable, 5xx, rate-limited)

```bash
URL=$(deadrop send "$DB_PASSWORD" --ttl 5m --quiet)
deadrop receive "$URL" --quiet > /run/secrets/db_password
```

## Spec compliance

Implements [SPEC.md v2.1](https://github.com/deadrop-dev/crypto/blob/master/SPEC.md), including the §9 request flow:

- Client-generated 32-char base64url ids (24 random bytes); one regenerate-and-retry on a 409 collision
- `POST /api/secrets {id, encrypted, iv, keyHash, expiresMinutes, hint?}`; retrieve/revoke key proof via `?k={keyHash}`
- Password keys derived with PBKDF2-SHA256 (600k iterations, salt = raw URL key bytes); the wire `keyHash` is of the **derived** key
- Passwords NFC-normalized on encrypt; receive tries NFC first and falls back to the raw password for legacy (pre-2.0) secrets — safe because a wrong key proof never burns
- Unknown URL fragment KDF selectors (e.g. `a2.`) are refused, never guessed
- Request flow (§9): ephemeral ECDH P-256 keypair per request; responder wraps a fresh AES-256-GCM data key via ECDH + HKDF-SHA256 (`deadrop/request-wrap/v1`); claim proof is a hash of the fragment key; claim status precedence `404 → 403 → 202 → 200` with burns only on `200`; key fingerprints shown on both fulfill and claim (§9.4)
- All published `@deadrop/crypto` test vectors — including the request-flow vectors — pass through the CLI crypto plumbing

## Development

```bash
npm test          # unit + wire tests (in-process mock server, no network)
npm run test:live # 3 live requests against deadrop.dev (rate-limit friendly)
npm run build     # bundle to dist/index.js
npm run typecheck
```

## License

MIT
