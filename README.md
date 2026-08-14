# agentbin

Share a coding agent's output through a unique URL, collect reviewer feedback,
then paste the link back into the agent session. Pastes expire after **one
hour** and are permanently deleted.

The production service runs on Cloudflare Workers. Each paste has its own
SQLite-backed Durable Object, which provides strongly consistent feedback
writes and schedules the paste's deletion with a Durable Object alarm.

Pastes are **encrypted at rest and unreadable by the operator**: the paste
link contains a 32-character token whose first half names the storage object
and whose SHA-256 digest is the AES-256-GCM key for the paste body. The
server never stores the token and redacts it from every log line, so anyone
without the link — including the operator — sees only ciphertext plus the
timestamps needed for expiry.

https://agentbin.sh runs the code in this repository. Verify any claim on
this page against `src/`, or reproduce the deployed bundle locally with
`npm run check`.

## Development

Requirements: Node.js 20+ and npm.

```sh
npm install
npm test
npm run dev
```

`npm test` runs unit tests and a full local Wrangler integration suite. The
integration suite covers form and JSON creation, rendering, raw output,
concurrent feedback, agent-readable feedback, owner deletion, hard expiry,
and validation failures.

## Deploy

Authenticate Wrangler and deploy the Worker plus its Durable Object namespace:

```sh
wrangler login
npm run deploy
```

If Cloudflare OAuth is unavailable, create an API token from Cloudflare's
**Edit Cloudflare Workers** template and put it in the git-ignored `.env` file:

```sh
cp .env.example .env
# edit .env locally; never paste or commit the token
npx wrangler whoami
npm run deploy
```

This configuration serves on the custom-domain route only (`workers_dev` and
`preview_urls` are disabled). To self-host, add your own domain to the
Cloudflare account, make its Cloudflare nameservers authoritative at the
registrar, and point the route in `wrangler.jsonc` at it — for example:

```json
"routes": [
  {
    "pattern": "agentbin.sh",
    "custom_domain": true
  }
]
```

Cloudflare creates the DNS record and TLS certificate for a Worker Custom
Domain. Domain registration can remain at the existing registrar.

## Install the agent skill

```sh
curl -fsSL https://agentbin.sh/install | sh
```

The installer detects Claude Code, Codex, and Pi directories and installs
`skill/agentbin/SKILL.md` for each available agent. Set `AGENTBIN_URL` to use a
development or alternate deployment.

## Flow

1. After an agent response, say `/agentbin` or "share this".
2. The agent redacts credential-shaped content and posts its response with
   useful session metadata.
3. Send the returned URL to a reviewer.
4. The reviewer submits feedback below the paste.
5. Paste the URL back into the agent session to review each feedback item.

An agent creates a paste with form data:

```sh
curl -s https://agentbin.sh/api/pastes \
  -d title="auth refactor" -d task="uuid pks" -d repo="acme/backend" \
  -d sender="sam" -d agent="codex" \
  --data-urlencode content@response.txt
```

The response contains the public-by-link URL and a one-time owner secret:

```json
{"id":"…","url":"https://agentbin.sh/…","secret":"…"}
```

The owner can delete a paste before expiry:

```sh
curl -X DELETE https://agentbin.sh/PASTE_ID \
  -H "Authorization: Bearer OWNER_SECRET"
```

## Routes

| Route | Purpose |
|---|---|
| `GET /` | Manual paste form |
| `POST /` | Create from the manual form |
| `GET /skill` | Agent skill source |
| `GET /install` | Shell installer |
| `POST /api/pastes` | Create from form or JSON data |
| `GET /{token}` | View a paste and its feedback form |
| `POST /{token}/feedback` | Submit feedback |
| `GET /{token}/feedback.md` | Agent-readable feedback |
| `GET /{token}/raw` | Raw paste content |
| `DELETE /{token}` | Owner deletion |

Paste tokens are 32-character, uniformly generated base58 strings (~188
bits): 16 characters route to the paste, all 32 derive its encryption key.
Owner secrets are separate 32-character tokens and only their SHA-256 hashes
are stored. Owner deletion accepts the secret in the `Authorization` header
only, so secrets never appear in URLs or request logs. Feedback is capped at
10,000 UTF-8 bytes per item and 100 items per paste; request bodies at 1 MiB.
Paste creation and feedback are rate-limited per IP through Cloudflare's
rate-limiting bindings (see `wrangler.jsonc`).

## Privacy and data

- A paste stores only what the creator submits (title, task, repo, sender,
  agent, content) plus reviewer feedback. There are no accounts.
- All of it is stored AES-256-GCM encrypted. The key is derived from the
  link token, which the server never persists and never logs, so the
  operator cannot read paste contents — only creation and expiry times.
- Everything is deleted at most one hour after creation — a Durable Object
  alarm hard-deletes the storage, and expired pastes are also deleted on
  first access. Owners can delete earlier with the one-time secret.
- The application logs method, redacted path, status, and duration only —
  no IP addresses, user agents, query strings, or paste tokens. Cloudflare
  invocation logs (which would include full URLs) are disabled.
- Rate limiting uses the client IP as an in-memory bucketing key inside
  Cloudflare's rate-limiting primitive; it is never written to logs.
- Pastes are public to anyone who has the link. Links are unguessable but
  not access-controlled: do not paste secrets, credentials, or personal data.
- Every page ships a hash-based `Content-Security-Policy` with no
  `unsafe-inline` that also blocks remote images, so reviewers cannot be
  tracked through markdown content. Markdown is rendered client-side and
  sanitized with DOMPurify; the two CDN scripts are pinned with
  subresource-integrity hashes.
- The service runs on Cloudflare Workers, so requests transit Cloudflare's
  network subject to Cloudflare's own policies.

Report abuse or problems via
[GitHub issues](https://github.com/yrstm/agentbin/issues).

## License

[Apache-2.0](LICENSE)
