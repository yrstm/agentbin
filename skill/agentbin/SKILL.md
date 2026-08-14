---
name: agentbin
description: Share my previous response for review via a unique agentbin URL, and fetch reviewer feedback when given an agentbin link. Use when the user says "/agentbin", "share this", "agentbin this", or pastes an agentbin URL.
---

# agentbin

Server: `$AGENTBIN_URL` if set, otherwise `https://agentbin.sh`.
Pastes are public-by-link and expire after 1 hour, then are permanently deleted.

## Sharing (user asks to share your response)

1. Take your **immediately previous response** verbatim as the content.
2. **Redact secrets before posting.** Scan the content for anything
   credential-shaped — API keys (`sk-…`, `AKIA…`, `ghp_…`, `xox…`), bearer
   tokens, private key blocks, passwords, connection strings with credentials,
   `.env` values — and replace each with `[REDACTED]`. If you redacted
   anything, tell the user what and why.
3. Determine metadata yourself — do not ask unless truly unknown:
   - `title`: short summary of what is being worked on
   - `task`: the task of this session in one line
   - `repo`: current repo/project name (e.g. from `git remote get-url origin` or the directory name)
   - `sender`: the user's name (from git config `user.name` if unknown)
   - `agent`: your own name (e.g. "claude code", "codex", "pi")
4. Write the content to `/tmp/agentbin-content.txt` (avoids shell quoting
   issues), then create the paste:

```sh
curl -s "${AGENTBIN_URL:-https://agentbin.sh}/api/pastes" \
  -d title="..." -d task="..." -d repo="..." -d sender="..." -d agent="..." \
  --data-urlencode content@/tmp/agentbin-content.txt
```

5. The response is `{"id":"...","url":"...","secret":"..."}`.
   - Show the user the **url** and say: "Share this with your reviewer.
     It expires in 1 hour. Paste the link back to me when feedback is in."
   - Keep the **secret** available in this session (do not display it unless
     asked) — it is needed to delete the paste early.

## Deleting (user asks to remove a shared paste)

```sh
curl -s -X DELETE "<paste url>" -H "Authorization: Bearer <secret>"
```

Use the secret from the create step. Confirm deletion to the user.

## Fetching feedback (user pastes an agentbin link back)

1. `curl -s <url>/feedback.md` (append `/feedback.md` to the paste URL).
2. Present each feedback item, numbered, and ask the user which to
   **approve, edit, or skip**.
3. Only act on approved items, incorporating any edits the user makes.
4. If the fetch 404s, the paste expired — offer to re-share.
