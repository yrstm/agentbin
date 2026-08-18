export const TTL_MS = 60 * 60 * 1000;
export const MAX_FEEDBACK_BYTES = 10_000;
export const MAX_FEEDBACK_COUNT = 100;
// Keep well under the 2 MB SQLite-backed Durable Object per-value limit so a
// paste plus its feedback always fits in one stored record.
export const MAX_BODY_BYTES = 1024 * 1024;
// A paste link carries a 32-character token. The first half names the storage
// object; the SHA-256 of the full token is the AES-256-GCM key for the paste
// body. The server never stores the token, so stored pastes are ciphertext
// the operator cannot read without a link.
export const ID_LENGTH = 16;
export const TOKEN_LENGTH = 32;
export const SECRET_LENGTH = 32;
export const ID_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const encoder = new TextEncoder();

export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export function randomToken(length) {
  let output = "";
  const limit = Math.floor(256 / ID_ALPHABET.length) * ID_ALPHABET.length;

  while (output.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(64));
    for (const byte of bytes) {
      if (byte >= limit) continue;
      output += ID_ALPHABET[byte % ID_ALPHABET.length];
      if (output.length === length) break;
    }
  }

  return output;
}

function hexFromBytes(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesFromHex(hex) {
  return Uint8Array.from(hex.match(/../g).map((pair) => parseInt(pair, 16)));
}

export async function hashSecret(secret) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(secret));
  return hexFromBytes(new Uint8Array(digest));
}

export async function keyHexFromToken(token) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(`agentbin-key:${token}`));
  return hexFromBytes(new Uint8Array(digest));
}

async function importAesKey(keyHex) {
  return crypto.subtle.importKey("raw", bytesFromHex(keyHex), "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

export async function sealJson(value, keyHex) {
  const key = await importAesKey(keyHex);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(JSON.stringify(value))),
  );
  return { iv, data };
}

export async function openJson(box, keyHex) {
  try {
    const key = await importAesKey(keyHex);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: box.iv }, key, box.data);
    return JSON.parse(new TextDecoder().decode(plain));
  } catch {
    return null;
  }
}

export function utf8Length(value) {
  return encoder.encode(value).byteLength;
}

export function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => {
    switch (character) {
      case "&": return "&amp;";
      case "<": return "&lt;";
      case ">": return "&gt;";
      case "\"": return "&quot;";
      default: return "&#39;";
    }
  });
}

export async function readLimitedText(request) {
  const declaredLength = Number(request.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
    throw new HttpError(413, "request body too large");
  }

  const body = await request.arrayBuffer();
  if (body.byteLength > MAX_BODY_BYTES) {
    throw new HttpError(413, "request body too large");
  }
  return new TextDecoder().decode(body);
}

export function pasteFromValues(values, now = Date.now(), ttlMs = TTL_MS) {
  const get = (key) => values.get(key) ?? "";
  return {
    title: get("title").trim(),
    task: get("task").trim(),
    repo: get("repo").trim(),
    sender: get("sender").trim(),
    agent: get("agent").trim(),
    content: get("content"),
    feedback: [],
    createdAt: now,
    expiresAt: now + ttlMs,
  };
}

export function pasteFromJson(input, now = Date.now(), ttlMs = TTL_MS) {
  const string = (key) => typeof input?.[key] === "string" ? input[key] : "";
  return {
    title: string("title").trim(),
    task: string("task").trim(),
    repo: string("repo").trim(),
    sender: string("sender").trim(),
    agent: string("agent").trim(),
    content: string("content"),
    feedback: [],
    createdAt: now,
    expiresAt: now + ttlMs,
  };
}

export function isValidToken(value, length = TOKEN_LENGTH) {
  if (typeof value !== "string" || value.length !== length) return false;
  for (const character of value) {
    if (!ID_ALPHABET.includes(character)) return false;
  }
  return true;
}

export function relativeTime(timestamp, now = Date.now()) {
  const seconds = Math.max(0, Math.floor((now - timestamp) / 1000));
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

export function formatUtcTime(timestamp) {
  const date = new Date(timestamp);
  const hours = String(date.getUTCHours()).padStart(2, "0");
  const minutes = String(date.getUTCMinutes()).padStart(2, "0");
  return `${hours}:${minutes} UTC`;
}

export function feedbackMarkdown(paste) {
  let output = `## Feedback on ${JSON.stringify(paste.title)} (${paste.id})\n\n`;
  if (paste.feedback.length === 0) return `${output}No feedback yet.\n`;

  paste.feedback.forEach((feedback, index) => {
    output += `### ${index + 1}. ${feedback.author} (${formatUtcTime(feedback.createdAt)})\n`;
    output += `${feedback.body}\n\n`;
  });
  return output;
}

const pageHead = (noindex) => `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Share coding-agent output, collect reviewer feedback, and bring it back into the agent session.">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
${noindex ? '<meta name="robots" content="noindex">\n' : ""}<title>agentbin.sh — share agent output and collect feedback</title>
<style>${STYLE}</style>
</head><body>
<div class="sky" aria-hidden="true"></div>
<header class="site-header">
  <a class="brand" href="/">agentbin<span>.sh</span></a>
  <nav class="site-nav" aria-label="Primary">
    <a href="/#workflow">how it works</a>
    <a href="/#manual">manual</a>
    <a href="/skill">skill</a>
  </nav>
</header>
<main class="page wrap">`;

const STYLE = `
  :root {
    --paper: #f1eee5;
    --paper-raised: #f8f5ec;
    --ink: #1b1915;
    --ink-soft: #696459;
    --ink-faint: #aaa497;
    --moss: #2f6b46;
    --moss-dark: #245438;
    --rule: rgba(27, 25, 21, .22);
    --shadow: rgba(27, 25, 21, .12);
    --mono: "IBM Plex Mono", "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  }
  * { box-sizing: border-box; }
  html { scroll-behavior: smooth; }
  body {
    margin: 0;
    min-height: 100vh;
    background: var(--paper);
    color: var(--ink);
    font: 14px/1.7 var(--mono);
    -webkit-font-smoothing: antialiased;
  }
  .sky {
    position: fixed;
    inset: 0;
    z-index: 0;
    pointer-events: none;
    background-image: radial-gradient(var(--ink-faint) 1px, transparent 1.25px);
    background-size: 34px 34px;
    mask-image: linear-gradient(to bottom, rgba(0,0,0,.68), rgba(0,0,0,.18) 42%, transparent 72%);
    -webkit-mask-image: linear-gradient(to bottom, rgba(0,0,0,.68), rgba(0,0,0,.18) 42%, transparent 72%);
  }
  ::selection { background: var(--ink); color: var(--paper); }
  a { color: var(--ink); text-decoration-thickness: 1px; text-underline-offset: 3px; }
  a:hover { color: var(--moss); }
  a:focus-visible, button:focus-visible, input:focus-visible, textarea:focus-visible {
    outline: 2px solid var(--moss);
    outline-offset: 3px;
  }
  .site-header, .page, .site-footer { position: relative; z-index: 1; }
  .site-header {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 24px;
    max-width: 1180px;
    margin: 0 auto;
    padding: 22px 28px;
  }
  .brand { font-weight: 700; letter-spacing: .02em; text-decoration: none; }
  .brand span { color: var(--moss); }
  .site-nav { display: flex; gap: 24px; }
  .site-nav a { color: var(--ink-soft); text-decoration: none; }
  .site-nav a:hover { color: var(--moss); }
  .wrap { width: min(100% - 48px, 920px); margin-inline: auto; }
  .page { padding: 44px 0 72px; }
  h1, h2, h3, p { margin-top: 0; }
  h2 {
    margin: 52px 0 22px;
    font-size: 13px;
    line-height: 1.4;
    font-weight: 500;
    letter-spacing: .11em;
    text-transform: lowercase;
    color: var(--ink-soft);
  }
  h2::before { content: "## "; color: var(--ink-faint); }
  .page > h2:first-child {
    margin: 12px 0 24px;
    color: var(--ink);
    font-size: clamp(22px, 4vw, 34px);
    line-height: 1.3;
    font-weight: 700;
    letter-spacing: -.035em;
    text-transform: none;
  }
  .page > h2:first-child::before { content: none; }
  h3 { margin-bottom: 8px; font-size: 14px; }
  code { font: inherit; background: rgba(255, 255, 255, .38); padding: .08em .28em; }
  pre {
    margin: 14px 0;
    padding: 16px 18px;
    overflow-x: auto;
    border: 1px solid var(--rule);
    background: rgba(248, 245, 236, .72);
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    font: inherit;
  }
  hr { margin: 34px 0; border: 0; border-top: 1px dashed var(--rule); }
  button, input, textarea { font: inherit; }
  button {
    border: 1px solid var(--ink);
    border-radius: 0;
    padding: 10px 16px;
    background: var(--ink);
    color: var(--paper);
    cursor: pointer;
  }
  button:hover { background: var(--moss-dark); border-color: var(--moss-dark); }
  input[type=text], textarea {
    display: block;
    width: 100%;
    border: 1px solid var(--rule);
    border-radius: 0;
    padding: 11px 12px;
    background: rgba(248, 245, 236, .78);
    color: var(--ink);
  }
  textarea { min-height: 180px; resize: vertical; }
  label { display: block; margin: 16px 0 5px; color: var(--ink-soft); font-size: 13px; }
  table.meta { width: 100%; border-collapse: collapse; }
  table.meta td { padding: 6px 16px 6px 0; vertical-align: top; border-bottom: 1px dotted var(--rule); }
  table.meta td:first-child { width: 92px; color: var(--ink-soft); }
  .dim { color: var(--ink-soft); }
  .fb { margin: 14px 0; padding: 12px 16px; border-left: 3px solid var(--moss); background: rgba(248, 245, 236, .56); white-space: pre-wrap; }
  .box, .warn { margin-top: 24px; padding: 18px; border: 1px solid var(--ink); background: rgba(248, 245, 236, .66); box-shadow: 4px 4px 0 var(--shadow); }
  .warn { border-left: 4px solid var(--moss); }
  .box button, form > button { margin-top: 16px; }
  .md { padding: 4px 18px; border: 1px solid var(--rule); background: rgba(248, 245, 236, .62); }
  .md pre { white-space: pre; }
  .md code { background: rgba(27, 25, 21, .06); }
  .md pre code { background: none; padding: 0; }
  .md h1, .md h2, .md h3 { margin: 1.2em 0 .55em; font-size: 14px; border: 0; letter-spacing: 0; text-transform: none; color: var(--ink); }
  .md h1::before, .md h2::before, .md h3::before { content: none; }
  .md table { border-collapse: collapse; }
  .md td, .md th { border: 1px solid var(--rule); padding: 5px 8px; }

  .hero { position: relative; padding: clamp(54px, 10vh, 104px) 0 28px; text-align: center; }
  .sun { position: absolute; top: 10px; right: 0; margin: 0; padding: 0; overflow: visible; border: 0; background: transparent; color: var(--ink-soft); line-height: 1.2; white-space: pre; user-select: none; }
  .eyebrow { margin-bottom: 12px; color: var(--moss); font-size: 12px; letter-spacing: .14em; text-transform: uppercase; }
  .wordmark { margin: 0; font-size: clamp(46px, 10vw, 88px); line-height: .95; letter-spacing: -.075em; font-weight: 700; }
  .wordmark span { color: var(--moss); }
  .lead { max-width: 710px; margin: 26px auto 0; font-size: clamp(16px, 2.2vw, 20px); line-height: 1.55; }
  .subline { margin-top: 8px; color: var(--ink-soft); }
  .terminal { max-width: 700px; margin: 40px auto 0; border: 1px solid var(--ink); background: rgba(248, 245, 236, .78); box-shadow: 6px 6px 0 var(--shadow); text-align: left; }
  .terminal-bar { display: flex; justify-content: space-between; align-items: center; min-height: 40px; padding: 7px 12px 7px 15px; border-bottom: 1px solid var(--rule); color: var(--ink-soft); font-size: 12px; }
  .terminal-bar button { margin: 0; border: 0; padding: 3px 5px; background: transparent; color: var(--ink-soft); font-size: 12px; }
  .terminal-bar button:hover { color: var(--moss); }
  .terminal pre { margin: 0; min-height: 132px; border: 0; background: transparent; line-height: 1.9; white-space: pre; overflow-wrap: normal; }
  .prompt { color: var(--moss); font-weight: 700; }
  .comment { color: var(--ink-faint); }
  .copy-status { min-height: 1.7em; margin: 12px 0 0; color: var(--moss); font-size: 12px; }
  .sections { padding-top: 24px; }
  .steps, .facts { display: grid; gap: 1px; border: 1px solid var(--rule); background: var(--rule); }
  .steps { grid-template-columns: repeat(3, 1fr); }
  .facts { grid-template-columns: repeat(2, 1fr); }
  .steps article, .facts article { min-width: 0; padding: 20px; background: var(--paper-raised); }
  .step-number { display: block; margin-bottom: 24px; color: var(--moss); font-size: 12px; }
  .steps p, .facts p { margin-bottom: 0; color: var(--ink-soft); font-size: 13px; }
  .api-example { border-left: 2px solid var(--moss); }
  .manual { margin-top: 58px; padding-top: 1px; border-top: 1px dashed var(--rule); }
  .manual-intro { max-width: 650px; color: var(--ink-soft); }
  .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0 22px; }
  .form-wide { grid-column: 1 / -1; }
  .policy { margin-top: 18px; color: var(--ink-soft); font-size: 12px; }
  .site-footer { border-top: 1px solid var(--rule); }
  .footer-row { display: flex; justify-content: space-between; gap: 18px; flex-wrap: wrap; max-width: 1180px; margin: 0 auto; padding: 20px 28px 28px; color: var(--ink-soft); font-size: 12px; }
  .footer-row a { color: var(--ink-soft); }
  @media (max-width: 700px) {
    .site-header { padding-inline: 20px; }
    .site-nav { gap: 14px; }
    .wrap { width: min(100% - 32px, 920px); }
    .page { padding-top: 24px; }
    .sun { display: none; }
    .steps, .facts, .form-grid { grid-template-columns: 1fr; }
    .form-wide { grid-column: auto; }
    .terminal pre { font-size: 12px; }
    table.meta, table.meta tbody, table.meta tr, table.meta td { display: block; }
    table.meta td:first-child { width: auto; padding-bottom: 0; border-bottom: 0; }
  }
  @media (max-width: 430px) {
    .site-nav a:first-child { display: none; }
    .wordmark { font-size: 42px; }
  }
  @media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; } }
`;

const HOME_SCRIPT = `
(function () {
  var button = document.getElementById('copy-install');
  var status = document.getElementById('copy-status');
  if (!button || !status) return;
  button.addEventListener('click', function () {
    navigator.clipboard.writeText('curl -fsSL https://agentbin.sh/install | sh').then(function () {
      button.textContent = 'copied';
      status.textContent = 'install command copied to clipboard';
      setTimeout(function () {
        button.textContent = 'copy install command';
        status.textContent = '';
      }, 1600);
    }).catch(function () {
      status.textContent = 'copy failed — select the command above';
    });
  });
})();
`;

const PASTE_SCRIPT = `
(function () {
  var pre = document.getElementById('content');
  if (!pre || !window.marked || !window.DOMPurify) return;
  var div = document.createElement('div');
  div.className = 'md';
  div.innerHTML = DOMPurify.sanitize(marked.parse(pre.textContent));
  pre.replaceWith(div);
})();
(function () {
  var el = document.getElementById('ttl');
  if (!el) return;
  var exp = parseInt(el.dataset.exp, 10) * 1000;
  function tick() {
    var s = Math.floor((exp - Date.now()) / 1000);
    if (s <= 0) { el.textContent = 'expired'; return; }
    el.textContent = 'in ' + Math.floor(s / 60) + 'm ' + (s % 60) + 's';
    setTimeout(tick, 1000);
  }
  tick();
})();
`;

export const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="12" fill="#1b1915"/><text x="32" y="45" font-family="Menlo, Consolas, monospace" font-size="34" font-weight="700" text-anchor="middle" fill="#f1eee5">a<tspan fill="#2f6b46">b</tspan></text></svg>
`;

async function cspHash(source) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(source));
  return `'sha256-${btoa(String.fromCharCode(...new Uint8Array(digest)))}'`;
}

// No 'unsafe-inline': the inline script and style blocks are allowed by hash
// only, and the two CDN scripts are additionally pinned with SRI attributes.
export async function buildCsp() {
  const [home, paste, style] = await Promise.all([HOME_SCRIPT, PASTE_SCRIPT, STYLE].map(cspHash));
  return [
    "default-src 'none'",
    `script-src ${home} ${paste} https://cdn.jsdelivr.net`,
    `style-src ${style}`,
    "img-src 'self'",
    "form-action 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
}

const FOOT = `</main>
<footer class="site-footer">
  <div class="footer-row">
    <span>agentbin.sh · temporary by design</span>
    <span><a href="/skill">skill</a> · <a href="/install">installer</a> · <a href="https://github.com/yrstm/agentbin/issues">report abuse</a> · one-hour lifetime</span>
  </div>
</footer>
</body></html>`;

export function renderHome() {
  return `${pageHead(false)}
<section class="hero">
  <pre class="sun" aria-hidden="true">. \\ | / .
-- ( ) --
' / | \\ &#96;</pre>
  <p class="eyebrow">a temporary review loop for agent work</p>
  <h1 class="wordmark">agentbin<span>.sh</span></h1>
  <p class="lead">Share an agent response. Let a person review it. Bring the feedback back into the same session.</p>
  <p class="subline">Public by link · no account · permanently deleted after one hour.</p>

  <div class="terminal" aria-label="Agentbin setup">
    <div class="terminal-bar">
      <span>~/setup</span>
      <button id="copy-install" type="button">copy install command</button>
    </div>
    <pre><span class="prompt">$</span> curl -fsSL https://agentbin.sh/install | sh

<span class="comment"># then, after any agent response:</span>
<span class="prompt">›</span> /agentbin
<span class="comment"># share the returned link with your reviewer</span></pre>
  </div>
  <p class="copy-status" id="copy-status" aria-live="polite"></p>
</section>

<div class="sections">
  <section id="workflow">
    <h2>how it works</h2>
    <div class="steps">
      <article>
        <span class="step-number">01 / install once</span>
        <h3>Add the skill</h3>
        <p>The installer adds agentbin to supported coding agents already present on your machine.</p>
      </article>
      <article>
        <span class="step-number">02 / share</span>
        <h3>Type /agentbin</h3>
        <p>Your agent posts its previous response and gives you a public-by-link URL for review.</p>
      </article>
      <article>
        <span class="step-number">03 / close the loop</span>
        <h3>Bring feedback back</h3>
        <p>The reviewer submits notes on the page. Paste the link back into your agent session to fetch them.</p>
      </article>
    </div>
  </section>

  <section>
    <h2>the endpoint</h2>
    <p class="dim">The skill uses the same plain HTTP endpoint available to scripts. Only <code>content</code> is required.</p>
    <pre class="api-example"><span class="prompt">$</span> curl -s https://agentbin.sh/api/pastes \\
  --data-urlencode content@response.txt

<span class="comment"># returns JSON with the paste URL and a one-time owner secret</span></pre>
  </section>

  <section>
    <h2>what stays simple</h2>
    <div class="facts">
      <article><h3>Public by link</h3><p>No account or reviewer login. Anyone with the URL can view the paste.</p></article>
      <article><h3>One-hour lifetime</h3><p>Each paste and its feedback are permanently removed when the hour ends.</p></article>
      <article><h3>Agent-readable feedback</h3><p>Every paste exposes feedback as plain text at <code>/feedback.md</code>.</p></article>
      <article><h3>Early deletion</h3><p>The creation response includes an owner secret that can delete the paste before expiry.</p></article>
    </div>
  </section>
</div>

<section class="manual" id="manual">
  <h2>manual fallback</h2>
  <p class="manual-intro">No agent handy? Paste the output here. The resulting page uses the same one-hour lifetime and reviewer feedback flow.</p>
  <form method="post" action="/">
    <div class="form-grid">
      <div>
        <label for="title">title</label>
        <input id="title" type="text" name="title" placeholder="auth refactor plan" required>
      </div>
      <div>
        <label for="task">task</label>
        <input id="task" type="text" name="task" placeholder="migrate session IDs">
      </div>
      <div>
        <label for="repo">repo / project</label>
        <input id="repo" type="text" name="repo" placeholder="acme/backend">
      </div>
      <div>
        <label for="sender">your name</label>
        <input id="sender" type="text" name="sender" placeholder="name">
      </div>
      <div class="form-wide">
        <label for="agent">coding agent</label>
        <input id="agent" type="text" name="agent" placeholder="claude code / codex / pi">
      </div>
      <div class="form-wide">
        <label for="content">agent output</label>
        <textarea id="content" name="content" placeholder="Paste the response you want reviewed…" required></textarea>
      </div>
    </div>
    <button type="submit">create one-hour link</button>
  </form>
  <p class="policy">Pastes are public to anyone with the link. Do not post secrets, credentials, or personal data.
  agentbin stores only the paste and its feedback — no accounts, no visitor analytics — and permanently deletes both within the hour.</p>
</section>

<script>${HOME_SCRIPT}</script>
${FOOT}`;
}

export function renderCreated(url, id, secret) {
  const safeUrl = escapeHtml(url);
  const safeId = escapeHtml(id);
  const safeSecret = escapeHtml(secret);
  return `${pageHead(true)}
<h2>link created</h2>
<p>share this with your reviewer:</p>
<pre><a href="${safeUrl}">${safeUrl}</a></pre>
<div class="warn"><strong>owner secret</strong> (shown once — save it if you may need to delete early):
<pre>${safeSecret}</pre>
delete with:
<pre>curl -X DELETE ${safeUrl} -H "Authorization: Bearer ${safeSecret}"</pre></div>
<p><a href="/${safeId}">&raquo; view the paste</a></p>
${FOOT}`;
}

export function renderGone() {
  return `${pageHead(true)}
<h2>not found</h2>
<p>this paste doesn't exist, expired (1 hour ttl), or was deleted by its owner.
expired pastes are permanently removed.</p>
<p class="dim">ask the sender to share again.</p>
${FOOT}`;
}

export function renderExpiredFeedback(body) {
  return `${pageHead(true)}
<h2>this paste expired before your feedback was saved</h2>
<p>sorry — pastes are deleted after 1 hour. your feedback was <strong>not</strong> lost,
copy it below and ask the sender to share a fresh link:</p>
<pre>${escapeHtml(body)}</pre>
${FOOT}`;
}

function metaRow(label, value) {
  if (!value) return "";
  return `<tr><td>${label}</td><td>${escapeHtml(value)}</td></tr>`;
}

export function renderPaste(paste, now = Date.now()) {
  const id = escapeHtml(paste.id);
  const feedback = paste.feedback.length === 0
    ? '<p class="dim">no feedback yet.</p>'
    : paste.feedback.map((item) => `
  <div class="fb"><strong>${escapeHtml(item.author)}</strong> <span class="dim">${relativeTime(item.createdAt, now)}</span>
${escapeHtml(item.body)}</div>`).join("");

  return `${pageHead(true)}
<h2>${paste.title ? escapeHtml(paste.title) : "(untitled)"}</h2>
<table class="meta">
  ${metaRow("task", paste.task)}
  ${metaRow("repo", paste.repo)}
  ${metaRow("from", paste.sender)}
  ${metaRow("agent", paste.agent)}
  <tr><td>expires</td><td><strong id="ttl" data-exp="${Math.floor(paste.expiresAt / 1000)}">soon</strong> <span class="dim">— then it is permanently deleted; submit feedback before then</span></td></tr>
  <tr><td>raw</td><td><a href="/${id}/raw">/${id}/raw</a> · feedback: <a href="/${id}/feedback.md">/${id}/feedback.md</a></td></tr>
</table>
<h2>agent output</h2>
<pre id="content">${escapeHtml(paste.content)}</pre>

<h2 id="feedback">feedback (${paste.feedback.length})</h2>
${feedback}

<div class="box">
  <strong>&raquo; reviewer: enter your feedback here</strong>
  <form method="post" action="/${id}/feedback">
    <label>your name (optional)</label>
    <input type="text" name="author" placeholder="anon">
    <label>feedback (max 10,000 chars)</label>
    <textarea name="body" maxlength="10000" placeholder="what should change, what's wrong, what's good…" required></textarea>
    <button type="submit">submit feedback</button>
  </form>
</div>
<hr>
<p class="dim"># sender: once feedback is in, paste this into your agent session:<br>
# "fetch feedback from ${id}/feedback.md and walk me through each item so I can approve, edit, or skip"</p>

<script src="https://cdn.jsdelivr.net/npm/marked@12.0.2/marked.min.js" integrity="sha384-/TQbtLCAerC3jgaim+N78RZSDYV7ryeoBCVqTuzRrFec2akfBkHS7ACQ3PQhvMVi" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/dompurify@3.1.5/dist/purify.min.js" integrity="sha384-nszIONF2FGC59kn+pPFaRa6WUNGwsZgXZiJxJwQbym+TzcH7smolUviLgpPbNx7V" crossorigin="anonymous"></script>
<script>${PASTE_SCRIPT}</script>
${FOOT}`;
}
