import assert from "node:assert/strict";
import test from "node:test";
import {
  ID_ALPHABET,
  ID_LENGTH,
  SECRET_LENGTH,
  TOKEN_LENGTH,
  buildCsp,
  escapeHtml,
  feedbackMarkdown,
  hashSecret,
  isValidToken,
  keyHexFromToken,
  openJson,
  pasteFromJson,
  randomToken,
  renderHome,
  renderPaste,
  sealJson,
} from "../src/core.js";

const SAMPLE_TOKEN = "123456789ABCDEFG123456789ABCDEFG";

test("tokens have the expected length, alphabet, and practical uniqueness", () => {
  const seen = new Set();
  for (let index = 0; index < 5_000; index += 1) {
    const token = randomToken(ID_LENGTH);
    assert.equal(token.length, ID_LENGTH);
    assert.match(token, new RegExp(`^[${ID_ALPHABET}]+$`));
    assert.equal(seen.has(token), false);
    seen.add(token);
  }
  assert.equal(randomToken(SECRET_LENGTH).length, SECRET_LENGTH);
});

test("paste tokens reject the wrong length and ambiguous characters", () => {
  assert.equal(isValidToken(SAMPLE_TOKEN), true);
  assert.equal(isValidToken(randomToken(TOKEN_LENGTH)), true);
  assert.equal(isValidToken("123456789ABCDEFG"), false);
  assert.equal(isValidToken("0".repeat(TOKEN_LENGTH)), false);
  assert.equal(isValidToken("l".repeat(TOKEN_LENGTH)), false);
});

test("sealed pastes round-trip with the right key and stay closed otherwise", async () => {
  const keyHex = await keyHexFromToken(SAMPLE_TOKEN);
  const value = { title: "t", content: "hello", feedback: [] };
  const box = await sealJson(value, keyHex);

  assert.equal(box.data.includes && false, false);
  assert.doesNotMatch(new TextDecoder().decode(box.data), /hello/);
  assert.deepEqual(await openJson(box, keyHex), value);

  const wrongKey = await keyHexFromToken(randomToken(TOKEN_LENGTH));
  assert.equal(await openJson(box, wrongKey), null);
  assert.equal(await openJson({ iv: box.iv, data: box.data.slice(0, -1) }, keyHex), null);
});

test("key derivation is deterministic per token and distinct across tokens", async () => {
  assert.equal(await keyHexFromToken(SAMPLE_TOKEN), await keyHexFromToken(SAMPLE_TOKEN));
  assert.notEqual(await keyHexFromToken(SAMPLE_TOKEN), await keyHexFromToken(randomToken(TOKEN_LENGTH)));
});

test("secret hashing is deterministic SHA-256", async () => {
  assert.equal(
    await hashSecret("owner secret"),
    "7d1614120f4cbb33bdb2ebeb045f3fe6546d5dbd59d3b104c30458b90a4e610f",
  );
});

test("JSON input ignores caller-controlled IDs, secrets, feedback, and timestamps", () => {
  const paste = pasteFromJson({
    id: "attacker",
    secretHash: "attacker",
    title: " title ",
    content: "hello",
    feedback: [{ body: "attacker" }],
    createdAt: 1,
    expiresAt: 2,
  }, 1_000);

  assert.equal(paste.title, "title");
  assert.equal(paste.content, "hello");
  assert.deepEqual(paste.feedback, []);
  assert.equal(paste.createdAt, 1_000);
  assert.equal(paste.expiresAt, 3_601_000);
  assert.equal("id" in paste, false);
  assert.equal("secretHash" in paste, false);
});

test("HTML output escapes paste and feedback fields", () => {
  const hostile = `<img src=x onerror="alert('x')">`;
  assert.equal(escapeHtml(hostile).includes("<img"), false);
  const page = renderPaste({
    id: SAMPLE_TOKEN,
    title: hostile,
    task: hostile,
    repo: "",
    sender: "",
    agent: "",
    content: hostile,
    feedback: [{ author: hostile, body: hostile, createdAt: 1_000 }],
    createdAt: 1_000,
    expiresAt: 3_601_000,
  }, 1_000);
  assert.equal(page.includes(hostile), false);
  assert.match(page, /&lt;img/);
});

test("feedback markdown preserves the agent-readable format", () => {
  const output = feedbackMarkdown({
    id: SAMPLE_TOKEN,
    title: "Review me",
    feedback: [{ author: "sam", body: "swap steps", createdAt: Date.UTC(2026, 7, 11, 20, 5) }],
  });
  assert.match(output, new RegExp(`## Feedback on "Review me" \\(${SAMPLE_TOKEN}\\)`));
  assert.match(output, /### 1\. sam \(20:05 UTC\)/);
  assert.match(output, /swap steps/);
});

test("homepage describes only the supported one-hour workflow", () => {
  const page = renderHome();
  assert.match(page, /permanently deleted after one hour/i);
  assert.match(page, /https:\/\/agentbin\.sh\/api\/pastes/);
  assert.match(page, /one-time owner secret/i);
  assert.doesNotMatch(page, /7 days|same IP|\?ttl=|curl -sT-/i);
});

test("homepage is indexable but paste pages are not", () => {
  assert.doesNotMatch(renderHome(), /noindex/);
  const page = renderPaste({
    id: SAMPLE_TOKEN,
    title: "t",
    task: "",
    repo: "",
    sender: "",
    agent: "",
    content: "c",
    feedback: [],
    createdAt: 1_000,
    expiresAt: 3_601_000,
  }, 1_000);
  assert.match(page, /noindex/);
});

test("paste pages pin CDN scripts with subresource integrity", () => {
  const page = renderPaste({
    id: SAMPLE_TOKEN,
    title: "t",
    task: "",
    repo: "",
    sender: "",
    agent: "",
    content: "c",
    feedback: [],
    createdAt: 1_000,
    expiresAt: 3_601_000,
  }, 1_000);
  for (const tag of page.match(/<script src="https:[^>]*>/g) ?? []) {
    assert.match(tag, /integrity="sha384-/);
    assert.match(tag, /crossorigin="anonymous"/);
  }
});

test("CSP allows exactly the rendered inline scripts and style, without unsafe-inline", async () => {
  const csp = await buildCsp();
  assert.doesNotMatch(csp, /unsafe-inline/);
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /frame-ancestors 'none'/);

  const { createHash } = await import("node:crypto");
  const hashOf = (source) => `'sha256-${createHash("sha256").update(source).digest("base64")}'`;

  const pastePage = renderPaste({
    id: SAMPLE_TOKEN,
    title: "t",
    task: "",
    repo: "",
    sender: "",
    agent: "",
    content: "c",
    feedback: [],
    createdAt: 1_000,
    expiresAt: 3_601_000,
  }, 1_000);

  for (const page of [renderHome(), pastePage]) {
    for (const [, script] of page.matchAll(/<script>([\s\S]*?)<\/script>/g)) {
      assert.equal(csp.includes(hashOf(script)), true, "inline script must be hash-allowed");
    }
    for (const [, style] of page.matchAll(/<style>([\s\S]*?)<\/style>/g)) {
      assert.equal(csp.includes(hashOf(style)), true, "inline style must be hash-allowed");
    }
  }
});
