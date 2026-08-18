import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";

const port = 8794;
const baseUrl = `http://127.0.0.1:${port}`;
const wrangler = new URL("../node_modules/.bin/wrangler", import.meta.url).pathname;
let output = "";

const child = spawn(wrangler, [
  "dev",
  "--ip", "127.0.0.1",
  "--port", String(port),
  "--var", "PASTE_TTL_SECONDS:1",
], {
  cwd: new URL("..", import.meta.url),
  env: { ...process.env, WRANGLER_LOG_PATH: "/tmp/agentbin-wrangler-test.log" },
  stdio: ["ignore", "pipe", "pipe"],
});
child.stdout.on("data", (chunk) => { output += chunk; });
child.stderr.on("data", (chunk) => { output += chunk; });

async function waitUntilReady() {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`wrangler exited early\n${output}`);
    try {
      const response = await fetch(baseUrl);
      if (response.status === 200) return;
    } catch {
      // The development server is still starting.
    }
    await delay(250);
  }
  throw new Error(`timed out waiting for wrangler\n${output}`);
}

async function createPaste(content = "hello **world**") {
  const response = await fetch(`${baseUrl}/api/pastes`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      title: "test title",
      task: "test task",
      repo: "acme/x",
      sender: "casey",
      agent: "codex",
      content,
    }),
  });
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.id.length, 32);
  assert.equal(result.secret.length, 32);
  assert.equal(new URL(result.url).pathname, `/${result.id}`);
  return { ...result, url: `${baseUrl}/${result.id}` };
}

try {
  await waitUntilReady();

  const home = await fetch(baseUrl);
  assert.equal(home.status, 200);
  assert.match(await home.text(), /share agent output/);

  const skill = await fetch(`${baseUrl}/skill`);
  assert.equal(skill.status, 200);
  assert.match(await skill.text(), /name: agentbin/);

  const installer = await fetch(`${baseUrl}/install`);
  assert.equal(installer.status, 200);
  assert.match(await installer.text(), /#!\/bin\/sh/);

  const favicon = await fetch(`${baseUrl}/favicon.svg`);
  assert.equal(favicon.status, 200);
  assert.equal(favicon.headers.get("content-type"), "image/svg+xml");
  assert.match(await favicon.text(), /^<svg /);

  const paste = await createPaste();
  let response = await fetch(paste.url);
  let body = await response.text();
  assert.equal(response.status, 200);
  assert.match(body, /hello \*\*world\*\*/);
  assert.match(body, /test title/);
  assert.equal(body.includes(paste.secret), false);

  response = await fetch(`${paste.url}/raw`);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "hello **world**");

  response = await fetch(`${paste.url}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ author: "sam", body: "swap steps" }),
    redirect: "manual",
  });
  assert.equal(response.status, 303);
  assert.equal(response.headers.get("location"), `/${paste.id}#feedback`);

  response = await fetch(`${paste.url}/feedback.md`);
  body = await response.text();
  assert.equal(response.status, 200);
  assert.match(body, /sam/);
  assert.match(body, /swap steps/);
  assert.equal(body.includes(paste.secret), false);

  response = await fetch(paste.url, {
    method: "DELETE",
    headers: { Authorization: "Bearer wrong" },
  });
  assert.equal(response.status, 403);

  // Secrets are accepted in the Authorization header only, never the URL.
  response = await fetch(`${paste.url}?secret=${paste.secret}`, { method: "DELETE" });
  assert.equal(response.status, 403);

  response = await fetch(paste.url, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${paste.secret}` },
  });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { deleted: true });
  assert.equal((await fetch(paste.url)).status, 404);

  const concurrent = await createPaste("concurrent");
  const submissions = Array.from({ length: 10 }, (_, index) => fetch(`${concurrent.url}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ body: `item ${index}` }),
    redirect: "manual",
  }));
  const results = await Promise.all(submissions);
  assert.equal(results.every((result) => result.status === 303), true);
  body = await (await fetch(`${concurrent.url}/feedback.md`)).text();
  assert.equal((body.match(/^### /gm) ?? []).length, 10);

  response = await fetch(`${baseUrl}/api/pastes`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content: "json paste", id: "caller-controlled" }),
  });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).id.length, 32);

  // The first half of a token routes to the right paste; without the full
  // token (the decryption key) the paste stays unreadable.
  const keyProbe = await createPaste("key material check");
  const truncated = `${keyProbe.id.slice(0, 16)}${"2".repeat(16)}`;
  response = await fetch(`${baseUrl}/${truncated}`);
  assert.equal(response.status, 404);
  assert.equal((await response.text()).includes("key material check"), false);

  response = await fetch(`${baseUrl}/api/pastes`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{bad json",
  });
  assert.equal(response.status, 400);

  response = await fetch(`${baseUrl}/api/pastes`, {
    method: "POST",
    body: new URLSearchParams({ content: "   " }),
  });
  assert.equal(response.status, 400);

  const expired = await createPaste("expires promptly in this test");
  await delay(1_200);
  response = await fetch(expired.url);
  assert.equal(response.status, 404);
  assert.equal((await response.text()).includes("expires promptly"), false);

  const expiredDuringReview = await createPaste("review target");
  await delay(1_200);
  response = await fetch(`${expiredDuringReview.url}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ body: "preserve my feedback" }),
    redirect: "manual",
  });
  body = await response.text();
  assert.equal(response.status, 410);
  assert.match(body, /preserve my feedback/);

  console.log("integration tests passed");
} catch (error) {
  console.error(error);
  console.error(output);
  process.exitCode = 1;
} finally {
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    delay(5_000),
  ]);
  if (child.exitCode === null) child.kill("SIGKILL");
}
