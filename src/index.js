import { DurableObject } from "cloudflare:workers";
import SKILL_MD from "../skill/agentbin/SKILL.md";
import INSTALL_SH from "../install.sh";
import {
  HttpError,
  ID_LENGTH,
  MAX_FEEDBACK_BYTES,
  MAX_FEEDBACK_COUNT,
  SECRET_LENGTH,
  TOKEN_LENGTH,
  TTL_MS,
  buildCsp,
  feedbackMarkdown,
  hashSecret,
  isValidToken,
  keyHexFromToken,
  openJson,
  pasteFromJson,
  pasteFromValues,
  randomToken,
  readLimitedText,
  renderCreated,
  renderExpiredFeedback,
  renderGone,
  renderHome,
  renderPaste,
  sealJson,
  utf8Length,
} from "./core.js";

const SECURITY_HEADERS = {
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

function response(request, body, status = 200, headers = {}) {
  return new Response(request.method === "HEAD" ? null : body, {
    status,
    headers: { ...SECURITY_HEADERS, ...headers },
  });
}

function html(request, body, status = 200) {
  return response(request, body, status, { "Content-Type": "text/html; charset=utf-8" });
}

function text(request, body, status = 200) {
  return response(request, body, status, { "Content-Type": "text/plain; charset=utf-8" });
}

function json(request, value, status = 200) {
  return response(request, `${JSON.stringify(value)}\n`, status, {
    "Content-Type": "application/json; charset=utf-8",
  });
}

function redirect(location) {
  return new Response(null, {
    status: 303,
    headers: { ...SECURITY_HEADERS, Location: location },
  });
}

function constantTimeEqual(left, right) {
  if (left.length !== right.length) return false;
  let mismatch = 0;
  for (let index = 0; index < left.length; index += 1) {
    mismatch |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return mismatch === 0;
}

// Records store only ciphertext plus the scheduling fields the server needs
// (createdAt, expiresAt, secretHash). Paste content, metadata, and feedback
// live inside `box`, encrypted with a key derived from the full link token,
// which the server never persists.
export class PasteStore extends DurableObject {
  async createPaste(record) {
    const existing = await this.ctx.storage.get("paste");
    if (existing && existing.expiresAt > Date.now()) return false;
    if (existing) await this.ctx.storage.deleteAll();

    await this.ctx.storage.put("paste", record);
    await this.ctx.storage.setAlarm(record.expiresAt);
    return true;
  }

  async getRecord() {
    const record = await this.ctx.storage.get("paste");
    if (!record) return null;
    if (record.expiresAt <= Date.now()) {
      await this.ctx.storage.deleteAll();
      return null;
    }
    return record;
  }

  async appendFeedback(feedback, keyHex) {
    let outcome = "missing";
    await this.ctx.storage.transaction(async (transaction) => {
      const record = await transaction.get("paste");
      if (!record) return;
      if (record.expiresAt <= Date.now()) {
        outcome = "expired";
        return;
      }

      const fields = await openJson(record.box, keyHex);
      if (!fields) return;
      if (fields.feedback.length >= MAX_FEEDBACK_COUNT) {
        outcome = "full";
        return;
      }

      fields.feedback = [...fields.feedback, feedback];
      record.box = await sealJson(fields, keyHex);
      await transaction.put("paste", record);
      outcome = "ok";
    });

    if (outcome === "expired") await this.ctx.storage.deleteAll();
    return outcome;
  }

  async deletePaste(candidateHash) {
    const record = await this.getRecord();
    if (!record) return "not_found";
    if (!constantTimeEqual(candidateHash, record.secretHash)) return "forbidden";

    await this.ctx.storage.deleteAll();
    return "deleted";
  }

  async alarm() {
    await this.ctx.storage.deleteAll();
  }
}

async function createStoredPaste(env, input) {
  const { createdAt, expiresAt, ...fields } = input;

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const token = randomToken(TOKEN_LENGTH);
    const secret = randomToken(SECRET_LENGTH);
    const record = {
      createdAt,
      expiresAt,
      secretHash: await hashSecret(secret),
      box: await sealJson(fields, await keyHexFromToken(token)),
    };
    const stub = env.PASTES.getByName(token.slice(0, ID_LENGTH));
    if (await stub.createPaste(record)) return { token, secret };
  }
  throw new HttpError(503, "could not allocate paste id");
}

function configuredTtlMs(env) {
  const seconds = Number(env.PASTE_TTL_SECONDS);
  return Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : TTL_MS;
}

async function parsePaste(request, env) {
  const raw = await readLimitedText(request);
  const ttlMs = configuredTtlMs(env);
  if (request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    try {
      return pasteFromJson(JSON.parse(raw), Date.now(), ttlMs);
    } catch {
      throw new HttpError(400, "bad json");
    }
  }
  return pasteFromValues(new URLSearchParams(raw), Date.now(), ttlMs);
}

// Backed by Cloudflare's rate-limiting bindings (see wrangler.jsonc). The
// client IP is used only as the in-memory bucketing key and is never logged.
async function enforceRateLimit(limiter, request) {
  if (!limiter) return;
  const key = request.headers.get("cf-connecting-ip") ?? "unknown";
  const { success } = await limiter.limit({ key });
  if (!success) throw new HttpError(429, "too many requests — try again in a minute");
}

function methodAllowed(request, allowed) {
  if (allowed.includes(request.method)) return null;
  return response(request, "method not allowed\n", 405, {
    Allow: allowed.join(", "),
    "Content-Type": "text/plain; charset=utf-8",
  });
}

async function route(request, env) {
  const url = new URL(request.url);

  if (url.pathname === "/") {
    if (request.method === "GET" || request.method === "HEAD") {
      return html(request, renderHome());
    }
    if (request.method !== "POST") return methodAllowed(request, ["GET", "HEAD", "POST"]);

    await enforceRateLimit(env.CREATE_LIMIT, request);
    const input = await parsePaste(request, env);
    if (!input.content.trim()) return text(request, "content required\n", 400);
    const { token, secret } = await createStoredPaste(env, input);
    return html(request, renderCreated(`${url.origin}/${token}`, token, secret));
  }

  if (url.pathname === "/skill" || url.pathname === "/install") {
    const invalidMethod = methodAllowed(request, ["GET", "HEAD"]);
    if (invalidMethod) return invalidMethod;
    return text(request, url.pathname === "/skill" ? SKILL_MD : INSTALL_SH);
  }

  if (url.pathname === "/api/pastes") {
    const invalidMethod = methodAllowed(request, ["POST"]);
    if (invalidMethod) return invalidMethod;

    await enforceRateLimit(env.CREATE_LIMIT, request);
    const input = await parsePaste(request, env);
    if (!input.content.trim()) return text(request, "content required\n", 400);
    const { token, secret } = await createStoredPaste(env, input);
    return json(request, {
      id: token,
      url: `${url.origin}/${token}`,
      secret,
    });
  }

  const match = url.pathname.match(/^\/([^/]+)(?:\/(feedback\.md|raw|feedback))?$/);
  if (!match || !isValidToken(match[1])) return text(request, "not found\n", 404);

  const [, token, child] = match;
  const stub = env.PASTES.getByName(token.slice(0, ID_LENGTH));

  if (!child && request.method === "DELETE") {
    // Header only: query-string secrets could end up in server or proxy logs.
    let secret = request.headers.get("authorization") ?? "";
    if (secret.startsWith("Bearer ")) secret = secret.slice(7);

    if (!secret) return text(request, "invalid secret\n", 403);
    const result = await stub.deletePaste(await hashSecret(secret));
    if (result === "not_found") return text(request, "not found\n", 404);
    if (result === "forbidden") return text(request, "invalid secret\n", 403);
    return json(request, { deleted: true });
  }

  const keyHex = await keyHexFromToken(token);

  if (child === "feedback" && request.method === "POST") {
    await enforceRateLimit(env.FEEDBACK_LIMIT, request);
    const values = new URLSearchParams(await readLimitedText(request));
    const body = (values.get("body") ?? "").trim();
    const author = (values.get("author") ?? "").trim() || "anon";
    if (!body) return redirect(`/${token}`);
    if (utf8Length(body) > MAX_FEEDBACK_BYTES) {
      return text(request, `feedback too long (max ${MAX_FEEDBACK_BYTES} chars)\n`, 400);
    }

    const outcome = await stub.appendFeedback({ author, body, createdAt: Date.now() }, keyHex);
    if (outcome === "full") {
      return text(request, `feedback limit reached (max ${MAX_FEEDBACK_COUNT} items)\n`, 409);
    }
    if (outcome !== "ok") return html(request, renderExpiredFeedback(body), 410);
    return redirect(`/${token}#feedback`);
  }

  if (request.method !== "GET" && request.method !== "HEAD") {
    return methodAllowed(request, ["GET", "HEAD"]);
  }

  const record = await stub.getRecord();
  const fields = record ? await openJson(record.box, keyHex) : null;
  if (!fields) {
    if (!child) return html(request, renderGone(), 404);
    return text(request, "404 page not found\n", 404);
  }

  const paste = {
    ...fields,
    id: token,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
  };

  if (!child) return html(request, renderPaste(paste));
  if (child === "raw") return text(request, paste.content);
  if (child === "feedback.md") return text(request, feedbackMarkdown(paste));
  return text(request, "not found\n", 404);
}

// Paste tokens are the decryption keys, so they are redacted from log lines.
function redactPath(pathname) {
  return pathname.replace(/[1-9A-HJ-NP-Za-km-z]{24,}/g, ":paste");
}

export default {
  async fetch(request, env) {
    SECURITY_HEADERS["Content-Security-Policy"] ??= await buildCsp();

    const startedAt = Date.now();
    let result;
    try {
      result = await route(request, env);
    } catch (error) {
      if (error instanceof HttpError) {
        result = text(request, `${error.message}\n`, error.status);
      } else {
        console.error("request failed", error);
        result = text(request, "internal server error\n", 500);
      }
    }

    console.log(
      `${request.method} ${redactPath(new URL(request.url).pathname)} ${result.status} ${Date.now() - startedAt}ms`,
    );
    return result;
  },
};
