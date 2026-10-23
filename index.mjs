// opencode-perch-auth — Perch Terminal provider plugin for magpie / OpenCode
//
// 逆向自 Perch Terminal 2.4.2 (resources/app.asar → dist-electron/main.js)
// 与官方 CLI perchai-cli@2.4.115:
//
//   POST https://app.perchai.app/api/perch-terminal/turn-ticket   {"surface":"cli","profile":"standard"}
//   POST https://app.perchai.app/api/perch-terminal/model-call    SSE: answer_delta / reasoning_delta /
//                                                                 tool_call_delta / tool_use_end /
//                                                                 stream_restart / continuation_seam / done
//
// 鉴权是 Supabase access token (Authorization: Bearer)，换票后带 x-perch-turn-ticket。
// 关键：表面（surface）绑定在会话上，必须用 `perch login` 签发的会话，
// 桌面端/网页会话无论请求怎么写都会 403 perch_surface_required。

import crypto from "node:crypto"
import fs from "node:fs"
import http from "node:http"
import os from "node:os"
import path from "node:path"

const PROVIDER = "perch"
const APP_URL = "https://app.perchai.app"
const MODEL_CALL = `${APP_URL}/api/perch-terminal/model-call`
const TURN_TICKET = `${APP_URL}/api/perch-terminal/turn-ticket`

// 公开的 Supabase 配置（web bundle 中 supabase-js 初始化参数）
const SUPABASE_URL = "https://zlfuvsfjtgsdtqcaykia.supabase.co"
const SUPABASE_KEY = "sb_publishable_w4R_pNkUpygBFIljZCoOlA_67ACg0FO"

const CLI_VERSION = "2.4.115"
const USER_AGENT = `perchai-cli/${CLI_VERSION}`
const LOCALE = "en"

const DEFAULT_SESSION = path.join(os.homedir(), ".perch", "cli-auth-session.json")
const TICKET_RENEW_MS = 30_000
const TICKET_FALLBACK_MS = 300_000

// 默认只挂 DeepSeek Flash。
// Starter 套餐上，光给 preferredModelId 会被忽略（一律落到 Qwen/Qwen3.8-Flash），
// 必须同时给 CoreWeave 那条 pin 的 manualModelOptionId，服务端才真的路由过去
// （done.model 回 deepseek/deepseek-v4.1-flash-1017）。
// 想再加模型，用插件 options：
//   { "models": [{ "id": "opus", "name": "Claude Opus 5.5", "preferredModelId": "claude-opus-5.5" }] }
const DEEPSEEK_STARTER_PIN = "openrouter-deepseek-deepseek-v4-1-flash"

const BASE_MODELS = {
  "deepseek-flash": {
    name: "DeepSeek Flash",
    preferredModelId: "deepseek-v4.1-flash",
    manualModelOptionId: DEEPSEEK_STARTER_PIN,
    strictManual: true,
    limit: { context: 1000000, output: 32000 },
    tool_call: true,
    reasoning: true,
  },
}

// ---------------------------------------------------------------- 会话与登录

function expandHome(p) {
  if (!p) return DEFAULT_SESSION
  const s = String(p).trim()
  if (!s) return DEFAULT_SESSION
  if (s === "~") return os.homedir()
  if (s.startsWith("~/") || s.startsWith("~\\")) return path.join(os.homedir(), s.slice(2))
  return s
}

function readSession(sessionPath) {
  const raw = fs.readFileSync(sessionPath, "utf8")
  const j = JSON.parse(raw)
  return {
    accessToken: j.accessToken || j.access_token || "",
    refreshToken: j.refreshToken || j.refresh_token || "",
    email: j.email || "",
    appUrl: j.appUrl || APP_URL,
    expiresAt: Number(j.expiresAt || 0),
  }
}

function inputValue(inputs, key, fallback) {
  if (inputs == null) return fallback
  if (typeof inputs === "string") return inputs
  if (Array.isArray(inputs)) {
    const hit = inputs.find((x) => x && x.key === key)
    return hit?.value ?? fallback
  }
  return inputs[key] ?? fallback
}

async function refreshSession(refreshToken) {
  const res = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=refresh_token`, {
    method: "POST",
    headers: { apikey: SUPABASE_KEY, "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
  })
  if (!res.ok) return { ok: false, status: res.status }
  const j = await res.json()
  return {
    ok: true,
    access: j.access_token,
    refresh: j.refresh_token || refreshToken,
    expiresIn: Number(j.expires_in || 3600),
  }
}

function authToken(auth) {
  return auth?.key || auth?.access || ""
}

// ---------------------------------------------------------------- 浏览器登录（PKCE）

// 复刻官方 CLI 的登录（perchai-cli 的 waitForCode / exchangeCodeForSession）：
//   1. GET {app}/api/perch-terminal/cli-auth/config  → supabaseUrl / anonKey / providers / redirectHost
//   2. 本地起 http://127.0.0.1:<随机端口>/callback 收 code
//   3. 浏览器打开 Supabase /auth/v1/authorize（S256 PKCE）
//   4. POST /auth/v1/token?grant_type=pkce 换 access_token / refresh_token

const CALLBACK_PATH = "/callback"
const LOGIN_TIMEOUT_MS = 120_000

function b64url(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

function makePkce() {
  const verifier = b64url(crypto.randomBytes(32))
  const challenge = b64url(crypto.createHash("sha256").update(verifier).digest())
  return { verifier, challenge }
}

async function fetchCliAuthConfig(appUrl) {
  const res = await fetch(`${appUrl.replace(/\/+$/, "")}/api/perch-terminal/cli-auth/config`, {
    headers: { Accept: "application/json" },
  })
  if (!res.ok) throw new Error(`Perch 登录配置不可用（HTTP ${res.status}）`)
  const cfg = await res.json()
  if (!cfg?.ok || !cfg.supabaseUrl || !cfg.supabaseAnonKey) {
    throw new Error("Perch 没有返回 CLI 登录配置")
  }
  return cfg
}

function callbackPage(ok) {
  const title = ok ? "已登录 Perch" : "登录失败"
  const hint = ok ? "可以关掉这个页面，回到 magpie。" : "回到 magpie 再点一次登录。"
  return `<!doctype html><meta charset="utf-8"><title>${title}</title>` +
    `<body style="font-family:system-ui;padding:40px;background:#100d0b;color:#f5efe8">` +
    `<h1 style="font-size:18px">${title}</h1><p style="opacity:.7">${hint}</p></body>`
}

async function startCallbackServer(host, timeoutMs = LOGIN_TIMEOUT_MS) {
  let settle = null
  const result = new Promise((resolve) => { settle = resolve })

  const server = http.createServer((req, res) => {
    const url = new URL(req.url || "/", `http://${host}`)
    if (url.pathname !== CALLBACK_PATH) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" })
      res.end("Not found")
      return
    }
    const code = url.searchParams.get("code")
    const error = url.searchParams.get("error_description") || url.searchParams.get("error")
    res.writeHead(code ? 200 : 400, { "Content-Type": "text/html; charset=utf-8" })
    res.end(callbackPage(Boolean(code)))
    settle?.(code ? { ok: true, code } : { ok: false, error: error || "回调里没有 code" })
    settle = null
  })

  await new Promise((resolve, reject) => {
    server.once("error", reject)
    server.listen(0, host, () => {
      server.off("error", reject)
      resolve()
    })
  })

  const { port } = server.address()
  const timer = setTimeout(() => {
    settle?.({ ok: false, error: "等待浏览器登录超时" })
    settle = null
  }, timeoutMs)

  return {
    redirectTo: `http://${host}:${port}${CALLBACK_PATH}`,
    waitForCode: () => result,
    close: () => {
      clearTimeout(timer)
      return new Promise((resolve) => server.close(() => resolve()))
    },
  }
}

function authorizeUrl(cfg, provider, redirectTo, challenge) {
  const url = new URL(`${cfg.supabaseUrl.replace(/\/+$/, "")}/auth/v1/authorize`)
  url.searchParams.set("provider", provider)
  url.searchParams.set("redirect_to", redirectTo)
  url.searchParams.set("code_challenge", challenge)
  url.searchParams.set("code_challenge_method", "s256")
  url.searchParams.set("flow_type", "pkce")
  if (provider === "google") url.searchParams.set("prompt", "select_account")
  return url.toString()
}

async function exchangePkce(cfg, code, verifier) {
  const res = await fetch(`${cfg.supabaseUrl.replace(/\/+$/, "")}/auth/v1/token?grant_type=pkce`, {
    method: "POST",
    headers: {
      apikey: cfg.supabaseAnonKey,
      Authorization: `Bearer ${cfg.supabaseAnonKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ auth_code: code, code_verifier: verifier }),
  })
  const j = await res.json().catch(() => null)
  if (!res.ok || !j?.access_token) {
    throw new Error(j?.error_description || j?.msg || j?.message || `换取会话失败（HTTP ${res.status}）`)
  }
  return j
}

// 官方 CLI 写进 ~/.perch/cli-auth-session.json 的形状；插件默认不写，避免覆盖 CLI 会话
function sessionFilePayload(appUrl, session) {
  const expiresAt =
    session.expires_at ??
    (session.expires_in ? Math.floor(Date.now() / 1000) + Number(session.expires_in) : null)
  return {
    version: 1,
    appUrl,
    accessToken: session.access_token,
    refreshToken: session.refresh_token ?? null,
    expiresAt,
    userId: session.user?.id ?? null,
    email: session.user?.email ?? null,
    updatedAt: new Date().toISOString(),
  }
}

function oauthMethod(provider, label, appUrl, options) {
  return {
    type: "oauth",
    label,
    async authorize() {
      const cfg = await fetchCliAuthConfig(appUrl)
      if (Array.isArray(cfg.providers) && cfg.providers.length && !cfg.providers.includes(provider)) {
        return { type: "failed", error: `Perch 没有启用 ${provider} 登录` }
      }
      const { verifier, challenge } = makePkce()
      const server = await startCallbackServer(cfg.redirectHost?.trim() || "127.0.0.1")
      return {
        url: authorizeUrl(cfg, provider, server.redirectTo, challenge),
        instructions: `在浏览器里完成 Perch 的 ${provider} 登录，结束后会自动回到 magpie。`,
        method: "auto",
        async callback() {
          try {
            const r = await server.waitForCode()
            if (!r.ok) return { type: "failed", error: r.error }
            const session = await exchangePkce(cfg, r.code, verifier)
            // 可选：把会话按官方 CLI 的形状落盘，供 perch 命令和别的工具复用
            if (options?.writeSessionFile) {
              try {
                const target = expandHome(options.sessionPath || DEFAULT_SESSION)
                fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 })
                fs.writeFileSync(target, JSON.stringify(sessionFilePayload(appUrl, session), null, 2), {
                  mode: 0o600,
                })
              } catch {
                // 写不了文件不影响登录本身
              }
            }
            const expires = session.expires_at
              ? session.expires_at * 1000
              : Date.now() + Number(session.expires_in || 3600) * 1000
            return {
              type: "success",
              access: session.access_token,
              refresh: session.refresh_token,
              expires,
              accountId: session.user?.email || session.user?.id,
            }
          } catch (err) {
            return { type: "failed", error: String(err?.message || err) }
          } finally {
            await server.close()
          }
        },
      }
    },
  }
}

// ---------------------------------------------------------------- 单轮票据

function createTicketClient(getAccess, appUrl = APP_URL) {
  let ticket = null
  let inflight = null

  async function request(body) {
    const token = getAccess()
    if (!token) return null
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 8000)
    try {
      const res = await fetch(`${appUrl.replace(/\/+$/, "")}/api/perch-terminal/turn-ticket`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
          "User-Agent": USER_AGENT,
          "x-perch-locale": LOCALE,
        },
        body: JSON.stringify(body),
        signal: ctrl.signal,
      })
      if (!res.ok) return null
      return await res.json()
    } catch {
      return null
    } finally {
      clearTimeout(timer)
    }
  }

  function adopt(payload, renewal) {
    if (!payload?.ok || !payload.ticket || !payload.ticketId || !payload.runId) return null
    const exp = payload.expiresAt ? Date.parse(payload.expiresAt) : Date.now() + TICKET_FALLBACK_MS
    ticket = {
      token: payload.ticket,
      ticketId: payload.ticketId,
      runId: payload.runId,
      expiresAt: Number.isFinite(exp) ? exp : Date.now() + TICKET_FALLBACK_MS,
      renewal,
    }
    return ticket
  }

  async function mint() {
    if (inflight) return inflight
    inflight = (async () => {
      // 官方 CLI 的换票体；surface 必须声明为 cli
      const payload = await request({ surface: "cli", profile: "standard" })
      return adopt(payload, null)
    })()
    try {
      return await inflight
    } finally {
      inflight = null
    }
  }

  async function renew(t) {
    if (!t?.renewal) return null
    const payload = await request({ ...t.renewal, renew: true, ticketId: t.ticketId })
    return adopt(payload, t.renewal)
  }

  return {
    async header() {
      const t = ticket
      if (!t) {
        const fresh = await mint()
        return fresh ? { "x-perch-turn-ticket": fresh.token } : {}
      }
      if (t.expiresAt > Date.now() + TICKET_RENEW_MS) {
        return { "x-perch-turn-ticket": t.token }
      }
      if (t.renewal) {
        const next = await renew(t)
        if (next) return { "x-perch-turn-ticket": next.token }
      }
      if (t.expiresAt > Date.now()) return { "x-perch-turn-ticket": t.token }
      ticket = null
      const fresh = await mint()
      return fresh ? { "x-perch-turn-ticket": fresh.token } : {}
    },
  }
}

// ---------------------------------------------------------------- 请求/响应转换

function normalizeContent(content) {
  if (typeof content === "string") return content
  if (!Array.isArray(content)) return content == null ? "" : String(content)
  const parts = []
  for (const p of content) {
    if (!p || typeof p !== "object") continue
    if (p.type === "text" && typeof p.text === "string") parts.push({ type: "text", text: p.text })
    else if (p.type === "image_url") parts.push(p)
  }
  return parts
}

function normalizeMessage(m) {
  const out = { role: m.role, content: normalizeContent(m.content) }
  if (m.name) out.name = m.name
  if (m.tool_call_id) out.tool_call_id = m.tool_call_id
  if (Array.isArray(m.tool_calls)) out.tool_calls = m.tool_calls
  if (out.role === "assistant" && out.content === "" && out.tool_calls) out.content = ""
  return out
}

function mapModel(bodyModel, extraModels) {
  const key = String(bodyModel || "perch-auto")
  const all = { ...BASE_MODELS, ...extraModels }
  if (all[key]) {
    const entry = all[key]
    return {
      key,
      preferredModelId: entry.preferredModelId ?? null,
      manualModelOptionId: entry.manualModelOptionId ?? null,
      strictManual: entry.strictManual === true,
    }
  }
  // perch-auto：显式交回服务端路由
  if (key === "perch-auto") return { key, preferredModelId: null, manualModelOptionId: null, strictManual: false }
  // 未知 id：当作服务端的 preferredModelId 直接透传
  return { key, preferredModelId: key, manualModelOptionId: null, strictManual: false }
}

function buildPerchBody(body, mapped) {
  const request = {
    messages: (body.messages || []).map(normalizeMessage),
    toolChoice: body.tool_choice ?? "auto",
  }
  if (Array.isArray(body.tools) && body.tools.length) request.tools = body.tools
  if (Number.isFinite(body.max_tokens)) request.maxTokens = body.max_tokens
  if (Number.isFinite(body.temperature)) request.temperature = body.temperature
  if (body.response_format) request.responseFormat = body.response_format

  return {
    request,
    lane: "chat",
    strictManual: mapped.strictManual === true,
    preferredModelId: mapped.preferredModelId,
    avoidModelIds: [],
    attribution: null,
    clientSurface: "cli",
    // 有 pin 时服务端才肯离开默认路由；见文件开头 DEEPSEEK_STARTER_PIN 的说明
    ...(mapped.manualModelOptionId ? { manualModelOptionId: mapped.manualModelOptionId } : {}),
  }
}

function toolCallsToOpenAI(toolCalls) {
  if (!Array.isArray(toolCalls)) return []
  return toolCalls.map((c, i) => ({
    index: i,
    id: c.id || `call_${i}`,
    type: "function",
    function: {
      name: c.name || "",
      arguments: typeof c.arguments === "string" ? c.arguments : JSON.stringify(c.arguments ?? {}),
    },
  }))
}

// Perch 的 tool_call_delta / tool_use_end 推的是累积快照，不是增量。
// OpenAI 客户端会把 delta 直接拼接，所以这里按 id 合并，取最长的一份。
function mergeToolCalls(pending, calls) {
  for (const c of calls) {
    const key = c.id || `idx-${c.index}`
    const prev = pending.get(key)
    const args = c.function.arguments || ""
    if (!prev) {
      pending.set(key, { ...c, id: key })
      continue
    }
    if (c.function.name) prev.function.name = c.function.name
    if (args.length >= (prev.function.arguments || "").length) prev.function.arguments = args
  }
}

// Perch 的 usage 把缓存拆开报：inputTokens 是"未命中缓存的输入"，
// cacheReadInputTokens / cacheCreationInputTokens 单列，totalTokens 是三者与输出之和。
// OpenAI 那边 prompt_tokens 含缓存，缓存命中数在 prompt_tokens_details.cached_tokens，
// magpie 的缓存率就是拿这两个相除算的，漏映射就会一直显示 0%。
function usageToOpenAI(u) {
  if (!u) return null
  const n = (v) => (Number.isFinite(v) ? v : 0)
  const fresh = n(u.inputTokens ?? u.prompt_tokens)
  const out = n(u.outputTokens ?? u.completion_tokens)
  const cacheRead = n(u.cacheReadInputTokens)
  const cacheWrite = n(u.cacheCreationInputTokens)
  const prompt = fresh + cacheRead + cacheWrite
  const total = Number.isFinite(u.totalTokens) ? u.totalTokens : prompt + out
  const usage = {
    prompt_tokens: prompt,
    completion_tokens: out,
    total_tokens: total,
    prompt_tokens_details: {
      cached_tokens: cacheRead,
      cache_write_tokens: cacheWrite,
    },
  }
  if (Number.isFinite(u.reasoningTokens)) {
    usage.completion_tokens_details = { reasoning_tokens: u.reasoningTokens }
  }
  return usage
}

function errorResponse(status, text, code) {
  let message = text
  let errorCode = code || ""
  try {
    const j = JSON.parse(text)
    if (j && typeof j.error === "string") message = j.error
    if (j && typeof j.errorCode === "string") errorCode = j.errorCode
  } catch {}

  const headers = { "content-type": "application/json" }
  if (status === 401) headers["X-Magpie-Sign-In"] = "expired"

  return new Response(
    JSON.stringify({
      error: {
        message: message || `Perch answered ${status}`,
        type: errorCode || "perch_error",
        code: errorCode || String(status),
      },
    }),
    { status, headers },
  )
}

function sseStream(upstream, modelName) {
  const id = `chatcmpl-${crypto.randomUUID().replace(/-/g, "")}`
  const created = Math.floor(Date.now() / 1000)
  const enc = new TextEncoder()

  return new ReadableStream({
    async start(controller) {
      let started = false
      let final = null
      let lastText = ""
      const pending = new Map()
      const send = (obj) => controller.enqueue(enc.encode(`data: ${JSON.stringify(obj)}\n\n`))
      const chunk = (delta, finish = null) =>
        send({
          id,
          object: "chat.completion.chunk",
          created,
          model: modelName,
          choices: [{ index: 0, delta, finish_reason: finish }],
        })
      const start = () => {
        if (started) return
        started = true
        chunk({ role: "assistant", content: "" })
      }

      const reader = upstream.getReader()
      const dec = new TextDecoder()
      let buf = ""

      try {
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          buf += dec.decode(value, { stream: true })
          const lines = buf.split("\n")
          buf = lines.pop() ?? ""
          for (const line of lines) {
            if (!line.startsWith("data:")) continue
            const raw = line.slice(5).trim()
            if (!raw) continue
            let ev
            try {
              ev = JSON.parse(raw)
            } catch {
              continue
            }
            switch (ev.type) {
              case "answer_delta":
                if (typeof ev.text === "string") {
                  start()
                  lastText += ev.text
                  chunk({ content: ev.text })
                }
                break
              case "reasoning_delta":
                if (typeof ev.text === "string") {
                  start()
                  chunk({ reasoning_content: ev.text })
                }
                break
              case "tool_call_delta":
              case "tool_use_end":
                mergeToolCalls(pending, toolCallsToOpenAI(ev.toolCalls))
                break
              case "stream_restart":
                // 上游中途故障切换，之前的内容已作废；流式端无法收回，标记给客户端
                lastText = ""
                break
              case "model_call_failed":
                break
              case "done":
                final = ev
                // 排查路由用：PERCH_DEBUG_MODEL=1 时把服务端真正用的模型打到 stderr
                if (process.env.PERCH_DEBUG_MODEL) {
                  console.error(`[perch] provider=${ev.provider} model=${ev.model}`)
                }
                break
              default:
                break
            }
          }
        }
      } catch (err) {
        send({ error: { message: String(err?.message || err), type: "perch_stream_error" } })
      } finally {
        try {
          start()
          if (final && final.ok === false) {
            send({
              error: {
                message: String(final.error || "Perch model call failed"),
                type: final.errorCode || "perch_error",
              },
            })
          } else {
            mergeToolCalls(pending, toolCallsToOpenAI(final?.toolCalls))
            const calls = [...pending.values()]
            if (calls.length) {
              chunk({ tool_calls: calls.map((c, i) => ({ ...c, index: i })) })
              chunk({}, "tool_calls")
            } else {
              chunk({}, "stop")
            }
            const usage = usageToOpenAI(final?.usage)
            if (usage) {
              send({
                id,
                object: "chat.completion.chunk",
                created,
                model: modelName,
                choices: [],
                usage,
              })
            }
          }
          controller.enqueue(enc.encode("data: [DONE]\n\n"))
        } catch {}
        controller.close()
      }
    },
  })
}

function jsonCompletion(payload, modelName) {
  const calls = toolCallsToOpenAI(payload?.toolCalls)
  const message = {
    role: "assistant",
    content: typeof payload?.text === "string" ? payload.text : "",
  }
  if (calls.length) {
    message.tool_calls = calls.map(({ index, ...rest }) => rest)
  }
  return new Response(
    JSON.stringify({
      id: `chatcmpl-${crypto.randomUUID().replace(/-/g, "")}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: modelName,
      choices: [
        {
          index: 0,
          message,
          finish_reason: calls.length ? "tool_calls" : "stop",
        },
      ],
      usage: usageToOpenAI(payload?.usage) || undefined,
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  )
}

// ---------------------------------------------------------------- 插件

export const PerchPlugin = async (_input, options) => {
  const extraModels = {}
  for (const m of options?.models || []) {
    if (!m?.id) continue
    extraModels[m.id] = {
      ...BASE_MODELS["perch-auto"],
      ...m,
      name: m.name || m.id,
    }
  }

  return {
    config: async (cfg) => {
      cfg.provider ??= {}
      cfg.provider[PROVIDER] ??= {
        name: "Perch",
        npm: "@ai-sdk/openai-compatible",
        api: APP_URL,
        models: { ...BASE_MODELS, ...extraModels },
      }
    },

    auth: {
      provider: PROVIDER,
      methods: [
        oauthMethod("google", "使用 Google 登录 Perch", APP_URL, options),
        oauthMethod("github", "使用 GitHub 登录 Perch", APP_URL, options),
        {
          type: "api",
          label: "Perch CLI 会话",
          placeholder: DEFAULT_SESSION,
          prompts: [
            {
              type: "text",
              key: "sessionPath",
              message: "Perch CLI 会话文件（回车使用默认路径）",
              placeholder: DEFAULT_SESSION,
            },
          ],
          async authorize(inputs) {
            const sessionPath = expandHome(inputValue(inputs, "sessionPath", DEFAULT_SESSION))
            let session
            try {
              session = readSession(sessionPath)
            } catch (err) {
              return {
                type: "failed",
                error: `读不到 ${sessionPath}，先在终端运行 perch login`,
              }
            }
            if (!session.accessToken) {
              return { type: "failed", error: `${sessionPath} 里没有 access token，重新运行 perch login` }
            }
            return {
              type: "success",
              key: session.accessToken,
              metadata: {
                refreshToken: session.refreshToken,
                email: session.email,
                sessionPath,
                appUrl: session.appUrl,
              },
            }
          },
        },
      ],

      refreshLead: 5 * 60 * 1000,

      async refresh(auth) {
        const rt = auth?.refreshToken || auth?.refresh || auth?.metadata?.refreshToken
        if (!rt) {
          throw Object.assign(new Error("会话里没有 refresh token，请重新 perch login"), {
            signIn: "expired",
          })
        }
        const r = await refreshSession(rt)
        if (!r.ok) {
          throw Object.assign(new Error(`Supabase 拒绝了续期（${r.status}），请重新 perch login`), {
            signIn: "expired",
          })
        }
        return {
          access: r.access,
          key: r.access,
          refresh: r.refresh,
          expires: Date.now() + r.expiresIn * 1000,
          metadata: { ...(auth.metadata || {}), refreshToken: r.refresh },
        }
      },

      async usage(auth) {
        const token = authToken(auth)
        if (!token) return { error: "尚未登录 Perch CLI", windows: [] }
        try {
          const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")))
          return {
            plan: payload?.app_metadata?.plan || undefined,
            user: payload?.email || auth?.metadata?.email || undefined,
            windows: [],
          }
        } catch {
          return { windows: [] }
        }
      },

      async loader(getAuth) {
        const auth = await getAuth()
        const token = authToken(auth)
        if (!token) return {}

        const tickets = createTicketClient(() => authToken(auth))

        return {
          baseURL: APP_URL,

          async fetch(_input, init) {
            let body
            try {
              const raw =
                typeof init?.body === "string"
                  ? init.body
                  : init?.body
                    ? new TextDecoder().decode(init.body)
                    : "{}"
              body = JSON.parse(raw)
            } catch (err) {
              return errorResponse(400, JSON.stringify({ error: "请求体不是合法 JSON" }), "bad_request")
            }

            const mapped = mapModel(body.model, extraModels)
            const perchBody = buildPerchBody(body, mapped)
            const streaming = body.stream !== false

            const headers = {
              "Content-Type": "application/json",
              Authorization: `Bearer ${authToken(auth)}`,
              "User-Agent": USER_AGENT,
              "x-perch-locale": LOCALE,
              ...(streaming ? { Accept: "text/event-stream" } : {}),
              ...(await tickets.header()),
            }

            let res
            try {
              res = await fetch(MODEL_CALL, {
                method: "POST",
                headers,
                body: JSON.stringify(perchBody),
                signal: init?.signal,
              })
            } catch (err) {
              return errorResponse(502, JSON.stringify({ error: `连不上 Perch: ${err?.message || err}` }), "upstream_unreachable")
            }

            if (!res.ok) {
              const text = await res.text().catch(() => "")
              return errorResponse(res.status, text)
            }

            const ctype = (res.headers.get("content-type") || "").toLowerCase()
            if (ctype.includes("text/event-stream")) {
              return new Response(sseStream(res.body, mapped.key), {
                status: 200,
                headers: { "content-type": "text/event-stream", "cache-control": "no-cache" },
              })
            }

            if (streaming) {
              // 请求要流式但上游给了整包，转成单块流
              const payload = await res.json().catch(() => null)
              if (!payload) return errorResponse(502, JSON.stringify({ error: "Perch 返回了无法解析的响应" }), "bad_upstream")
              return new Response(sseStream(payloadToStream(payload), mapped.key), {
                status: 200,
                headers: { "content-type": "text/event-stream", "cache-control": "no-cache" },
              })
            }

            const payload = await res.json().catch(() => null)
            if (!payload) return errorResponse(502, JSON.stringify({ error: "Perch 返回了无法解析的响应" }), "bad_upstream")
            if (payload.ok === false) {
              return errorResponse(502, JSON.stringify(payload), payload.errorCode || "perch_error")
            }
            return jsonCompletion(payload, mapped.key)
          },
        }
      },
    },

    provider: {
      id: PROVIDER,
      async models(provider) {
        return { ...provider.models, ...extraModels }
      },
    },
  }
}

// 把非流式 payload 包成一段 SSE，供“要流式但上游整包返回”的情况复用
function payloadToStream(payload) {
  const enc = new TextEncoder()
  return new ReadableStream({
    start(controller) {
      const events = []
      if (typeof payload.text === "string" && payload.text) {
        events.push({ type: "answer_delta", text: payload.text })
      }
      events.push({ type: "done", ok: payload.ok !== false, text: payload.text, usage: payload.usage, toolCalls: payload.toolCalls })
      for (const ev of events) controller.enqueue(enc.encode(`data: ${JSON.stringify(ev)}\n\n`))
      controller.close()
    },
  })
}

export const _internal = {
  normalizeMessage,
  normalizeContent,
  buildPerchBody,
  mapModel,
  toolCallsToOpenAI,
  usageToOpenAI,
  readSession,
  expandHome,
  inputValue,
}
