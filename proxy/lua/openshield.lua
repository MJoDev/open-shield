-- openshield.lua — the proxy's access phase.
--
-- This is the thin layer of §4.1: it collects what the engine needs to decide,
-- asks, and acts on the answer. No filtering logic lives here. That belongs to
-- the engine, where it can be tested, versioned and changed without touching
-- the server that is carrying live traffic.
--
-- Why access_by_lua rather than the auth_request module the design document
-- sketches: auth_request discards the request body, and RF-03 requires
-- filtering SQL injection and XSS payloads — which, in a POST, live in the
-- body. This phase can read the body, and it saves an internal subrequest.

local http = require "resty.http"
local cjson = require "cjson.safe"

local _M = {}

-- Configuration comes from the environment (§5.5), read once per worker.
local function env(name, fallback)
  local value = os.getenv(name)
  if value == nil or value == "" then
    return fallback
  end
  return value
end

local ENGINE_URL      = env("OS_ENGINE_URL", "http://engine:8080")
local DECIDE_TIMEOUT  = tonumber(env("OS_DECIDE_TIMEOUT_MS", "150"))
local MAX_BODY        = tonumber(env("OS_MAX_BODY_INSPECT_BYTES", "8192"))
local FAIL_MODE       = env("OS_FAIL_MODE", "open")
local KEEPALIVE_IDLE  = tonumber(env("OS_ENGINE_KEEPALIVE_MS", "60000"))
local KEEPALIVE_POOL  = tonumber(env("OS_ENGINE_KEEPALIVE_POOL", "32"))

-- Headers the engine never needs to see. Dropping them keeps the decision
-- request small, and keeps credentials out of a request that gets logged.
local SKIP_HEADERS = {
  ["authorization"]       = true,
  ["proxy-authorization"] = true,
  ["content-length"]      = true,
  ["accept-encoding"]     = true,
}

-- collect_headers copies the request's headers, lowercased.
local function collect_headers()
  local out = {}
  for name, value in pairs(ngx.req.get_headers()) do
    local key = string.lower(name)
    if not SKIP_HEADERS[key] then
      -- A repeated header arrives as a table; join it so the engine always
      -- sees a string.
      if type(value) == "table" then
        out[key] = table.concat(value, ", ")
      else
        out[key] = value
      end
    end
  end
  return out
end

-- read_body returns at most MAX_BODY bytes of the request body.
--
-- The cap is what keeps an upload from being copied into memory and scanned on
-- the request path. A truncated body is reported as such, so the engine's rules
-- know they are looking at part of the picture.
local function read_body()
  if MAX_BODY <= 0 then
    return "", false
  end

  ngx.req.read_body()

  local body = ngx.req.get_body_data()
  if body == nil then
    -- Nginx spilled the body to a temporary file because it exceeded
    -- client_body_buffer_size. Reading it back would mean disk I/O on the
    -- request path; the size alone already puts it past the inspection cap.
    if ngx.req.get_body_file() ~= nil then
      return "", true
    end
    return "", false
  end

  if #body > MAX_BODY then
    return string.sub(body, 1, MAX_BODY), true
  end
  return body, false
end

-- deny renders the block page. It carries the request id so that a user who
-- reports being blocked can be matched to the exact audit entry.
local function deny(status, request_id)
  ngx.status = status

  local message = "Request blocked"
  if status == 429 then
    message = "Too many requests"
    ngx.header["Retry-After"] = "60"
  end

  ngx.header["Content-Type"] = "text/html; charset=utf-8"
  ngx.header["X-Request-ID"] = request_id
  ngx.say(string.format([[<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>%d — %s</title>
<style>body{font-family:system-ui,sans-serif;margin:4rem auto;max-width:34rem;
padding:0 1.5rem;line-height:1.6;color:#1c1f24}code{background:#e8eaee;
padding:.15rem .35rem;border-radius:.25rem}</style></head><body>
<h1>%d — %s</h1>
<p>Esta solicitud fue bloqueada por open-shield.</p>
<p>Si crees que se trata de un error, comunica esta referencia al equipo técnico:</p>
<p><code>%s</code></p>
</body></html>]], status, message, status, message, request_id))

  return ngx.exit(status)
end

-- fail_open decides what happens when the engine cannot be reached.
--
-- The default is to let the request through. A protection layer that takes the
-- protected site offline whenever its own control plane hiccups has inverted
-- its purpose — §8.2 sets an availability target of 99%, and no filtering
-- requirement outranks it. Set OS_FAIL_MODE=closed where the opposite trade is
-- the right one.
local function on_engine_error(err, request_id)
  ngx.log(ngx.ERR, "openshield: engine unreachable (", err, "), fail mode: ", FAIL_MODE)

  if FAIL_MODE == "closed" then
    return deny(503, request_id)
  end
  -- Fall through: the request proceeds to the backend.
end

function _M.access()
  local request_id = ngx.var.request_id
  ngx.req.set_header("X-Request-ID", request_id)

  local body, truncated = read_body()

  local payload = cjson.encode({
    request_id     = request_id,
    ip             = ngx.var.remote_addr,
    method         = ngx.req.get_method(),
    path           = ngx.var.uri,
    query          = ngx.var.args or "",
    host           = ngx.var.host,
    scheme         = ngx.var.scheme,
    headers        = collect_headers(),
    body           = body,
    body_truncated = truncated,
  })

  if payload == nil then
    ngx.log(ngx.ERR, "openshield: could not encode the decision request")
    return on_engine_error("encoding failed", request_id)
  end

  local client = http.new()
  client:set_timeouts(DECIDE_TIMEOUT, DECIDE_TIMEOUT, DECIDE_TIMEOUT)

  local res, err = client:request_uri(ENGINE_URL .. "/v1/decide", {
    method  = "POST",
    body    = payload,
    headers = { ["Content-Type"] = "application/json" },
    -- Reusing connections is what keeps the added latency inside the 50 ms
    -- budget: a fresh TCP handshake per request would spend most of it before
    -- the engine had seen anything.
    keepalive_timeout = KEEPALIVE_IDLE,
    keepalive_pool    = KEEPALIVE_POOL,
  })

  if not res then
    return on_engine_error(err, request_id)
  end
  if res.status ~= 200 then
    return on_engine_error("engine answered " .. res.status, request_id)
  end

  local decision = cjson.decode(res.body)
  if decision == nil then
    return on_engine_error("malformed decision", request_id)
  end

  if decision.verdict == "block" then
    ngx.log(ngx.WARN, "openshield: blocked ", ngx.var.remote_addr,
            " rule=", decision.rule or "?",
            " request_id=", request_id,
            " reason=", decision.reason or "")
    return deny(decision.status or 403, request_id)
  end

  -- Allowed: fall through to proxy_pass.
end

return _M
