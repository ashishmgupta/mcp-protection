local MCP_Firewall = {
  PRIORITY = 950,
  VERSION  = "1.1.0",
}

-- ─────────────────────────────────────────────────────────────
-- Shared helper: open a TCP socket, POST body to the firewall,
-- return the HTTP status code from the response line.
-- Returns nil on any network error (caller decides fail-open/closed).
-- ─────────────────────────────────────────────────────────────
local function call_firewall(conf, path, body)
  local sock = ngx.socket.tcp()
  sock:settimeout(conf.timeout_ms)

  local ok, err = sock:connect(conf.firewall_host, conf.firewall_port)
  if not ok then
    kong.log.warn("MCP_FIREWALL | UNREACHABLE | " .. tostring(err))
    return nil
  end

  local req = table.concat({
    "POST " .. path .. " HTTP/1.1\r\n",
    "Host: " .. conf.firewall_host .. "\r\n",
    "Content-Type: application/json\r\n",
    "Content-Length: " .. #body .. "\r\n",
    "Connection: close\r\n",
    "\r\n",
    body
  })

  sock:send(req)
  local status_line = sock:receive("*l")
  sock:close()

  if not status_line then
    return nil
  end

  return tonumber(status_line:match("HTTP/%d+%.%d+ (%d+)"))
end


-- ─────────────────────────────────────────────────────────────
-- REQUEST phase — inspect inbound MCP tool call before it
-- reaches the Atlassian MCP server.
-- ─────────────────────────────────────────────────────────────
function MCP_Firewall:access(conf)
  kong.service.request.enable_buffering()

  local body = kong.request.get_raw_body()
  if not body or body == "" then
    return
  end

  local ct = kong.request.get_header("content-type") or ""
  if not ct:find("application/json") then
    return
  end

  kong.log.warn("MCP_FIREWALL | REQUEST | INSPECTING | len=" .. #body)

  local code = call_firewall(conf, "/inspect", body)

  if code == nil then
    kong.log.warn("MCP_FIREWALL | REQUEST | FIREWALL_UNREACHABLE — allowing")
    return
  end

  kong.log.warn("MCP_FIREWALL | REQUEST | firewall_status=" .. code)

  if code == 403 then
    kong.log.warn("MCP_FIREWALL | REQUEST | BLOCKED")
    return kong.response.exit(403,
      '{"error":"Request blocked by AI security policy"}',
      { ["Content-Type"] = "application/json" })
  end

  kong.log.warn("MCP_FIREWALL | REQUEST | ALLOWED")
end


-- ─────────────────────────────────────────────────────────────
-- RESPONSE phase — inspect MCP server response before it is
-- sent back to the client.
--
-- Kong automatically enables buffered proxying when this
-- function is present: the full upstream response body is
-- available via kong.response.get_raw_body() and nothing has
-- been sent to the client yet.
--
-- Catches: indirect prompt injection embedded in Jira ticket
-- content, reconnaissance data in tool responses, etc.
--
-- Note: only application/json responses are inspected.
-- text/event-stream (SSE) is skipped — buffering an open SSE
-- stream would block the connection indefinitely.
-- ─────────────────────────────────────────────────────────────
function MCP_Firewall:response(conf)
  local ct = kong.response.get_header("content-type") or ""

  if not ct:find("application/json") then
    kong.log.warn("MCP_FIREWALL | RESPONSE | SKIP | content-type=" .. ct)
    return
  end

  local body = kong.response.get_raw_body()
  if not body or body == "" then
    return
  end

  kong.log.warn("MCP_FIREWALL | RESPONSE | INSPECTING | len=" .. #body)

  local code = call_firewall(conf, "/inspect-response", body)

  if code == nil then
    kong.log.warn("MCP_FIREWALL | RESPONSE | FIREWALL_UNREACHABLE — allowing")
    return
  end

  kong.log.warn("MCP_FIREWALL | RESPONSE | firewall_status=" .. code)

  if code == 403 then
    kong.log.warn("MCP_FIREWALL | RESPONSE | BLOCKED — indirect injection in MCP response")
    return kong.response.exit(403,
      '{"error":"Response blocked — indirect prompt injection detected in MCP server response"}',
      { ["Content-Type"] = "application/json" })
  end

  kong.log.warn("MCP_FIREWALL | RESPONSE | ALLOWED")
end


return MCP_Firewall
