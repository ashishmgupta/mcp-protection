local MCP_Firewall = {
  PRIORITY = 950,
  VERSION  = "1.2.3",
}

-- POST body to firewall. Returns status code and full response body.
local function call_firewall(conf, path, body)
  local sock = ngx.socket.tcp()
  sock:settimeout(conf.timeout_ms)

  local ok, err = sock:connect(conf.firewall_host, conf.firewall_port)
  if not ok then
    kong.log.warn("MCP_FIREWALL | UNREACHABLE | " .. tostring(err))
    return nil, nil
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

  -- Read status line
  local status_line = sock:receive("*l")
  if not status_line then
    sock:close()
    return nil, nil
  end
  local code = tonumber(status_line:match("HTTP/%d+%.%d+ (%d+)"))

  -- Skip response headers
  while true do
    local line = sock:receive("*l")
    if not line or line == "" or line == "\r" then break end
  end

  -- Read response body
  local resp_body = sock:receive("*a") or ""
  sock:close()

  return code, resp_body
end


-- REQUEST phase
function MCP_Firewall:access(conf)
  kong.service.request.enable_buffering()

  local body = kong.request.get_raw_body()
  if not body or body == "" then
    return
  end

  local ct = kong.request.get_header("content-type") or ""
  if not ct:find("application/json", 1, true) then
    return
  end

  kong.log.warn("MCP_FIREWALL | REQUEST | INSPECTING | len=" .. #body)
  kong.log.warn("MCP_FIREWALL | REQUEST | BODY | " .. body:sub(1, 500))

  local code, resp_body = call_firewall(conf, "/inspect", body)

  if code == nil then
    kong.log.warn("MCP_FIREWALL | REQUEST | FIREWALL_UNREACHABLE | allowing")
    return
  end

  kong.log.warn("MCP_FIREWALL | REQUEST | firewall_status=" .. code)
  kong.log.warn("MCP_FIREWALL | REQUEST | FIREWALL_RESPONSE | " .. (resp_body or ""):sub(1, 300))

  if code == 403 then
    kong.log.warn("MCP_FIREWALL | REQUEST | BLOCKED")
    return kong.response.exit(403,
      '{"error":"Request blocked by AI security policy"}',
      { ["Content-Type"] = "application/json" })
  end

  kong.log.warn("MCP_FIREWALL | REQUEST | ALLOWED")
end


-- RESPONSE phase
function MCP_Firewall:response(conf)
  local ct = kong.response.get_header("content-type") or ""

  local body = kong.response.get_raw_body()
  if not body or body == "" then
    kong.log.warn("MCP_FIREWALL | RESPONSE | EMPTY BODY | content-type=" .. ct)
    return
  end

  kong.log.warn("MCP_FIREWALL | RESPONSE | content-type=" .. ct .. " | body_len=" .. #body)

  -- application/json
  if ct:find("application/json", 1, true) then
    kong.log.warn("MCP_FIREWALL | RESPONSE | JSON BODY | " .. body:sub(1, 800))

    local code, resp_body = call_firewall(conf, "/inspect-response", body)
    if code == nil then
      kong.log.warn("MCP_FIREWALL | RESPONSE | FIREWALL_UNREACHABLE | allowing")
      return
    end

    kong.log.warn("MCP_FIREWALL | RESPONSE | firewall_status=" .. code)
    kong.log.warn("MCP_FIREWALL | RESPONSE | FIREWALL_RESPONSE | " .. (resp_body or ""):sub(1, 300))

    if code == 403 then
      kong.log.warn("MCP_FIREWALL | RESPONSE | BLOCKED")
      return kong.response.exit(403,
        '{"error":"Response blocked — indirect prompt injection detected"}',
        { ["Content-Type"] = "application/json" })
    end

    kong.log.warn("MCP_FIREWALL | RESPONSE | ALLOWED")
    return
  end

  -- text/event-stream (SSE)
  if ct:find("text/event-stream", 1, true) then
    kong.log.warn("MCP_FIREWALL | RESPONSE | SSE | body_len=" .. #body)
    kong.log.warn("MCP_FIREWALL | RESPONSE | SSE RAW BODY | " .. body:sub(1, 2000))

    local line_count = 0
    local jsonrpc_count = 0

    for data_line in body:gmatch("data: ([^\r\n]+)") do
      line_count = line_count + 1
      kong.log.warn("MCP_FIREWALL | RESPONSE | SSE LINE[" .. line_count .. "] len=" .. #data_line .. " | " .. data_line:sub(1, 500))

      if data_line:find('"jsonrpc"') then
        jsonrpc_count = jsonrpc_count + 1
        kong.log.warn("MCP_FIREWALL | RESPONSE | SSE JSONRPC LINE[" .. line_count .. "] FULL | " .. data_line)

        local code, resp_body = call_firewall(conf, "/inspect-response", data_line)
        if code == nil then
          kong.log.warn("MCP_FIREWALL | RESPONSE | FIREWALL_UNREACHABLE | allowing")
          return
        end

        kong.log.warn("MCP_FIREWALL | RESPONSE | SSE firewall_status=" .. code .. " line=" .. line_count)
        kong.log.warn("MCP_FIREWALL | RESPONSE | SSE FIREWALL_RESPONSE | " .. (resp_body or ""):sub(1, 500))

        if code == 403 then
          kong.log.warn("MCP_FIREWALL | RESPONSE | BLOCKED | line=" .. line_count)
          return kong.response.exit(403,
            '{"error":"Response blocked — indirect prompt injection detected in MCP server response"}',
            { ["Content-Type"] = "application/json" })
        end
      end
    end

    kong.log.warn("MCP_FIREWALL | RESPONSE | SSE DONE | total_lines=" .. line_count .. " jsonrpc_lines=" .. jsonrpc_count)
    if jsonrpc_count == 0 then
      kong.log.warn("MCP_FIREWALL | RESPONSE | SSE WARNING | no jsonrpc lines found in SSE body")
    end
    kong.log.warn("MCP_FIREWALL | RESPONSE | SSE ALLOWED")
    return
  end

  kong.log.warn("MCP_FIREWALL | RESPONSE | SKIP | content-type=" .. ct)
end


return MCP_Firewall
