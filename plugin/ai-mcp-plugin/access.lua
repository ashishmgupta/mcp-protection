-- MCP AI Firewall — minimal passthrough (confirmed working)
kong.log.warn("MCP_FIREWALL | START | method=" .. (kong.request.get_method() or "?") .. " path=" .. (kong.request.get_path() or "?"))
kong.log.warn("MCP_FIREWALL | PASS_THROUGH")
