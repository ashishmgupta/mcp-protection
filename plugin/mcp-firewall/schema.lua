local typedefs = require "kong.db.schema.typedefs"

return {
  name = "mcp-firewall",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type   = "record",
        fields = {
          { firewall_host = { type = "string",  default = "127.0.0.1" } },
          { firewall_port = { type = "integer", default = 5000 } },
          { timeout_ms    = { type = "integer", default = 3000 } },
        },
    }},
  },
}
