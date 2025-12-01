-- API Shield Kong Plugin Schema

local typedefs = require "kong.db.schema.typedefs"

return {
    name = "api-shield",
    fields = {
        { consumer = typedefs.no_consumer },
        { protocols = typedefs.protocols_http },
        {
            config = {
                type = "record",
                fields = {
                    {
                        shield_url = {
                            type = "string",
                            required = true,
                            description = "URL of the API Shield service",
                        },
                    },
                    {
                        timeout = {
                            type = "integer",
                            default = 1000,
                            description = "Request timeout in milliseconds",
                        },
                    },
                    {
                        block_on_error = {
                            type = "boolean",
                            default = false,
                            description = "Block requests if Shield service is unavailable",
                        },
                    },
                    {
                        log_only = {
                            type = "boolean",
                            default = false,
                            description = "Log results only, do not block requests",
                        },
                    },
                    {
                        include_body = {
                            type = "boolean",
                            default = false,
                            description = "Include request body in analysis",
                        },
                    },
                    {
                        max_body_size = {
                            type = "integer",
                            default = 8192,
                            description = "Maximum body size to send for analysis",
                        },
                    },
                    {
                        excluded_paths = {
                            type = "array",
                            elements = { type = "string" },
                            default = {},
                            description = "Paths to exclude from analysis",
                        },
                    },
                },
            },
        },
    },
}
