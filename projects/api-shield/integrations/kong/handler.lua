-- API Shield Kong Plugin
-- Real-time API security integration

local http = require "resty.http"
local cjson = require "cjson.safe"

local APIShieldHandler = {
    VERSION = "1.0.0",
    PRIORITY = 1000, -- Run before most other plugins
}

function APIShieldHandler:access(conf)
    local httpc = http.new()
    httpc:set_timeout(conf.timeout)

    -- Build request payload
    local request_data = {
        method = kong.request.get_method(),
        path = kong.request.get_path(),
        client_ip = kong.client.get_forwarded_ip(),
        user_id = self:get_user_id(),
        headers = kong.request.get_headers(),
        query_params = kong.request.get_query(),
        response_code = nil, -- Not available yet in access phase
    }

    -- Optionally include body
    if conf.include_body then
        local body, err = kong.request.get_body()
        if body and #body <= conf.max_body_size then
            request_data.request_body = body
        end
    end

    -- Add geo information if available
    local geo = self:get_geo_info()
    if geo then
        request_data.geo = geo
    end

    -- Call API Shield
    local res, err = httpc:request_uri(conf.shield_url .. "/analyze", {
        method = "POST",
        body = cjson.encode(request_data),
        headers = {
            ["Content-Type"] = "application/json",
        },
    })

    if not res then
        kong.log.err("API Shield request failed: ", err)
        if conf.block_on_error then
            return kong.response.exit(503, {
                message = "Security service unavailable"
            })
        end
        return -- Allow request to proceed
    end

    local result = cjson.decode(res.body)
    if not result then
        kong.log.err("Failed to parse API Shield response")
        return
    end

    -- Store result for logging
    kong.ctx.shared.api_shield_result = result

    -- Log the result
    kong.log.info("API Shield analysis: ",
        "score=", result.risk_score,
        " action=", result.action,
        " blocking=", result.blocking
    )

    -- Handle action
    if conf.log_only then
        -- Just log, don't block
        return
    end

    if result.blocking then
        -- Add security headers
        kong.response.set_header("X-API-Shield-Score", result.risk_score)
        kong.response.set_header("X-API-Shield-Action", result.action)

        local status_code = 403
        if result.action == "rate_limit" then
            status_code = 429
            -- Add rate limit headers
            kong.response.set_header("Retry-After", "60")
        end

        return kong.response.exit(status_code, {
            message = result.reason or "Request blocked by security policy",
            request_id = result.request_id,
        })
    end

    -- Handle rate limiting (non-blocking)
    if result.action == "rate_limit" and result.rate_limit then
        kong.response.set_header("X-RateLimit-Limit", result.rate_limit.limit)
        kong.response.set_header("X-RateLimit-Window", result.rate_limit.window)
    end

    -- Handle challenge
    if result.action == "challenge" then
        kong.response.set_header("X-API-Shield-Challenge", result.challenge_type or "captcha")
    end
end

function APIShieldHandler:log(conf)
    -- Log the final result after response
    local result = kong.ctx.shared.api_shield_result
    if result then
        kong.log.info("API Shield final: ",
            "request_id=", result.request_id,
            " risk_score=", result.risk_score,
            " action=", result.action,
            " detectors=", table.concat(result.detectors_triggered or {}, ",")
        )
    end
end

function APIShieldHandler:get_user_id()
    -- Try to get user ID from various sources

    -- 1. From authenticated consumer
    local consumer = kong.client.get_consumer()
    if consumer then
        return consumer.id
    end

    -- 2. From JWT claim
    local jwt_claims = kong.ctx.shared.jwt_claims
    if jwt_claims and jwt_claims.sub then
        return jwt_claims.sub
    end

    -- 3. From header
    local user_header = kong.request.get_header("X-User-ID")
    if user_header then
        return user_header
    end

    return nil
end

function APIShieldHandler:get_geo_info()
    -- Try to get geo information from headers or GeoIP plugin
    local geo = {}

    -- From Cloudflare headers
    local cf_country = kong.request.get_header("CF-IPCountry")
    if cf_country then
        geo.country = cf_country
    end

    -- From X-Forwarded headers
    local lat = kong.request.get_header("X-Geo-Latitude")
    local lon = kong.request.get_header("X-Geo-Longitude")
    if lat and lon then
        geo.latitude = tonumber(lat)
        geo.longitude = tonumber(lon)
    end

    if next(geo) then
        return geo
    end
    return nil
end

return APIShieldHandler
