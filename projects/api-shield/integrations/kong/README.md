# Kong Integration

Integrate API Shield with Kong Gateway for real-time API security.

## Architecture

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   Client    │─────▶│    Kong     │─────▶│  Upstream   │
│             │      │   Gateway   │      │    API      │
└─────────────┘      └──────┬──────┘      └─────────────┘
                            │
                     ┌──────▼──────┐
                     │  API Shield │
                     │   Plugin    │
                     └─────────────┘
```

## Installation

### 1. Deploy API Shield

```bash
# Using Docker
docker run -d \
  --name api-shield \
  -p 8080:8000 \
  ghcr.io/your-org/api-shield:latest

# Or using Kubernetes
kubectl apply -f api-shield-deployment.yaml
```

### 2. Install Kong Plugin

```bash
# Copy plugin to Kong plugins directory
cp -r kong-plugin/api-shield /usr/local/share/lua/5.1/kong/plugins/

# Or install via LuaRocks
luarocks install kong-plugin-api-shield
```

### 3. Configure Kong

```yaml
# kong.yml
_format_version: "3.0"

plugins:
  - name: api-shield
    config:
      shield_url: "http://api-shield:8000"
      timeout: 1000
      block_on_error: false
      log_only: false
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `shield_url` | string | required | URL of API Shield service |
| `timeout` | integer | 1000 | Request timeout in ms |
| `block_on_error` | boolean | false | Block if Shield unavailable |
| `log_only` | boolean | false | Log only, don't block |
| `include_body` | boolean | false | Send request body to Shield |
| `max_body_size` | integer | 8192 | Max body size to send |

## Plugin Code

See `handler.lua` for the full plugin implementation.
