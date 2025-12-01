# Envoy Integration

Integrate API Shield with Envoy Proxy using External Authorization (ext_authz).

## Architecture

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   Client    │─────▶│   Envoy     │─────▶│  Upstream   │
│             │      │   Proxy     │      │   Service   │
└─────────────┘      └──────┬──────┘      └─────────────┘
                            │
                     ┌──────▼──────┐
                     │  API Shield │
                     │  ext_authz  │
                     └─────────────┘
```

## Configuration

### 1. Deploy API Shield with gRPC support

```bash
docker run -d \
  --name api-shield \
  -p 8000:8000 \
  -p 9001:9001 \  # gRPC port
  ghcr.io/your-org/api-shield:latest
```

### 2. Configure Envoy

See `envoy.yaml` for the complete configuration.

```yaml
# Key configuration snippet
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      grpc_service:
        envoy_grpc:
          cluster_name: api_shield_cluster
        timeout: 0.5s
      failure_mode_allow: false
      include_peer_certificate: true
```

## Features

- **gRPC Integration**: High-performance native Envoy integration
- **Request Headers**: All headers passed for analysis
- **Response Headers**: Security headers added to responses
- **Metadata**: Risk scores and signals in response metadata
- **Tracing**: Full distributed tracing support
