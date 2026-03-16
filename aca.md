# Azure Container Apps Deployment (ap-proxy)

## Architecture

```
Client → [TLS] → ACA Ingress (:443) → [HTTP] → Caddy (:8080) → [WS] → ap-proxy (127.0.0.1:9090)
```

- ACA handles TLS termination
- Caddy listens on `:8080` — reverse proxies WebSocket traffic, adds security headers, serves `/health`
- `ap-proxy` binds to `127.0.0.1:9090` (localhost only, not directly accessible)

## Prerequisites

```bash
az login

# Register required providers (one-time per subscription)
az provider register --namespace Microsoft.ContainerRegistry
az provider register --namespace Microsoft.App
az provider register --namespace Microsoft.OperationalInsights
```

## Create Resources

```bash
# Resource group
az group create --name rat-demo --location eastus

# Container registry (alphanumeric only, globally unique)
az acr create --name ratdemo --resource-group rat-demo --sku Basic

# Container Apps environment
az containerapp env create \
  --name rat-demo-env \
  --resource-group rat-demo \
  --location eastus
```

## Build and Push Image

Cross-compiles the binary locally with `cross`, then builds and pushes the image in ACR:

```bash
scripts/docker-build.sh --acr --registry ratdemo --name ap-proxy --tag latest
```

## Deploy

Uses managed identity for ACR pull (no passwords):

```bash
az containerapp create \
  --name rat1 \
  --resource-group rat-demo \
  --environment rat-demo-env \
  --image ratdemo.azurecr.io/ap-proxy:latest \
  --registry-server ratdemo.azurecr.io \
  --registry-identity system \
  --ingress external \
  --target-port 8080
```

### Health Probes

After creating the app, configure health probes to use the `/health` endpoint:

```bash
az containerapp update \
  --name rat1 \
  --resource-group rat-demo \
  --yaml - <<'EOF'
properties:
  template:
    containers:
      - name: rat1
        probes:
          - type: liveness
            httpGet:
              path: /health
              port: 8080
            periodSeconds: 30
          - type: readiness
            httpGet:
              path: /health
              port: 8080
            periodSeconds: 10
          - type: startup
            httpGet:
              path: /health
              port: 8080
            periodSeconds: 5
            failureThreshold: 10
EOF
```

## Update

Rebuild and redeploy:

```bash
scripts/docker-build.sh --acr --registry ratdemo --name ap-proxy --tag latest

# --revision-suffix forces a new revision, ensuring ACA pulls the fresh image.
# Without it, updating with the same "latest" tag may reuse the cached image.
az containerapp update \
  --name rat1 \
  --resource-group rat-demo \
  --image ratdemo.azurecr.io/ap-proxy:latest \
  --revision-suffix "v$(date -u +%Y%m%d%H%M%S)"
```

## Environment Variables

The container runs with `BIND_ADDR=127.0.0.1:9090` (ap-proxy on localhost) and `RUST_LOG=info`. Caddy listens on `:8080` and reverse-proxies to ap-proxy. Override log level with:

```bash
az containerapp update \
  --name rat1 \
  --resource-group rat-demo \
  --set-env-vars RUST_LOG=debug
```

## Teardown

```bash
az group delete --name rat-demo --yes --no-wait
```
