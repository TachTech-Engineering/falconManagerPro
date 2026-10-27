# Cloudflare Tunnel setup

Falcon Manager Pro is served through an outbound-only Cloudflare Tunnel (cloudflared).
There is no public load balancer, static IP or origin certificate; the origin has no
inbound path from the internet.

```
User -> Cloudflare (proxy, WAF) -> Tunnel -> cloudflared pods -> falcon-ui:80 / falcon-api:5003
```

## Components
- `k8s-cloudflared.yaml`: ConfigMap (ingress rules), 2-replica Deployment, PodDisruptionBudget.
- Secret `cloudflared-creds`: tunnel credentials (`credentials.json`), not stored in the repo.
- Secret `tenant-encryption-keys`: key for encrypting tenant credentials in the database.
- DNS: `falconmanagerpro.com` is a proxied CNAME to `<tunnel-id>.cfargotunnel.com`
  (`www` is a CNAME to the apex).

## Routing
The tunnel is **locally managed**: routes live in the `cloudflared-config` ConfigMap.
Routes added in the Cloudflare dashboard are ignored (cloudflared returns 503 for every
request if no ingress rules load). To change routes, edit the ConfigMap and restart:

```
kubectl apply -f k8s-cloudflared.yaml
kubectl rollout restart deploy/cloudflared
```

`/api/` goes to `falcon-api`, everything else to `falcon-ui`.

## Recreating the credentials secret
Derive `credentials.json` from the tunnel token (`{"AccountTag": ..., "TunnelSecret": ..., "TunnelID": ...}`):

```
cloudflared tunnel token <tunnel-id>      # base64 JSON with keys a, s, t
kubectl create secret generic cloudflared-creds --from-file=credentials.json=<file>
```

## Troubleshooting
- 503 on every request: cloudflared has no ingress rules; check `kubectl logs -l app=cloudflared`.
- Health: `kubectl get pods -l app=cloudflared`; each pod serves `/ready` on port 2000.
- Remove LB history: the previous GCE load balancer, Cloud Armor policy and Cloudflare
  origin certificate were retired once the tunnel went live. See git history for
  `CLOUDFLARE_TLS_SETUP.md` and `k8s-ingress.yaml`.
