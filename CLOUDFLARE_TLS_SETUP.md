# Cloudflare Full (Strict) TLS Setup Guide
## falconmanagerpro.com

---

## Overview

This guide walks you through setting up full end-to-end TLS encryption with Cloudflare for your GKE cluster.

**Architecture:**
```
User → Cloudflare (TLS) → GCP Load Balancer (TLS with origin cert) → K8s Ingress → Services
     [Full Strict Mode]   [Static IP: 136.110.230.236]
```

---

## Prerequisites

- ✅ Domain transferred to Cloudflare nameservers
- ✅ GKE cluster: `falcon-autopilot` (us-central1)
- ✅ Static IP reserved: `falcon-ui-ip` (136.110.230.236)
- ✅ Cloudflare origin certificate generated

---

## Files Created

| File | Purpose |
|------|---------|
| `k8s-ingress.yaml` | Ingress resource with TLS configuration |
| `cloudflare-origin-secret.yaml` | K8s secret with Cloudflare origin certificate |
| `deploy-tls.sh` | Deployment script |
| `fmp-origin.pem` | Cloudflare origin certificate (DO NOT COMMIT) |
| `fmpp.pem` | Private key for origin certificate (DO NOT COMMIT) |

---

## Deployment Steps

### Step 1: Upload Files to GCP Cloud Shell

Option A: **GCP Cloud Shell (Recommended)**

1. Open [Google Cloud Console](https://console.cloud.google.com)
2. Select project: `falconmanagerpro`
3. Click Cloud Shell icon (top right)
4. Upload these files:
   ```bash
   k8s-ingress.yaml
   cloudflare-origin-secret.yaml
   deploy-tls.sh
   ```

Option B: **Local kubectl** (if you fix the auth plugin issue)

### Step 2: Connect to GKE Cluster

```bash
gcloud container clusters get-credentials falcon-autopilot \
  --region us-central1 \
  --project falconmanagerpro
```

Verify connection:
```bash
kubectl get nodes
kubectl get services
```

### Step 3: Run Deployment Script

```bash
chmod +x deploy-tls.sh
./deploy-tls.sh
```

Or manually:
```bash
# Apply secret
kubectl apply -f cloudflare-origin-secret.yaml

# Apply ingress
kubectl apply -f k8s-ingress.yaml

# Check status
kubectl get ingress falcon-ingress
```

### Step 4: Wait for Load Balancer Provisioning

⏱️ **This takes 10-15 minutes**

Monitor progress:
```bash
# Check ingress status
kubectl get ingress falcon-ingress -w

# Get load balancer IP (once available)
kubectl get ingress falcon-ingress -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
```

Expected output:
```
136.110.230.236
```

### Step 5: Update Cloudflare DNS

1. **Log into Cloudflare Dashboard**
2. **Select domain:** falconmanagerpro.com
3. **Go to:** DNS > Records
4. **Create/Update A records:**

   | Type | Name | Content | Proxy Status | TTL |
   |------|------|---------|--------------|-----|
   | A | `@` | `136.110.230.236` | Proxied (🟠) | Auto |
   | A | `www` | `136.110.230.236` | Proxied (🟠) | Auto |

5. **Delete any existing records** pointing to other IPs (the old LoadBalancer IP 35.184.54.110 was released on 2026-10-23)

### Step 6: Enable Full (Strict) TLS in Cloudflare

1. **Cloudflare Dashboard** → falconmanagerpro.com
2. **Go to:** SSL/TLS → Overview
3. **Select:** "Full (strict)"
4. **Verify setting:**
   ```
   Your SSL/TLS encryption mode is Full (strict)
   ```

### Step 7: Configure Additional Cloudflare Settings

**Recommended Settings:**

1. **Always Use HTTPS**
   - SSL/TLS → Edge Certificates
   - Enable "Always Use HTTPS"

2. **Automatic HTTPS Rewrites**
   - SSL/TLS → Edge Certificates
   - Enable "Automatic HTTPS Rewrites"

3. **Minimum TLS Version**
   - SSL/TLS → Edge Certificates
   - Set to "TLS 1.2" or higher

4. **HTTP Strict Transport Security (HSTS)** - Optional
   - SSL/TLS → Edge Certificates
   - Enable HSTS (be careful - this cannot be easily undone)

### Step 8: Verify End-to-End TLS

Wait 5-10 minutes after DNS propagation, then test:

```bash
# Test DNS resolution
dig falconmanagerpro.com
dig www.falconmanagerpro.com

# Test HTTPS
curl -I https://falconmanagerpro.com
curl -I https://www.falconmanagerpro.com

# Check certificate
openssl s_client -connect falconmanagerpro.com:443 -servername falconmanagerpro.com
```

**In browser:**
1. Visit https://falconmanagerpro.com
2. Click padlock icon → Certificate details
3. Verify: Issued by "Cloudflare"
4. Check for secure connection

---

## Monitoring & Troubleshooting

### Check Ingress Status

```bash
kubectl describe ingress falcon-ingress
```

Look for:
- `Address: 136.110.230.236`
- `Default backend: 404 Not Found`
- Events showing successful creation

### Check the Certificate Served by the Origin

```bash
echo | openssl s_client -connect 136.110.230.236:443 -servername falconmanagerpro.com 2>/dev/null \
  | openssl x509 -noout -issuer -enddate
```

Expected: issuer `CloudFlare Origin SSL Certificate Authority`, `notAfter=Nov 20 15:10:00 2040 GMT`.

> **Do not add a GCP `ManagedCertificate`.** Google can't validate the domain while it is
> proxied through Cloudflare, so it fails permanently. Worse, the controller keeps every
> failed `mcrt-*` cert attached via the `ingress.gcp.kubernetes.io/pre-shared-cert`
> annotation; once that passed 15 certs, every Ingress sync failed
> (`At most 15 SSL certificate(s) ... in TargetHttpsProxy`). It was removed on 2026-10-23.

### Check Services

```bash
kubectl get services
```

Verify:
- `falcon-api` (ClusterIP on 5003)
- `falcon-ui` (ClusterIP on 80, with `cloud.google.com/neg: '{"ingress": true}'`)

Neither service may be `type: LoadBalancer` — that gives it its own public IP that bypasses
Cloudflare and TLS. Without the NEG annotation, the GCE Ingress needs a NodePort and a
ClusterIP service will drop out of the load balancer.

### Check Ingress Sync Errors

```bash
kubectl get events --field-selector involvedObject.name=falcon-ingress,type=Warning --sort-by=.lastTimestamp
```

Warnings here mean changes to `k8s-ingress.yaml` are not reaching GCP, even if the site still works.

### Common Issues

**Issue: Ingress not getting IP address**
```bash
# Check events
kubectl get events --sort-by='.lastTimestamp' | grep ingress

# Check ingress controller
kubectl get pods -n kube-system | grep ingress
```

**Issue: Certificate not provisioning**
- Verify DNS is pointing to correct IP
- Ensure domains are set to "Proxied" in Cloudflare
- Wait up to 24 hours for propagation

**Issue: 502 Bad Gateway**
- Check backend services are running:
  ```bash
  kubectl get pods
  kubectl logs <pod-name>
  ```

**Issue: Mixed content warnings**
- Enable "Automatic HTTPS Rewrites" in Cloudflare
- Check nginx.conf for hardcoded HTTP URLs

---

## Architecture Details

### Current Setup

```
User → Cloudflare → Ingress (136.110.230.236, port 443 only) → NEG backends
     [TLS]          [TLS with origin cert]
                         ↓
                    falcon-ui:80 (frontend, ClusterIP)
                    falcon-api:5003 (backend, ClusterIP)
```

The Ingress has `kubernetes.io/ingress.allow-http: "false"`, so there is no port-80
listener at the origin. HTTP→HTTPS redirects happen at Cloudflare ("Always Use HTTPS").
This requires Cloudflare's SSL/TLS mode to stay on **Full (strict)** — "Flexible" connects
to the origin over HTTP and would take the site down.

### Path Routing

| Path | Backend Service | Port | Purpose |
|------|----------------|------|---------|
| `/api/*` | falcon-api | 5003 | Python Flask backend |
| `/*` | falcon-ui | 80 | React frontend (nginx) |

---

## Security Considerations

### Certificate Chain

1. **User ↔ Cloudflare**: Cloudflare Universal SSL certificate
2. **Cloudflare ↔ GCP**: Cloudflare origin certificate (15-year validity)
3. **Inside GKE**: Unencrypted (ClusterIP services)

### Origin Certificate Details

- **Type**: RSA 2048-bit
- **Validity**: 15 years (expires 2040-11-20)
- **Hostnames**:
  - `falconmanagerpro.com`
  - `*.falconmanagerpro.com`
- **Storage**: K8s secret `cloudflare-origin-cert` (base64 encoded)

### Important Notes

- Origin certificates are **only trusted by Cloudflare**
- Do NOT use origin certificates outside of Cloudflare
- Keep private key (`fmpp.pem`) secure and DO NOT commit to git
- Rotate certificates before expiry (set reminder for 2040!)

---

## Cleanup Old Resources (Done 2026-10-23)

The old `falcon-ui` LoadBalancer was still serving the site over plain HTTP at
35.184.54.110, bypassing Cloudflare. It was removed in this order to avoid downtime:

```bash
# 1. Move the Ingress backend for falcon-ui to a NEG (wait until it reports HEALTHY)
kubectl annotate svc falcon-ui 'cloud.google.com/neg={"ingress": true}'
# 2. Switch to ClusterIP (released 35.184.54.110)
kubectl apply -f k8s-frontend.yaml
# 3. HTTPS-only Ingress, drop the failed ManagedCertificate and its stale certs
kubectl apply -f k8s-ingress.yaml
kubectl delete managedcertificate falcon-managed-cert
kubectl annotate ingress falcon-ingress ingress.gcp.kubernetes.io/pre-shared-cert-
```

---

## Rollback Plan

The old LoadBalancer IP has been released, so there is no fallback origin. If the site
breaks after an Ingress change, check the sync warnings above and re-apply the last
known-good `k8s-ingress.yaml` / `k8s-frontend.yaml` from git. If Cloudflare reports
SSL handshake or 521 errors, confirm the SSL/TLS mode is still **Full (strict)**.

---

## Files to Add to .gitignore

```
# TLS Certificates - DO NOT COMMIT
*.pem
fmp-origin.pem
fmpp.pem
cloudflare-origin-secret.yaml
```

---

## Maintenance

### Certificate Renewal

Cloudflare origin certificates are valid for 15 years. Set a reminder:

**Date:** November 20, 2040
**Action:** Generate new origin certificate and update K8s secret

### Monitoring

**Check certificate expiry:**
```bash
kubectl get secret cloudflare-origin-cert -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -enddate
```

**Expected output:**
```
notAfter=Nov 20 15:10:00 2040 GMT
```

---

## Support & References

- **GKE Ingress Docs**: https://cloud.google.com/kubernetes-engine/docs/concepts/ingress
- **Cloudflare SSL Docs**: https://developers.cloudflare.com/ssl/
- **Cloudflare Origin Certificates**: https://developers.cloudflare.com/ssl/origin-configuration/origin-ca

---

## Verification Checklist

After deployment, verify:

- [ ] Ingress has IP address (136.110.230.236)
- [ ] No Warning events on `falcon-ingress`
- [ ] `curl -I -H 'Host: falconmanagerpro.com' http://136.110.230.236` is refused/reset (no HTTP at origin)
- [ ] No service in `kubectl get svc` has an EXTERNAL-IP
- [ ] Cloudflare DNS points to ingress IP
- [ ] Cloudflare SSL/TLS mode set to "Full (strict)"
- [ ] https://falconmanagerpro.com loads correctly
- [ ] https://www.falconmanagerpro.com loads correctly
- [ ] API endpoint works: https://falconmanagerpro.com/api/health
- [ ] Browser shows secure padlock
- [ ] No certificate warnings
- [ ] http://falconmanagerpro.com redirects to HTTPS (Cloudflare)

---

**Last Updated:** 2026-10-23
**Project:** falconmanagerpro
**GKE Cluster:** falcon-autopilot (us-central1)
**Domain:** falconmanagerpro.com
