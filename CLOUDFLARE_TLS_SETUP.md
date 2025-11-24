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
kubectl get managedcertificate falcon-managed-cert
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

5. **Delete any existing records** pointing to the old IP (35.184.54.110)

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

### Check ManagedCertificate Status

```bash
kubectl describe managedcertificate falcon-managed-cert
```

Expected status after DNS propagation:
```
Status:
  Certificate Name: mcrt-xxxxx
  Certificate Status: Active
  Domain Status:
    Domain: falconmanagerpro.com
    Status: Active
    Domain: www.falconmanagerpro.com
    Status: Active
```

**If status is "Provisioning"**: Wait for DNS to propagate (can take up to 24 hours)

### Check Services

```bash
kubectl get services
```

Verify:
- `falcon-api` (ClusterIP on 5003)
- `falcon-ui` (can remain LoadBalancer or change to ClusterIP after Ingress works)

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

### Current Setup (Before Ingress)

```
User → Cloudflare → LoadBalancer (35.184.54.110) → falcon-ui:80 → nginx → falcon-api:5003
                    [No TLS]
```

### New Setup (After Ingress)

```
User → Cloudflare → Ingress (136.110.230.236) → Services
     [TLS]          [TLS with origin cert]
                         ↓
                    falcon-ui:80 (frontend)
                    falcon-api:5003 (backend)
```

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

## Cleanup Old Resources (After Verification)

Once the new Ingress is working, you can clean up:

```bash
# Optional: Change falcon-ui service from LoadBalancer to ClusterIP
kubectl patch service falcon-ui -p '{"spec":{"type":"ClusterIP"}}'

# This will release the old IP: 35.184.54.110
```

---

## Rollback Plan

If something goes wrong:

```bash
# Delete ingress
kubectl delete ingress falcon-ingress

# Delete managed certificate
kubectl delete managedcertificate falcon-managed-cert

# Keep the secret (doesn't hurt to keep it)
# kubectl delete secret cloudflare-origin-cert

# In Cloudflare: Point DNS back to old IP
# A record @ → 35.184.54.110
# A record www → 35.184.54.110
```

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
- [ ] ManagedCertificate status is "Active"
- [ ] Cloudflare DNS points to ingress IP
- [ ] Cloudflare SSL/TLS mode set to "Full (strict)"
- [ ] https://falconmanagerpro.com loads correctly
- [ ] https://www.falconmanagerpro.com loads correctly
- [ ] API endpoint works: https://falconmanagerpro.com/api/health
- [ ] Browser shows secure padlock
- [ ] No certificate warnings
- [ ] HTTP redirects to HTTPS (if enabled)

---

**Last Updated:** 2025-11-24
**Project:** falconmanagerpro
**GKE Cluster:** falcon-autopilot (us-central1)
**Domain:** falconmanagerpro.com
