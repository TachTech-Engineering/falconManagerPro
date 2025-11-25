# URGENT: Deploy Origin Certificate to Fix SSL Error

## Current Problem

**SSL Handshake Failed** because:
- Your site is running on the OLD LoadBalancer (35.184.54.110) - **NO TLS**
- Cloudflare Full (Strict) mode requires HTTPS on origin
- The Ingress with origin certificate **has not been deployed yet**

## Solution: Deploy Ingress with Origin Certificate

### Step 1: Open GCP Cloud Shell

1. Go to: https://console.cloud.google.com
2. Select project: **falconmanagerpro**
3. Click the Cloud Shell icon (top right)

### Step 2: Upload Files to Cloud Shell

Upload these 3 files from `/home/kthompson/Development/Projects/falconpy/`:
- `k8s-ingress.yaml`
- `cloudflare-origin-secret.yaml`
- `deploy-tls.sh`

**How to upload:**
- Click the 3-dot menu in Cloud Shell → "Upload"
- Select the 3 files above

### Step 3: Connect to Your Cluster

```bash
gcloud container clusters get-credentials falcon-autopilot \
  --region us-central1 \
  --project falconmanagerpro
```

### Step 4: Deploy the Configuration

```bash
# Make script executable
chmod +x deploy-tls.sh

# Run deployment
./deploy-tls.sh
```

Or manually:

```bash
# Apply origin certificate secret
kubectl apply -f cloudflare-origin-secret.yaml

# Apply ingress
kubectl apply -f k8s-ingress.yaml

# Check status
kubectl get ingress falcon-ingress
kubectl get managedcertificate falcon-managed-cert
```

### Step 5: Wait for Ingress to Provision (10-15 minutes)

Watch the ingress status:
```bash
kubectl get ingress falcon-ingress -w
```

Wait until you see:
```
NAME             CLASS    HOSTS                                           ADDRESS           PORTS     AGE
falcon-ingress   <none>   falconmanagerpro.com,www.falconmanagerpro.com   136.110.230.236   80, 443   5m
```

### Step 6: Get the Ingress IP Address

```bash
kubectl get ingress falcon-ingress -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
```

Expected output: **136.110.230.236** (or another IP)

### Step 7: Update Cloudflare DNS (CRITICAL!)

**Current DNS (WRONG):**
- Points to Cloudflare IPs (104.21.52.27, 172.67.194.154)
- These are proxied through Cloudflare
- But your origin is the OLD LoadBalancer without TLS

**What you need to do:**

1. Login to Cloudflare Dashboard
2. Go to: DNS → Records
3. **Update A records:**

| Type | Name | Content | Proxy Status | TTL |
|------|------|---------|--------------|-----|
| A | `@` | `136.110.230.236` | Proxied (🟠) | Auto |
| A | `www` | `136.110.230.236` | Proxied (🟠) | Auto |

**Note:** Use the IP from Step 6 if different from 136.110.230.236

### Step 8: Verify It's Working

Wait 5-10 minutes for DNS propagation, then:

```bash
# Test HTTPS
curl -I https://falconmanagerpro.com

# Check API
curl https://falconmanagerpro.com/api/health
```

You should see:
- **HTTP 200** response
- No SSL errors
- Secure connection

### Step 9: In Browser

Visit: https://falconmanagerpro.com

- Should load without SSL errors
- Click padlock → Certificate should be valid
- Issued by: Cloudflare

---

## What This Does

**Before (Current - BROKEN):**
```
Cloudflare [HTTPS] → Old LoadBalancer [HTTP only] ❌ SSL Handshake Failed
           (Full Strict)    (35.184.54.110)
```

**After (Fixed):**
```
Cloudflare [HTTPS] → New Ingress [HTTPS with origin cert] → Services ✅
           (Full Strict)    (136.110.230.236)
```

---

## Troubleshooting

### "kubectl: command not found"

Cloud Shell has kubectl pre-installed. If you see this error, you're not in Cloud Shell.

### "No resources found"

Make sure you're connected to the right cluster:
```bash
kubectl config current-context
```

Should show: `gke_falconmanagerpro_us-central1_falcon-autopilot`

### Ingress stuck in "Creating"

Check events:
```bash
kubectl describe ingress falcon-ingress
```

### DNS still not working after 10 minutes

Flush your DNS cache:
```bash
# Linux
sudo systemd-resolve --flush-caches

# Or use different DNS
dig @8.8.8.8 falconmanagerpro.com
```

### Still getting SSL errors after deployment

1. **Check Cloudflare SSL/TLS mode:**
   - Should be "Full (strict)"
   - Go to: SSL/TLS → Overview

2. **Check DNS points to new IP:**
   ```bash
   dig +short falconmanagerpro.com @8.8.8.8
   ```
   Should eventually resolve to your Ingress IP

3. **Check Ingress has IP:**
   ```bash
   kubectl get ingress falcon-ingress
   ```

---

## Quick Reference

### Current Status
- **Old LoadBalancer**: 35.184.54.110 (HTTP only - active)
- **Reserved Static IP**: 136.110.230.236 (not in use yet)
- **DNS**: Points to Cloudflare (104.21.52.27, 172.67.194.154)
- **Cloudflare Mode**: Full (Strict) - requires HTTPS on origin
- **Problem**: Origin (old LB) doesn't support HTTPS

### What Needs to Happen
1. ✅ Origin certificate created (done)
2. ✅ K8s secret YAML created (done)
3. ✅ Ingress YAML created (done)
4. ⏳ Deploy to cluster (YOU ARE HERE)
5. ⏳ Update DNS to new IP
6. ⏳ Wait for propagation
7. ⏳ Test and verify

---

## After Successful Deployment

Once working, you can optionally:

1. **Change falcon-ui service to ClusterIP** (from LoadBalancer):
   ```bash
   kubectl patch service falcon-ui -p '{"spec":{"type":"ClusterIP"}}'
   ```
   This will release the old IP (35.184.54.110)

2. **Monitor the new setup:**
   ```bash
   kubectl get ingress falcon-ingress
   kubectl describe managedcertificate falcon-managed-cert
   ```

3. **Update documentation** with actual deployed IP if different

---

**PRIORITY: Do Steps 1-7 NOW to fix the SSL error!**

Estimated time: **30 minutes** (10 min deployment + 10 min DNS + 10 min verification)
