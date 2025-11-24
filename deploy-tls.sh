#!/bin/bash
# Deploy TLS configuration for falconmanagerpro.com
# Run this script in GCP Cloud Shell or on a machine with kubectl access

set -e

echo "=== Deploying Cloudflare Origin Certificate and Ingress ==="
echo ""

# Check kubectl access
echo "Checking cluster access..."
kubectl get nodes

echo ""
echo "Step 1: Creating Cloudflare origin certificate secret..."
kubectl apply -f cloudflare-origin-secret.yaml

echo ""
echo "Step 2: Deploying Ingress with TLS..."
kubectl apply -f k8s-ingress.yaml

echo ""
echo "Step 3: Checking Ingress status..."
kubectl get ingress falcon-ingress

echo ""
echo "Step 4: Checking ManagedCertificate status..."
kubectl get managedcertificate falcon-managed-cert

echo ""
echo "=== Deployment Commands Completed ==="
echo ""
echo "IMPORTANT NEXT STEPS:"
echo "1. Wait 10-15 minutes for GCP Load Balancer to provision"
echo "2. Get the load balancer IP:"
echo "   kubectl get ingress falcon-ingress -o jsonpath='{.status.loadBalancer.ingress[0].ip}'"
echo ""
echo "3. Update Cloudflare DNS:"
echo "   - A record: falconmanagerpro.com -> <LOAD_BALANCER_IP>"
echo "   - A record: www.falconmanagerpro.com -> <LOAD_BALANCER_IP>"
echo "   - Set both to 'Proxied' (orange cloud)"
echo ""
echo "4. Enable Full (Strict) TLS in Cloudflare:"
echo "   - Go to SSL/TLS > Overview"
echo "   - Select 'Full (strict)'"
echo ""
echo "5. Monitor certificate provisioning:"
echo "   kubectl describe managedcertificate falcon-managed-cert"
echo ""
