# Whitelist Templates and Best Practices

This guide provides comprehensive whitelist templates for common scenarios and explains why certain IPs should be whitelisted.

## Table of Contents

- [Quick Start](#quick-start)
- [Common Scenarios](#common-scenarios)
- [Service-Specific Templates](#service-specific-templates)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### What is Whitelisting?

Whitelisting tells the TCP SYN Flood Detector to **never block** specific IP addresses or ranges, even if they exceed the SYN packet threshold. This prevents false positives for legitimate high-traffic sources.

### When to Whitelist

✅ **DO whitelist:**
- Your own IP addresses (office, home, VPN)
- Load balancers and reverse proxies
- Monitoring and uptime services
- CI/CD runners and automation tools
- Payment processor webhooks
- Legitimate high-traffic API consumers

❌ **DON'T whitelist:**
- Unknown IPs "just in case"
- Large public IP ranges
- IPs that only access your site occasionally
- Dynamic residential IPs (they change frequently)

### Basic Commands

```bash
# Add an IP to whitelist
sudo synflood-ctl whitelist add 203.0.113.50

# Add a CIDR range
sudo synflood-ctl whitelist add 10.0.0.0/24

# List current whitelist
sudo synflood-ctl whitelist list

# Remove an entry
sudo synflood-ctl whitelist remove 203.0.113.50

# Edit whitelist file directly
sudo synflood-ctl whitelist edit

# After editing, reload configuration
sudo synflood-ctl reload
```

---

## Common Scenarios

### Scenario 1: Preventing Self-Lockout

**Problem:** You configure aggressive detection settings and accidentally block yourself.

**Solution:** Always whitelist your own IPs first:

```conf
# Find your current IP
# Run: curl ifconfig.me

# Your office static IP
203.0.113.50

# Your home IP (if static)
198.51.100.25

# Your VPN endpoint
192.0.2.100/32

# Office network range
10.1.0.0/16
```

**Why it matters:** Getting locked out requires console access or IPMI to recover. Prevention is key.

### Scenario 2: Behind a Load Balancer

**Problem:** All traffic appears to come from your load balancer's IP, which quickly exceeds the SYN threshold.

**Solution:** Whitelist load balancer IPs:

```conf
# AWS ELB
52.1.2.3
52.1.2.4

# Or entire VPC CIDR if using internal load balancer
10.0.0.0/16

# GCP Load Balancer health check ranges
35.191.0.0/16
130.211.0.0/22

# Azure Load Balancer health probe
168.63.129.16
```

**Why it matters:** Without whitelisting, the detector sees one IP (the load balancer) sending hundreds of SYN packets per second from legitimate users, triggering false blocks.

**Important:** If you're behind a load balancer, make sure your application logs the real client IP using headers like `X-Forwarded-For`. The SYN flood detector operates at the network layer and only sees the load balancer's IP.

### Scenario 3: Cloudflare or CDN

**Problem:** Your site is behind Cloudflare/CDN, so all requests appear to come from CDN edge servers.

**Solution:** Whitelist CDN IP ranges:

**Cloudflare (all IPv4 ranges):**
```conf
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
```

**Get current ranges:**
```bash
# Cloudflare
curl https://www.cloudflare.com/ips-v4

# Fastly
curl https://api.fastly.com/public-ip-list

# AWS CloudFront
curl https://ip-ranges.amazonaws.com/ip-ranges.json | jq -r '.prefixes[] | select(.service=="CLOUDFRONT") | .ip_prefix'
```

**Why it matters:** CDN edge servers make thousands of connections on behalf of your users. Blocking them blocks your entire site for all users.

**Trade-off:** Whitelisting CDN IPs means attacks can come through the CDN. Ensure your CDN has DDoS protection enabled (Cloudflare does by default).

### Scenario 4: Monitoring Services

**Problem:** Uptime monitors like Pingdom or UptimeRobot make frequent health checks, triggering false positives.

**Solution:** Whitelist monitoring service IPs:

**Pingdom (example ranges):**
```conf
# North America
50.16.153.192/26
64.237.55.0/24
72.46.140.0/24

# Europe
85.195.116.0/23
94.247.174.0/23
178.162.206.0/23

# Asia-Pacific
43.225.198.0/23
103.47.211.0/24

# Full list: https://documentation.pingdom.com/probe-servers/
```

**UptimeRobot:**
```conf
63.143.42.242
63.143.42.243
63.143.42.244
63.143.42.245
63.143.42.246
```

**Why it matters:** Monitoring services check your site every 1-5 minutes from multiple locations. Over a detection window, this can trigger thresholds, causing downtime alerts for successfully "blocked" checkers.

### Scenario 5: CI/CD Pipelines

**Problem:** GitHub Actions, GitLab CI, or Jenkins runners trigger deployments and health checks that exceed thresholds.

**Solution:** Whitelist CI/CD runner IPs:

```conf
# GitHub Actions (dynamic - get from API)
# curl https://api.github.com/meta | jq -r '.actions[]'
# Example ranges (check API for current):
13.64.0.0/16
20.33.0.0/16

# Self-hosted Jenkins
198.51.100.50

# GitLab.com (varies by region)
# Check: https://docs.gitlab.com/ee/user/gitlab_com/
```

**Why it matters:** Deployment scripts often:
- Run health checks in loops
- Make many API calls during deployment
- Execute integration tests that create connections

Without whitelisting, deployments can block their own IPs mid-deployment.

### Scenario 6: Payment Webhooks

**Problem:** Stripe, PayPal, or other payment processors send webhooks that get blocked, causing missed payment notifications.

**Solution:** Whitelist payment processor IPs:

**Stripe:**
```conf
3.18.12.0/22
3.130.192.0/22
13.52.14.0/25
18.179.48.0/20
35.154.171.0/24
```

**PayPal IPN:**
```conf
64.4.240.0/20
66.211.168.0/22
147.75.0.0/16
173.0.80.0/20
216.113.160.0/19
```

**Why it matters:** Missing payment webhooks can cause:
- Orders marked as unpaid when they're actually paid
- Subscription renewals not processing
- Refund notifications not received
- Audit/compliance issues

**Verification:** Most payment processors provide webhook signing/verification. Always verify webhook signatures in your application code, even if IPs are whitelisted.

### Scenario 7: API Partners

**Problem:** High-volume API partners (e.g., mobile apps, data feeds) exceed thresholds.

**Solution:** Whitelist known partner IPs:

```conf
# Partner 1: Mobile App Backend
# Contact: partner1@example.com
# Added: 2024-01-15
203.0.113.0/24

# Partner 2: Analytics Service
# Contact: partner2@example.com
# Added: 2024-01-20
198.51.100.50
198.51.100.51
```

**Why it matters:** Legitimate high-volume API consumers should be whitelisted to ensure service availability.

**Best practice:**
- Document each partner (contact, date added, purpose)
- Periodically review and remove inactive partners
- Consider rate limiting in your application layer instead

---

## Service-Specific Templates

### AWS Infrastructure

```conf
# EC2 instances in your VPC
10.0.0.0/16

# Elastic Load Balancer (get IPs from DNS)
# dig +short your-elb.region.elb.amazonaws.com
52.1.2.3
52.1.2.4

# CloudFront distributions (if origin is your server)
# Get from: https://ip-ranges.amazonaws.com/ip-ranges.json
# Filter: service == "CLOUDFRONT"
```

**Get AWS IP ranges:**
```bash
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | \
  jq -r '.prefixes[] | select(.service=="CLOUDFRONT") | .ip_prefix' | \
  head -20
```

### Google Cloud Platform

```conf
# GCP Load Balancer health checks (required)
35.191.0.0/16
130.211.0.0/22

# GCP Cloud CDN
# Contact GCP support for current ranges

# GKE cluster nodes (if applicable)
# Get from: kubectl get nodes -o wide
10.128.0.0/9
```

### Azure

```conf
# Azure Load Balancer health probe source (required)
168.63.129.16

# Application Gateway (if used)
# Get from Azure portal

# Azure Front Door
# Get ranges from: https://www.microsoft.com/download/details.aspx?id=56519
```

### Kubernetes/Docker

```conf
# Docker default bridge network
172.17.0.0/16

# Kubernetes pod network (example)
10.244.0.0/16

# Kubernetes service network (example)
10.96.0.0/12

# Adjust based on your CNI plugin (Calico, Flannel, etc.)
```

**Warning:** Only whitelist container networks if your detector is running on the host network and needs to allow traffic from containers.

---

## Best Practices

### 1. Start Small, Expand as Needed

Begin with only essential IPs:
```conf
127.0.0.1        # Localhost
127.0.0.0/8      # Localhost range
YOUR_IP          # Your own IP
LOAD_BALANCER_IP # If applicable
```

Add more IPs only when you see false positives in logs:
```bash
sudo synflood-ctl logs events | grep "blocked"
```

### 2. Use the Smallest CIDR Range Possible

❌ **Too broad:**
```conf
0.0.0.0/0        # Whitelists entire internet (disables protection!)
10.0.0.0/8       # Entire Class A (16M IPs)
```

✅ **Appropriate:**
```conf
10.0.1.0/24      # Your specific subnet (256 IPs)
203.0.113.50/32  # Single IP (/32 is explicit)
```

**CIDR quick reference:**
- `/32` = 1 IP (single host)
- `/24` = 256 IPs (typical subnet)
- `/16` = 65,536 IPs (large network)
- `/8` = 16,777,216 IPs (very large network)

### 3. Document Everything

Use comments to explain each entry:
```conf
# -------------------------
# Production Load Balancers
# -------------------------
# Added: 2024-01-15
# Contact: devops@example.com
# Purpose: AWS ELB for production app
# Review date: 2024-04-15 (quarterly)
52.1.2.3
52.1.2.4

# -------------------------
# Monitoring - Pingdom
# -------------------------
# Added: 2024-01-16
# Account: ops@example.com
# Purpose: Uptime monitoring from NA probes
64.237.55.0/24
```

### 4. Regular Audits

Create a maintenance schedule:

**Monthly:**
- Review blocked IPs for patterns: `sudo synflood-ctl blocked list`
- Check for legitimate IPs being blocked
- Review whitelist hit count: `sudo synflood-ctl status`

**Quarterly:**
- Audit entire whitelist file
- Remove entries for decommissioned services
- Verify service IP ranges haven't changed
- Test that protection still works

**Annual:**
- Full security review
- Update third-party IP ranges (CDNs, monitoring, etc.)
- Document changes and lessons learned

### 5. Use Version Control

Track whitelist changes in git:

```bash
cd /etc/synflood-detector
sudo git init
sudo git add whitelist.conf
sudo git commit -m "Initial whitelist configuration"

# After changes
sudo git diff whitelist.conf
sudo git add whitelist.conf
sudo git commit -m "Added Stripe webhook IPs for payment processing"
```

### 6. Test Before and After

**Before whitelisting:**
```bash
# Verify IP is currently blocked or would be blocked
sudo synflood-ctl blocked test 203.0.113.50
```

**After whitelisting:**
```bash
# Verify IP is in whitelist
sudo synflood-ctl whitelist list | grep 203.0.113.50

# Check whitelist hits in metrics
sudo synflood-ctl status | grep -i whitelist
```

### 7. Monitor Whitelist Effectiveness

Track how often whitelisted IPs are checked:

```bash
# View whitelist hits
sudo synflood-ctl metrics | grep whitelist_hits

# Check logs for whitelist activity
sudo synflood-ctl logs | grep -i whitelist
```

If a whitelisted IP rarely appears in logs, consider if it's still needed.

### 8. Layered Security

**Don't rely solely on whitelisting:**
- Use application-level rate limiting (nginx limit_req, etc.)
- Implement authentication and authorization
- Enable CDN DDoS protection
- Use WAF (Web Application Firewall) for application-layer attacks
- Monitor application logs for abuse

**Defense in depth:**
```
Internet
  ↓
CDN/DDoS Protection (Cloudflare, Akamai)
  ↓
Firewall (ufw, iptables)
  ↓
SYN Flood Detector (this tool)
  ↓
Application Rate Limiting (nginx, app code)
  ↓
Your Application
```

### 9. Emergency Access Plan

If you get locked out:

**Option 1: Out-of-band access**
```bash
# Via console/IPMI/serial
sudo systemctl stop synflood-detector
```

**Option 2: Manual unblock**
```bash
# Via SSH from another IP
sudo ipset del synflood_blacklist YOUR_IP
```

**Option 3: Add to whitelist remotely**
```bash
# Via configuration management (Ansible, etc.)
echo "YOUR_IP" | sudo tee -a /etc/synflood-detector/whitelist.conf
sudo systemctl reload synflood-detector
```

**Prevention:**
- Always test from a whitelisted IP first
- Keep a secondary access method (VPN, jump host)
- Document recovery procedures

---

## Troubleshooting

### Issue: Whitelisted IP Still Getting Blocked

**Possible causes:**
1. Whitelist file has syntax errors
2. Configuration wasn't reloaded after editing
3. IP is in ipset blacklist from before whitelisting

**Solutions:**
```bash
# Check whitelist syntax
sudo synflood-ctl whitelist list

# Verify IP is in whitelist
grep -i "203.0.113.50" /etc/synflood-detector/whitelist.conf

# Reload configuration
sudo synflood-ctl reload

# Manually remove from blacklist
sudo synflood-ctl blocked remove 203.0.113.50

# Check service logs
sudo synflood-ctl logs | grep "203.0.113.50"
```

### Issue: Too Many IPs in Whitelist

**Problem:** Large whitelist reduces protection effectiveness.

**Solution:** Audit and categorize:
```bash
# Count whitelist entries
sudo synflood-ctl whitelist list | grep -vE '^\s*#|^\s*$' | wc -l

# Review each category
# Ask: Do we still need this?
# Ask: Can we use application-level controls instead?
```

**Rule of thumb:** If your whitelist has >100 entries, reconsider your approach. Consider:
- Moving protection to application layer
- Using a CDN with DDoS protection
- Segmenting services (separate detector per service)

### Issue: Dynamic IPs Need Whitelisting

**Problem:** Service uses dynamic IPs (e.g., GitHub Actions, some CDNs).

**Solutions:**

**Option 1: Use provider's IP API**
```bash
# GitHub Actions IPs
curl https://api.github.com/meta | jq -r '.actions[]' > /tmp/github-ips.txt
sudo synflood-ctl whitelist add < /tmp/github-ips.txt
```

**Option 2: Automate with cron**
```bash
#!/bin/bash
# /etc/cron.daily/update-whitelist
curl -s https://api.github.com/meta | \
  jq -r '.actions[]' | \
  while read ip; do
    sudo synflood-ctl whitelist add "$ip" 2>/dev/null || true
  done
sudo synflood-ctl reload
```

**Option 3: Use authentication instead**
- API keys
- OAuth tokens
- mTLS client certificates

### Issue: Service IP Ranges Changed

**Problem:** Third-party service changed IPs, now getting blocked.

**Prevention:**
```bash
# Subscribe to service status pages
# Examples:
# - GitHub: https://www.githubstatus.com/
# - Stripe: https://status.stripe.com/
# - Cloudflare: https://www.cloudflarestatus.com/

# Set up monitoring
# Check whitelist against known-good sources
# Alert on unexpected blocks
```

**Recovery:**
```bash
# Check recent blocks for new IPs
sudo synflood-ctl blocked list

# Cross-reference with service documentation
# Add new IPs
sudo synflood-ctl whitelist add NEW_IP

# Remove old IPs
sudo synflood-ctl whitelist remove OLD_IP
```

---

## Quick Reference Card

### Essential Commands

```bash
# Add IP
sudo synflood-ctl whitelist add <ip>

# Add CIDR
sudo synflood-ctl whitelist add <cidr>

# List all
sudo synflood-ctl whitelist list

# Remove
sudo synflood-ctl whitelist remove <ip>

# Edit file
sudo synflood-ctl whitelist edit

# Reload config
sudo synflood-ctl reload

# Check if IP is whitelisted
grep <ip> /etc/synflood-detector/whitelist.conf
```

### Must-Whitelist Checklist

- [ ] Localhost (127.0.0.1, 127.0.0.0/8)
- [ ] Your own IPs (office, home, VPN)
- [ ] Load balancer IPs
- [ ] CDN edge servers (if applicable)
- [ ] Monitoring service IPs
- [ ] Payment webhook IPs
- [ ] CI/CD runner IPs

### Verification Checklist

After whitelisting:
- [ ] IP appears in: `sudo synflood-ctl whitelist list`
- [ ] Config reloaded: `sudo synflood-ctl reload`
- [ ] IP not in blocklist: `sudo synflood-ctl blocked test <ip>`
- [ ] Documented in file with comments
- [ ] Added to version control (if using)
- [ ] Tested that IP can access service

---

## Additional Resources

- **Configuration file:** `/etc/synflood-detector/whitelist.conf`
- **Main documentation:** `/usr/local/share/doc/synflood-detector/`
- **Command reference:** `synflood-ctl help`
- **GitHub repository:** https://github.com/Hetti219/TCP-SYN-Flood-Detector

---

## Example: Complete Production Whitelist

Here's a fully documented example for a typical web application:

```conf
# ============================================================================
# Production Whitelist - example.com
# Last updated: 2024-01-20
# Maintained by: devops@example.com
# Review schedule: Quarterly (next: 2024-04-20)
# ============================================================================

# ----------------------------------------------------------------------------
# Localhost (required)
# ----------------------------------------------------------------------------
127.0.0.1
127.0.0.0/8

# ----------------------------------------------------------------------------
# Company Infrastructure
# ----------------------------------------------------------------------------
# Office network
# Added: 2024-01-15
# Contact: it@example.com
203.0.113.0/24

# VPN endpoint
# Added: 2024-01-15
198.51.100.10

# ----------------------------------------------------------------------------
# AWS Production Infrastructure
# ----------------------------------------------------------------------------
# VPC CIDR - EC2 instances
# Added: 2024-01-15
# VPC: vpc-abc123
10.0.0.0/16

# Production ALB
# Added: 2024-01-15
# dig +short prod-alb-123456.us-east-1.elb.amazonaws.com
52.1.2.3
52.1.2.4

# ----------------------------------------------------------------------------
# Cloudflare CDN
# ----------------------------------------------------------------------------
# Added: 2024-01-16
# Account: cdn@example.com
# All Cloudflare IPv4 ranges
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22

# ----------------------------------------------------------------------------
# Monitoring - Pingdom
# ----------------------------------------------------------------------------
# Added: 2024-01-16
# Account: monitoring@example.com
# North America probes only
50.16.153.192/26
64.237.55.0/24
72.46.140.0/24

# ----------------------------------------------------------------------------
# Payment Processing - Stripe
# ----------------------------------------------------------------------------
# Added: 2024-01-17
# Account: payments@example.com
# Purpose: Webhook notifications
# Docs: https://stripe.com/docs/ips
3.18.12.0/22
3.130.192.0/22
13.52.14.0/25

# ----------------------------------------------------------------------------
# CI/CD - GitHub Actions
# ----------------------------------------------------------------------------
# Added: 2024-01-18
# Purpose: Deployment health checks
# Update script: /opt/scripts/update-github-ips.sh (cron.daily)
# Note: IPs managed automatically, see script
# [Auto-populated by script]

# ----------------------------------------------------------------------------
# API Partners
# ----------------------------------------------------------------------------
# Partner: MobileApp Inc
# Added: 2024-01-19
# Contact: partners@mobileapp.example
# Contract: Until 2025-12-31
# Review: 2024-12-01
192.0.2.0/24

# ============================================================================
# Maintenance Log
# ============================================================================
# 2024-01-20: Initial production whitelist created
# 2024-01-19: Added MobileApp partner IPs
# 2024-01-18: Added GitHub Actions automation
# 2024-01-17: Added Stripe webhook IPs
# 2024-01-16: Added Pingdom and Cloudflare
# 2024-01-15: Created initial infrastructure whitelist
# ============================================================================
```

This template demonstrates best practices: categorization, documentation, contact information, review dates, and a maintenance log.
