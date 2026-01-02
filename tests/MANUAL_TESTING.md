# Manual Testing Guide for TCP SYN Flood Detector

This document describes manual tests that need to be performed to fully validate the TCP SYN Flood Detector, as some functionality cannot be automated due to system dependencies and network requirements.

## Prerequisites

Before running manual tests, ensure:
- You have root/sudo access (required for network operations)
- `ipset` package is installed
- `iptables` is installed and configured
- The detector is built and installed

## Manual Test Categories

### 1. NFQUEUE Integration Test

**Purpose**: Verify that the detector can capture packets from NFQUEUE

**Requirements**:
- Root access
- Network interface with traffic

**Steps**:
```bash
# 1. Create iptables rule to send SYN packets to NFQUEUE
sudo iptables -I INPUT -p tcp --syn -j NFQUEUE --queue-num 0

# 2. Start the detector
sudo ./build/synflood-detector -c /etc/synflood-detector/synflood-detector.conf

# 3. From another machine, send TCP SYN packets
# Option A: Using hping3
hping3 -S -p 80 -i u10000 <target-ip>

# Option B: Using nmap SYN scan
nmap -sS <target-ip>

# 4. Check detector logs for packet capture
sudo journalctl -u synflood-detector -f

# 5. Cleanup
sudo iptables -D INPUT -p tcp --syn -j NFQUEUE --queue-num 0
```

**Expected Results**:
- Detector should log received SYN packets
- No packet loss errors
- NFQUEUE fd should be valid

**Pass Criteria**:
- [ ] Detector initializes NFQUEUE successfully
- [ ] Packets are captured and processed
- [ ] No kernel buffer overrun errors

---

### 2. IPSet Integration Test

**Purpose**: Verify automatic blocking via ipset

**Requirements**:
- Root access
- ipset installed

**Steps**:
```bash
# 1. Create test ipset
sudo ipset create synflood_blacklist hash:ip timeout 300

# 2. Configure detector to use this ipset (in config file)
# enforcement:
# {
#   ipset_name = "synflood_blacklist";
#   block_duration_s = 60;
# };

# 3. Start detector
sudo ./build/synflood-detector

# 4. Generate SYN flood from a test IP
hping3 -S -p 80 --flood --rand-source <target-ip>
# OR use a single source IP to trigger threshold
hping3 -S -p 80 -i u1000 <target-ip>

# 5. Check if IP is added to ipset
sudo ipset list synflood_blacklist

# 6. Wait for block duration to expire (60 seconds)
# Then check if IP is removed
sudo ipset list synflood_blacklist

# 7. Cleanup
sudo ipset destroy synflood_blacklist
```

**Expected Results**:
- Attacker IP should appear in ipset after exceeding threshold
- IP should be automatically removed after expiry time

**Pass Criteria**:
- [ ] IPs are added to ipset when threshold exceeded
- [ ] IPs are removed from ipset after block duration
- [ ] ipset operations don't fail

---

### 3. /proc/net/tcp Parsing Test

**Purpose**: Verify parsing of TCP connection states from procfs

**Steps**:
```bash
# 1. Note current number of connections
cat /proc/net/tcp | wc -l

# 2. Create some SYN_RECV connections
# On another machine, start SYN flood:
hping3 -S -p 80 --flood <target-ip>

# 3. While flood is running, check /proc/net/tcp
cat /proc/net/tcp | grep "02" | wc -l
# "02" is SYN_RECV state

# 4. Start detector and check logs for SYN_RECV detection
sudo ./build/synflood-detector

# 5. Verify detector logs show SYN_RECV count
sudo journalctl -u synflood-detector | grep SYN_RECV
```

**Expected Results**:
- Detector should correctly parse and count SYN_RECV connections
- Count should correlate with actual connection state

**Pass Criteria**:
- [ ] /proc/net/tcp is parsed without errors
- [ ] SYN_RECV connections are correctly counted
- [ ] No parse errors in logs

---

### 4. Whitelist Functionality Test

**Purpose**: Verify whitelisted IPs are not blocked

**Steps**:
```bash
# 1. Add test IP to whitelist
echo "192.168.1.100/32" >> /etc/synflood-detector/whitelist.conf

# 2. Start detector
sudo ./build/synflood-detector

# 3. From whitelisted IP (192.168.1.100), send SYN flood
hping3 -S -p 80 --flood <target-ip>

# 4. Check logs for whitelist hits
sudo journalctl -u synflood-detector | grep WHITELIST

# 5. Verify IP is NOT in ipset
sudo ipset list synflood_blacklist | grep 192.168.1.100

# 6. From non-whitelisted IP, send SYN flood
hping3 -S -p 80 --flood <target-ip>

# 7. Verify this IP IS blocked
sudo ipset list synflood_blacklist
```

**Expected Results**:
- Whitelisted IP should not be blocked regardless of SYN count
- Non-whitelisted IP should be blocked normally

**Pass Criteria**:
- [ ] Whitelisted IP never appears in ipset
- [ ] Whitelist hits are logged
- [ ] Non-whitelisted IPs are still blocked

---

### 5. Metrics Socket Test

**Purpose**: Verify metrics are exported via Unix socket

**Steps**:
```bash
# 1. Start detector with metrics enabled
sudo ./build/synflood-detector

# 2. Check that metrics socket is created
ls -la /var/run/synflood-detector.sock

# 3. Query metrics
echo "GET" | sudo nc -U /var/run/synflood-detector.sock

# 4. Generate some traffic and re-query
hping3 -S -p 80 -c 1000 <target-ip>
echo "GET" | sudo nc -U /var/run/synflood-detector.sock

# 5. Verify metrics are updated
```

**Expected Results**:
- Socket is created successfully
- Metrics are returned in Prometheus format
- Metrics update in real-time

**Pass Criteria**:
- [ ] Metrics socket is created
- [ ] Metrics can be queried
- [ ] Counters increment correctly

---

### 6. Signal Handling Test

**Purpose**: Verify graceful shutdown on signals

**Steps**:
```bash
# 1. Start detector
sudo ./build/synflood-detector

# 2. Send SIGTERM
sudo pkill -TERM synflood-detector

# 3. Check logs for graceful shutdown
sudo journalctl -u synflood-detector | tail -20

# 4. Verify cleanup (no stale NFQUEUE, sockets, etc.)
ls -la /var/run/synflood-detector.sock  # Should not exist
```

**Expected Results**:
- Detector shuts down cleanly
- All resources are released
- No error messages on shutdown

**Pass Criteria**:
- [ ] Graceful shutdown message logged
- [ ] No resource leaks
- [ ] Clean exit code

---

### 7. Performance Test

**Purpose**: Verify detector can handle high packet rate

**Requirements**:
- High-speed network interface
- Packet generator (hping3, pktgen, or similar)

**Steps**:
```bash
# 1. Start detector
sudo ./build/synflood-detector

# 2. Monitor CPU and memory usage
top -p $(pidof synflood-detector)

# 3. Generate high-rate SYN packets
# Target: 50,000 PPS (as per NFR requirements)
hping3 -S -p 80 --flood --faster <target-ip>

# 4. Check metrics for:
#    - Packet processing rate
#    - CPU usage (should be <5%)
#    - Memory usage (should be <50MB)
#    - Detection latency (should be <100ms)

# 5. Query metrics
echo "GET" | sudo nc -U /var/run/synflood-detector.sock | grep -E "(cpu|memory|latency)"
```

**Expected Results**:
- CPU usage < 5%
- Memory usage < 50 MB
- Detection latency < 100 ms (p99)
- No packet drops

**Pass Criteria**:
- [ ] Handles 50,000 PPS without packet loss
- [ ] CPU usage within limits
- [ ] Memory usage within limits
- [ ] Latency within SLA

---

### 8. Configuration Reload Test (SIGHUP)

**Purpose**: Verify configuration can be reloaded without restart

**Steps**:
```bash
# 1. Start detector
sudo ./build/synflood-detector

# 2. Modify configuration
sudo nano /etc/synflood-detector/synflood-detector.conf
# Change syn_threshold from 100 to 200

# 3. Send SIGHUP
sudo pkill -HUP synflood-detector

# 4. Check logs for reload message
sudo journalctl -u synflood-detector | grep reload

# 5. Verify new threshold is in effect
# Send 150 SYNs (should not trigger with threshold=200)
hping3 -S -p 80 -c 150 -i u10000 <target-ip>
```

**Expected Results**:
- Configuration reloads without stopping detector
- New settings take effect immediately

**Pass Criteria**:
- [ ] SIGHUP triggers configuration reload
- [ ] New threshold is active
- [ ] No service interruption

---

### 9. False Positive Test

**Purpose**: Verify legitimate traffic is not blocked

**Steps**:
```bash
# 1. Start detector with threshold = 100 SYNs/second

# 2. Simulate legitimate web server traffic
# Run Apache benchmark with normal connection rate
ab -n 50 -c 5 http://<target-ip>/

# 3. Check that no IPs are blocked
sudo ipset list synflood_blacklist

# 4. Simulate legitimate high-volume traffic
# Multiple users connecting normally
for i in {1..50}; do
    curl -s http://<target-ip>/ > /dev/null &
done

# 5. Verify no false positives
sudo journalctl -u synflood-detector | grep BLOCKED
```

**Expected Results**:
- Normal traffic patterns should not trigger blocking
- SYN count should reset properly in time windows

**Pass Criteria**:
- [ ] No legitimate traffic is blocked
- [ ] False positive rate < 0.1%

---

### 10. Multi-Source Attack Test

**Purpose**: Verify detector handles distributed attacks

**Steps**:
```bash
# 1. Start detector

# 2. From 5+ different source IPs, send SYN floods simultaneously
# (Requires multiple test machines or spoofed sources)

# 3. Check that all attacking IPs are detected and blocked
sudo ipset list synflood_blacklist

# 4. Verify metrics show multiple blocked IPs
echo "GET" | sudo nc -U /var/run/synflood-detector.sock | grep blocked_ips
```

**Expected Results**:
- All attacking sources are detected independently
- Each is blocked according to policy

**Pass Criteria**:
- [ ] Multiple attackers detected simultaneously
- [ ] Each attacker tracked independently
- [ ] No cross-contamination of counters

---

## Test Reporting Template

After completing manual tests, fill out:

```
Test Date: _______________
Tester: _______________
System: _______________
Kernel Version: _______________

Test Results:
1. NFQUEUE Integration:    [PASS/FAIL] _______________
2. IPSet Integration:       [PASS/FAIL] _______________
3. /proc Parsing:           [PASS/FAIL] _______________
4. Whitelist:               [PASS/FAIL] _______________
5. Metrics Socket:          [PASS/FAIL] _______________
6. Signal Handling:         [PASS/FAIL] _______________
7. Performance:             [PASS/FAIL] _______________
8. Config Reload:           [PASS/FAIL] _______________
9. False Positives:         [PASS/FAIL] _______________
10. Multi-Source Attack:    [PASS/FAIL] _______________

Notes:
_______________________________________________________
_______________________________________________________
```

## Troubleshooting Manual Tests

### Common Issues

**NFQUEUE errors**:
```bash
# Check NFQUEUE kernel module
lsmod | grep nfnetlink_queue
# If not loaded:
sudo modprobe nfnetlink_queue
```

**IPSet errors**:
```bash
# Check ipset is installed
ipset version
# Check kernel module
lsmod | grep ip_set
```

**Permission errors**:
```bash
# Ensure running as root
sudo -i
# Or check capabilities
getcap ./build/synflood-detector
```

**No traffic captured**:
```bash
# Verify iptables rule is active
sudo iptables -L -n -v | grep NFQUEUE
# Check queue number matches config
```
