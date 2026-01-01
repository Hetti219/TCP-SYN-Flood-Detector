# TCP SYN Flood Detector - Troubleshooting Guide

## Common Issues and Solutions

### Service Won't Start

#### Symptom
```bash
sudo systemctl start synflood-detector
# Returns error or fails silently
```

#### Solutions

1. **Check service status**:
```bash
sudo systemctl status synflood-detector
sudo journalctl -u synflood-detector -n 50
```

2. **Verify dependencies**:
```bash
# Check if ipset is available
which ipset

# Check if iptables is available
which iptables

# Verify kernel modules
lsmod | grep nf_queue
lsmod | grep ip_set
```

3. **Check permissions**:
```bash
# Verify capabilities
getcap /usr/local/bin/synflood-detector

# Should show: cap_net_admin,cap_net_raw+ep
# If not:
sudo setcap cap_net_admin,cap_net_raw+ep /usr/local/bin/synflood-detector
```

4. **Verify configuration syntax**:
```bash
# Test configuration file
sudo synflood-detector -c /etc/synflood-detector/synflood-detector.conf
```

### High False Positive Rate

#### Symptom
Legitimate users are being blocked frequently.

#### Solutions

1. **Increase detection threshold**:
```
detection = {
    syn_threshold = 200;  # Increase from default 100
    window_ms = 2000;     # Increase from default 1000
};
```

2. **Add to whitelist**:
```bash
sudo nano /etc/synflood-detector/whitelist.conf
# Add IP or CIDR of legitimate high-traffic sources
```

3. **Review metrics**:
```bash
echo "GET /metrics" | socat - UNIX:/var/run/synflood-detector.sock | grep false_positives
```

4. **Check logs for patterns**:
```bash
sudo journalctl -u synflood-detector | grep SUSPICIOUS
```

### Attacks Not Being Detected

#### Symptom
Known SYN flood attacks are not triggering blocks.

#### Solutions

1. **Verify iptables rules**:
```bash
sudo iptables -L INPUT -n --line-numbers | grep -E "NFQUEUE|synflood"

# Should show:
# 1. NFQUEUE rule for SYN packets
# 2. DROP rule for synflood_blacklist

# If missing, add manually:
sudo iptables -I INPUT -p tcp --syn -j NFQUEUE --queue-num 0
sudo iptables -I INPUT -m set --match-set synflood_blacklist src -j DROP
```

2. **Decrease detection threshold**:
```
detection = {
    syn_threshold = 50;   # Decrease from default 100
    window_ms = 1000;     # Keep at default
};
```

3. **Check if packets are reaching NFQUEUE**:
```bash
# Monitor iptables counter
sudo iptables -L INPUT -n -v | grep NFQUEUE

# Counter should increase during attacks
```

4. **Verify daemon is running**:
```bash
sudo systemctl status synflood-detector
ps aux | grep synflood-detector
```

### High CPU Usage

#### Symptom
synflood-detector process consuming excessive CPU.

#### Solutions

1. **Reduce /proc validation frequency**:
```
detection = {
    proc_check_interval_s = 30;  # Increase from default 5
};
```

2. **Optimize hash table**:
```
limits = {
    hash_buckets = 8192;  # Increase if many collisions
};
```

3. **Check for attack in progress**:
```bash
# Monitor packet rate
echo "GET /metrics" | socat - UNIX:/var/run/synflood-detector.sock | grep packets_total

# High packet rate is expected during attacks
```

4. **Profile the application**:
```bash
# Using perf
sudo perf record -g -p $(pgrep synflood-detector)
# Wait 10 seconds, then Ctrl+C
sudo perf report
```

### High Memory Usage

#### Symptom
synflood-detector consuming too much memory.

#### Solutions

1. **Reduce tracking limits**:
```
limits = {
    max_tracked_ips = 5000;  # Decrease from default 10000
    hash_buckets = 2048;     # Decrease from default 4096
};
```

2. **Check for memory leak**:
```bash
# Monitor memory over time
watch -n 5 'ps aux | grep synflood-detector | grep -v grep'

# If continuously increasing, may be a bug - report on GitHub
```

3. **Verify LRU eviction is working**:
```bash
sudo journalctl -u synflood-detector | grep "Evicted LRU"
```

### ipset Errors

#### Symptom
Errors related to ipset operations:
```
Failed to add IP to ipset
ipset add failed
```

#### Solutions

1. **Verify ipset exists**:
```bash
sudo ipset list synflood_blacklist

# If doesn't exist:
sudo ipset create synflood_blacklist hash:ip timeout 300 maxelem 65536
```

2. **Check ipset capacity**:
```bash
sudo ipset list synflood_blacklist | grep -E "^Size|^References|^Number"

# If near maxelem, increase:
sudo ipset destroy synflood_blacklist
sudo ipset create synflood_blacklist hash:ip timeout 300 maxelem 131072
```

3. **Verify kernel modules**:
```bash
lsmod | grep ip_set
# If not loaded:
sudo modprobe ip_set
sudo modprobe ip_set_hash_ip
```

### Metrics Socket Not Working

#### Symptom
Cannot query metrics via Unix socket.

#### Solutions

1. **Check socket exists**:
```bash
ls -la /var/run/synflood-detector.sock

# If doesn't exist, check logs:
sudo journalctl -u synflood-detector | grep metrics
```

2. **Verify permissions**:
```bash
# Socket should be readable
sudo chmod 666 /var/run/synflood-detector.sock
```

3. **Test with socat**:
```bash
# If socat not installed:
sudo apt install socat

# Query metrics:
echo "GET /metrics" | socat - UNIX:/var/run/synflood-detector.sock
```

### NFQUEUE Errors

#### Symptom
```
Failed to open nfqueue library handle
Failed to create nfqueue
```

#### Solutions

1. **Check kernel module**:
```bash
lsmod | grep nfnetlink_queue

# If not loaded:
sudo modprobe nfnetlink_queue
```

2. **Verify another process isn't using the queue**:
```bash
# Only one process can attach to a NFQUEUE number
sudo lsof | grep nfnetlink

# If another process is using it, either:
# - Stop that process
# - Use a different queue number in config
```

3. **Use raw socket fallback**:
```
capture = {
    use_raw_socket = true;
};
```

### Logs Not Appearing

#### Symptom
No logs in journalctl or expected log location.

#### Solutions

1. **Check systemd journal**:
```bash
sudo journalctl -u synflood-detector -f
```

2. **Verify log level**:
```
logging = {
    level = "info";  # Or "debug" for more verbosity
};
```

3. **Check if syslog is enabled**:
```
logging = {
    syslog = true;
};
```

4. **Run in foreground for debugging**:
```bash
sudo /usr/local/bin/synflood-detector -c /etc/synflood-detector/synflood-detector.conf
# Logs will appear on stderr
```

## Debugging Techniques

### Enable Debug Logging

Edit configuration:
```
logging = {
    level = "debug";
};
```

Restart service:
```bash
sudo systemctl restart synflood-detector
sudo journalctl -u synflood-detector -f
```

### Monitor in Real-Time

```bash
# Watch metrics
watch -n 1 'echo "GET /metrics" | socat - UNIX:/var/run/synflood-detector.sock'

# Watch ipset
watch -n 1 'sudo ipset list synflood_blacklist | tail -20'

# Watch logs
sudo journalctl -u synflood-detector -f
```

### Test with Simulated Attack

```bash
# Using hping3 to simulate SYN flood
sudo hping3 -S -p 80 -i u1000 --rand-source <target_ip>

# Monitor detection
sudo journalctl -u synflood-detector -f
```

### Memory Profiling

```bash
# Using valgrind
sudo systemctl stop synflood-detector
sudo valgrind --leak-check=full --show-leak-kinds=all \
    /usr/local/bin/synflood-detector -c /etc/synflood-detector/synflood-detector.conf
```

### Performance Analysis

```bash
# CPU profiling with perf
sudo perf record -g -p $(pgrep synflood-detector) -- sleep 30
sudo perf report

# System call tracing
sudo strace -p $(pgrep synflood-detector) -f -e trace=network
```

## Performance Benchmarks

Expected performance on modest hardware (2 CPU cores, 2GB RAM):

- **Packet Processing Rate**: 50,000+ SYN packets/second
- **Detection Latency**: < 100ms from packet arrival to ipset insertion
- **CPU Usage (idle)**: < 1%
- **CPU Usage (under attack)**: < 5%
- **Memory Usage**: 10-50MB depending on tracked IPs

If your system significantly underperforms these benchmarks, review configuration and system resources.

## Getting Help

If you're still experiencing issues:

1. **Collect diagnostic information**:
```bash
# System info
uname -a
cat /etc/os-release

# Service status
sudo systemctl status synflood-detector

# Recent logs
sudo journalctl -u synflood-detector -n 100 --no-pager

# Configuration
cat /etc/synflood-detector/synflood-detector.conf

# iptables rules
sudo iptables -L INPUT -n -v

# ipset status
sudo ipset list synflood_blacklist

# Metrics
echo "GET /metrics" | socat - UNIX:/var/run/synflood-detector.sock
```

2. **Report issue on GitHub** with collected information

3. **Check documentation**:
   - [INSTALL.md](INSTALL.md)
   - [CONFIGURATION.md](CONFIGURATION.md)
   - README.md

## Known Limitations

1. **IPv6 Support**: Currently only IPv4 is supported. IPv6 support is planned for future versions.

2. **Distributed Attacks**: Detection is per-IP. Distributed attacks from many IPs below threshold may not be detected.

3. **State Synchronization**: No support for multi-node deployment with shared state.

4. **Configuration Reload**: SIGHUP handler exists but hot-reload not yet implemented. Requires service restart.

5. **Performance**: /proc/net/tcp parsing can be expensive under very high connection counts (100k+ connections).

## See Also

- [INSTALL.md](INSTALL.md) - Installation instructions
- [CONFIGURATION.md](CONFIGURATION.md) - Configuration options
