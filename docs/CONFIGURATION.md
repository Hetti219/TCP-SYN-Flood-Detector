# TCP SYN Flood Detector - Configuration Guide

## Configuration File Location

Default: `/etc/synflood-detector/synflood-detector.conf`

Custom path can be specified with the `-c` option:
```bash
synflood-detector -c /path/to/custom/config.conf
```

## Configuration Format

The configuration file uses libconfig syntax (similar to JSON/C).

## Configuration Sections

### Detection Parameters

```
detection = {
    syn_threshold = 100;
    window_ms = 1000;
    proc_check_interval_s = 5;
};
```

#### syn_threshold
- **Type**: Integer (1 - 1000000)
- **Default**: 100
- **Description**: Number of SYN packets from a single IP within the detection window that triggers an alert
- **Tuning**:
  - Lower values (50-100): More sensitive, may increase false positives
  - Higher values (200-500): Less sensitive, may miss low-rate attacks
  - Very high values (1000+): Only detect aggressive attacks

#### window_ms
- **Type**: Integer (1 - 60000 milliseconds)
- **Default**: 1000
- **Description**: Time window for counting SYN packets
- **Tuning**:
  - Shorter windows (500-1000ms): Faster detection but less tolerant of bursts
  - Longer windows (2000-5000ms): More tolerant of legitimate traffic patterns

#### proc_check_interval_s
- **Type**: Integer (1 - 3600 seconds)
- **Default**: 5
- **Description**: How often to validate detections by checking /proc/net/tcp
- **Tuning**:
  - Lower values (1-3s): More accurate validation, higher CPU usage
  - Higher values (10-30s): Less CPU usage, slower validation

### Enforcement Parameters

```
enforcement = {
    block_duration_s = 300;
    ipset_name = "synflood_blacklist";
};
```

#### block_duration_s
- **Type**: Integer (1 - 86400 seconds)
- **Default**: 300 (5 minutes)
- **Description**: How long to block an offending IP address
- **Tuning**:
  - Short duration (60-300s): Quick recovery for false positives
  - Medium duration (600-1800s): Balance between protection and accessibility
  - Long duration (3600-86400s): Aggressive blocking for persistent attackers

#### ipset_name
- **Type**: String
- **Default**: "synflood_blacklist"
- **Description**: Name of the ipset to use for blacklisting
- **Note**: Must match the ipset created by systemd service or manually

### Resource Limits

```
limits = {
    max_tracked_ips = 10000;
    hash_buckets = 4096;
};
```

#### max_tracked_ips
- **Type**: Integer (1 - 10000000)
- **Default**: 10000
- **Description**: Maximum number of IP addresses to track simultaneously
- **Memory Impact**: ~80 bytes per tracked IP
- **Tuning**:
  - Small deployments: 1000-5000
  - Medium deployments: 10000-50000
  - Large deployments: 100000+

#### hash_buckets
- **Type**: Integer (must be power of 2)
- **Default**: 4096
- **Description**: Number of hash table buckets
- **Tuning**:
  - General rule: buckets = max_tracked_ips / 2
  - More buckets: Better performance, more memory
  - Fewer buckets: Less memory, potential collisions

### Packet Capture Configuration

```
capture = {
    nfqueue_num = 0;
    use_raw_socket = false;
};
```

#### nfqueue_num
- **Type**: Integer (0 - 65535)
- **Default**: 0
- **Description**: NFQUEUE number to use for packet capture
- **Note**: Must match the queue number in iptables rule

#### use_raw_socket
- **Type**: Boolean (true/false)
- **Default**: false
- **Description**: Use raw socket capture instead of NFQUEUE
- **When to use**:
  - NFQUEUE not available
  - Testing environments
  - Simplified deployment (no iptables NFQUEUE rule needed)

### Whitelist Configuration

```
whitelist = {
    file = "/etc/synflood-detector/whitelist.conf";
};
```

#### file
- **Type**: String (file path)
- **Default**: "/etc/synflood-detector/whitelist.conf"
- **Description**: Path to whitelist configuration file
- **Format**: One IP/CIDR per line, # for comments

### Logging Configuration

```
logging = {
    level = "info";
    syslog = true;
    metrics_socket = "/var/run/synflood-detector.sock";
};
```

#### level
- **Type**: String (debug, info, warn, error)
- **Default**: "info"
- **Description**: Minimum log level to output
- **Levels**:
  - `debug`: Very verbose, all operations
  - `info`: Normal operations, detections, blocks
  - `warn`: Warnings and above
  - `error`: Only errors

#### syslog
- **Type**: Boolean (true/false)
- **Default**: true
- **Description**: Whether to use systemd journal for logging
- **Note**: If false, logs to stderr

#### metrics_socket
- **Type**: String (file path)
- **Default**: "/var/run/synflood-detector.sock"
- **Description**: Unix socket path for metrics API

## Whitelist Configuration

File: `/etc/synflood-detector/whitelist.conf`

Format:
```
# Comments start with #
# One IP or CIDR per line

# Single IP
192.168.1.100

# CIDR range
10.0.0.0/8

# Multiple entries
127.0.0.1
127.0.0.0/8
192.168.0.0/16
```

## Recommended Configurations

### Conservative (Low False Positives)

```
detection = {
    syn_threshold = 200;
    window_ms = 2000;
    proc_check_interval_s = 5;
};

enforcement = {
    block_duration_s = 180;
    ipset_name = "synflood_blacklist";
};
```

### Aggressive (Maximum Protection)

```
detection = {
    syn_threshold = 50;
    window_ms = 1000;
    proc_check_interval_s = 3;
};

enforcement = {
    block_duration_s = 600;
    ipset_name = "synflood_blacklist";
};
```

### High-Traffic Server

```
detection = {
    syn_threshold = 500;
    window_ms = 3000;
    proc_check_interval_s = 10;
};

limits = {
    max_tracked_ips = 50000;
    hash_buckets = 16384;
};
```

## Configuration Reload

To reload configuration without restarting:

```bash
sudo systemctl reload synflood-detector
# or
sudo killall -HUP synflood-detector
```

**Note**: Currently only SIGHUP signal is implemented for future reload capability. Full hot-reload is planned for future versions.

## Configuration Validation

Test configuration before applying:

```bash
# Dry-run to check syntax
synflood-detector -c /etc/synflood-detector/synflood-detector.conf --check

# View loaded configuration
sudo journalctl -u synflood-detector | grep "Configuration:"
```

## Performance Tuning

### CPU-Constrained Systems

```
detection = {
    proc_check_interval_s = 30;  # Reduce validation frequency
};

limits = {
    hash_buckets = 2048;  # Smaller hash table
};
```

### Memory-Constrained Systems

```
limits = {
    max_tracked_ips = 1000;  # Lower tracking limit
    hash_buckets = 512;      # Smaller hash table
};
```

### High-Performance Systems

```
limits = {
    max_tracked_ips = 100000;
    hash_buckets = 32768;
};

detection = {
    proc_check_interval_s = 2;  # More frequent validation
};
```

## Security Considerations

1. **Whitelist Critical IPs**: Always whitelist:
   - Monitoring systems
   - Load balancers
   - Administrative IPs
   - Internal infrastructure

2. **Block Duration**: Balance protection vs. accessibility
   - Too short: Attackers can retry quickly
   - Too long: Legitimate users affected

3. **Thresholds**: Start conservative, tune based on traffic patterns

4. **Monitoring**: Regularly review metrics and logs for false positives

## See Also

- [INSTALL.md](INSTALL.md) - Installation instructions
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues and solutions
