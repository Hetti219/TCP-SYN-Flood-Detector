# Configuration Presets

This directory contains pre-configured settings for different use cases. Each preset is optimized for specific scenarios.

## Available Presets

| Preset | Threshold | Block Duration | Best For |
|--------|-----------|----------------|----------|
| **conservative** | 200 SYN/sec | 2 minutes | Learning, testing, low-traffic servers |
| **balanced** | 100 SYN/sec | 5 minutes | Most production servers (RECOMMENDED) |
| **aggressive** | 50 SYN/sec | 10 minutes | High-security, servers under attack |
| **high-traffic** | 500 SYN/sec | 3 minutes | Popular sites, APIs, CDN edges |

## How to Apply a Preset

### Using synflood-ctl (Recommended)

```bash
# Apply a preset
sudo synflood-ctl preset apply balanced

# View available presets
sudo synflood-ctl preset list

# See what a preset contains
sudo synflood-ctl preset show aggressive
```

### Manual Application

```bash
# Backup current config
sudo cp /etc/synflood-detector/synflood-detector.conf /etc/synflood-detector/synflood-detector.conf.bak

# Copy preset
sudo cp /etc/synflood-detector/presets/balanced.conf /etc/synflood-detector/synflood-detector.conf

# Reload service
sudo synflood-ctl reload
```

## Choosing the Right Preset

### Start with `balanced`
If you're unsure, start with the balanced preset. It works well for most servers and provides good protection with minimal false positives.

### Use `conservative` when:
- You're new to synflood-detector
- You're testing in a staging environment
- False positives are unacceptable
- Your server has very low traffic

### Use `aggressive` when:
- Your server is under active attack
- Security is your top priority
- You have a well-maintained whitelist
- You can respond quickly to false positive reports

### Use `high-traffic` when:
- Your server handles thousands of concurrent users
- You see regular traffic spikes
- You're behind a CDN or load balancer
- Normal traffic patterns exceed 100 SYN/sec from some sources

## Customizing Presets

After applying a preset, you can fine-tune individual values:

```bash
# View current configuration
sudo synflood-ctl config show

# Adjust specific values
sudo synflood-ctl config set syn_threshold 150

# Reload to apply changes
sudo synflood-ctl reload
```

## Creating Custom Presets

You can create your own presets by copying and modifying an existing one:

```bash
# Copy a preset as a starting point
sudo cp /etc/synflood-detector/presets/balanced.conf /etc/synflood-detector/presets/custom.conf

# Edit your custom preset
sudo nano /etc/synflood-detector/presets/custom.conf
```

## Preset Comparison Table

| Parameter | Conservative | Balanced | Aggressive | High-Traffic |
|-----------|-------------|----------|------------|--------------|
| syn_threshold | 200 | 100 | 50 | 500 |
| window_ms | 1000 | 1000 | 1000 | 1000 |
| proc_check_interval_s | 10 | 5 | 3 | 5 |
| block_duration_s | 120 | 300 | 600 | 180 |
| max_tracked_ips | 10000 | 10000 | 10000 | 50000 |
| hash_buckets | 4096 | 4096 | 4096 | 16384 |
