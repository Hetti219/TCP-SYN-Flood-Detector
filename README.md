# TCP SYN Flood Detector

**Version 1.0.0** | **Software Design Document v1.0** | **SDLC: V-Model**

A high-performance userspace daemon for detecting and mitigating TCP SYN flood attacks through dynamic firewall rule management. Built with security, performance, and observability in mind.

## Status Badges
![CI/CD Pipeline](https://github.com/Hetti219/TCP-SYN-Flood-Detector/actions/workflows/ci.yml/badge.svg)
![CodeQL](https://github.com/Hetti219/TCP-SYN-Flood-Detector/actions/workflows/codeql.yml/badge.svg)

## Overview

Unlike naive polling-based approaches, this implementation uses a hybrid detection strategy combining:

- **Real-time packet inspection** via netfilter queue integration
- **Sliding window rate limiting** for per-IP SYN packet tracking
- **Secondary validation** through /proc/net/tcp analysis for SYN_RECV state correlation
- **Automatic mitigation** using dynamic ipset-based firewall rules

## Key Features

- ✅ **High Performance**: Handles 50,000+ SYN packets/second with <100ms detection latency
- ✅ **Low Resource Usage**: <5% CPU usage under baseline traffic, <50MB memory footprint
- ✅ **Dual Capture Modes**: NFQUEUE (primary) and raw socket (fallback)
- ✅ **Intelligent Detection**: Sliding window rate limiting with /proc validation
- ✅ **Automatic Enforcement**: Dynamic ipset blacklist management
- ✅ **Whitelist Support**: CIDR-based Patricia trie for O(k) whitelist matching
- ✅ **Observability**: Prometheus-compatible metrics via Unix socket
- ✅ **Structured Logging**: systemd journal integration with event tagging
- ✅ **Security Hardened**: Minimal capabilities (CAP_NET_ADMIN, CAP_NET_RAW), no full root
- ✅ **Production Ready**: systemd service with automatic recovery

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      KERNEL SPACE                           │
│  ┌────────────┐    ┌──────────┐    ┌──────────────────┐   │
│  │ NETFILTER  │───▶│ NFQUEUE  │───▶│ Packet to        │   │
│  │ (iptables) │    │ (queue 0)│    │ Userspace        │   │
│  └────────────┘    └──────────┘    └──────────────────┘   │
│         ▲                                   │               │
│         │                                   ▼               │
│  ┌──────────────┐                ┌──────────────────────┐  │
│  │ IPSET        │◀───────────────│ Netlink Socket       │  │
│  │ (blacklist)  │  Add/Remove IP │ (from userspace)     │  │
│  └──────────────┘                └──────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│               USER SPACE (synflood-detector)                │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │              PACKET CAPTURE LAYER                   │  │
│  │  ┌────────────────┐    ┌─────────────────────────┐ │  │
│  │  │ NFQueue Handler│    │ Raw Socket + BPF        │ │  │
│  │  └────────────────┘    └─────────────────────────┘ │  │
│  └─────────────────────────────────────────────────────┘  │
│                           │                                 │
│  ┌─────────────────────────────────────────────────────┐  │
│  │              ANALYSIS ENGINE                        │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │  │
│  │  │Rate Counter │  │/proc Parser │  │ Whitelist  │ │  │
│  │  │(per-IP HLL) │  │ Validator   │  │  Filter    │ │  │
│  │  └─────────────┘  └─────────────┘  └────────────┘ │  │
│  └─────────────────────────────────────────────────────┘  │
│                           │                                 │
│  ┌─────────────────────────────────────────────────────┐  │
│  │             ENFORCEMENT LAYER                       │  │
│  │  ┌────────────────┐       ┌──────────────────────┐ │  │
│  │  │ ipset Manager  │       │ Expiration Timer     │ │  │
│  │  └────────────────┘       └──────────────────────┘ │  │
│  └─────────────────────────────────────────────────────┘  │
│                           │                                 │
│  ┌─────────────────────────────────────────────────────┐  │
│  │             OBSERVABILITY                           │  │
│  │  ┌──────────┐  ┌─────────────┐  ┌───────────────┐ │  │
│  │  │  Logger  │  │Unix Socket  │  │Signal Handlers│ │  │
│  │  │(journald)│  │(metrics API)│  │(SIGHUP/SIGTERM)│ │  │
│  │  └──────────┘  └─────────────┘  └───────────────┘ │  │
│  └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Detection Algorithm

```
FUNCTION process_syn_packet(src_ip, config):
    // Step 1: Whitelist check (O(k) CIDR matching)
    IF is_whitelisted(src_ip):
        RETURN ACCEPT

    // Step 2: Get or create tracker entry
    tracker = tracker_table_get_or_create(src_ip)

    // Step 3: Sliding window rate calculation
    current_time = get_monotonic_ns()
    IF current_time - tracker.window_start > config.window_ms:
        tracker.syn_count = 1
        tracker.window_start = current_time
    ELSE:
        tracker.syn_count++

    // Step 4: Threshold check with secondary validation
    IF tracker.syn_count > config.syn_threshold:
        IF NOT tracker.blocked:
            syn_recv_count = count_syn_recv_state(src_ip)
            IF syn_recv_count > config.syn_threshold / 2:
                // Confirmed attack - block IP
                ipset_add(src_ip, config.block_duration_s)
                tracker.blocked = TRUE
                log_event(BLOCKED, src_ip, tracker.syn_count)
            ELSE:
                // Possible false positive - log only
                log_event(SUSPICIOUS, src_ip, tracker.syn_count)

    RETURN ACCEPT  // Let packet through (ipset handles blocking)
```

## Quick Start

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt install build-essential meson ninja-build \
    libnetfilter-queue-dev libmnl-dev libipset-dev \
    libconfig-dev libsystemd-dev iptables ipset
```

### Build and Install

```bash
# Configure
meson setup build --buildtype=release

# Build
ninja -C build

# Install
sudo ninja -C build install
```

### Configure

```bash
# Edit main configuration
sudo nano /etc/synflood-detector/synflood-detector.conf

# Add trusted IPs to whitelist
sudo nano /etc/synflood-detector/whitelist.conf
```

### Start Service

```bash
# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable synflood-detector
sudo systemctl start synflood-detector

# Check status
sudo systemctl status synflood-detector

# View logs
sudo journalctl -u synflood-detector -f
```

## Configuration Example

```conf
detection = {
    syn_threshold = 100;          # SYN packets per IP per window
    window_ms = 1000;             # Detection window (1 second)
    proc_check_interval_s = 5;    # /proc validation interval
};

enforcement = {
    block_duration_s = 300;       # Block for 5 minutes
    ipset_name = "synflood_blacklist";
};

limits = {
    max_tracked_ips = 10000;      # Maximum IPs to track
    hash_buckets = 4096;          # Hash table size (power of 2)
};

capture = {
    nfqueue_num = 0;              # NFQUEUE number
    use_raw_socket = false;       # Use NFQUEUE (recommended)
};

whitelist = {
    file = "/etc/synflood-detector/whitelist.conf";
};

logging = {
    level = "info";               # debug, info, warn, error
    syslog = true;                # Use systemd journal
    metrics_socket = "/var/run/synflood-detector.sock";
};
```

## Monitoring

### View Metrics

```bash
# Query metrics (Prometheus format)
echo "GET /metrics" | socat - UNIX:/var/run/synflood-detector.sock
```

Sample output:
```
synflood_packets_total 1234567
synflood_syn_packets_total 98765
synflood_blocked_ips_current 42
synflood_detections_total 156
synflood_false_positives_total 3
synflood_whitelist_hits_total 8901
```

### View Blocked IPs

```bash
# List currently blocked IPs
sudo ipset list synflood_blacklist

# Watch in real-time
watch -n 1 'sudo ipset list synflood_blacklist | tail -20'
```

### View Logs

```bash
# Follow live logs
sudo journalctl -u synflood-detector -f

# View detection events
sudo journalctl -u synflood-detector | grep BLOCKED

# View with structured fields
sudo journalctl -u synflood-detector -o json-pretty
```

## Testing

### Simulate SYN Flood Attack

```bash
# Using hping3
sudo hping3 -S -p 80 --flood --rand-source <target_ip>

# Targeted attack from specific IP
sudo hping3 -S -p 80 -i u100 -a <spoofed_ip> <target_ip>

# Monitor detection
sudo journalctl -u synflood-detector -f
```

### Performance Testing

```bash
# Build with debug symbols
meson setup build-debug --buildtype=debug

# Memory profiling
sudo valgrind --leak-check=full build-debug/synflood-detector

# CPU profiling
sudo perf record -g -p $(pgrep synflood-detector)
```

## Technology Stack

| Component | Technology | Justification |
|-----------|-----------|---------------|
| Language | C (C11) | Zero-overhead abstractions, direct syscall access |
| Build System | Meson + Ninja | Modern, fast, clean dependency handling |
| Packet Capture | libnetfilter_queue | Kernel-integrated, verdict-based filtering |
| Firewall Control | libmnl + ipset | Native netlink, no fork/exec overhead |
| Configuration | libconfig | Human-readable, complex structure support |
| Logging | systemd-journal | Structured logging, native integration |

## Performance Benchmarks

**Test Environment**: 2 CPU cores, 2GB RAM, Ubuntu 24.04

| Metric | Target (NFR) | Achieved |
|--------|-------------|----------|
| Detection Latency | < 100ms | ~45ms |
| Packet Processing | 50,000 PPS | 65,000+ PPS |
| CPU Usage (idle) | < 5% | ~1% |
| CPU Usage (attack) | < 10% | ~4% |
| Memory Usage | < 50MB | 12-35MB |

## Security

- **Minimal Privileges**: Runs with CAP_NET_ADMIN and CAP_NET_RAW only (no full root)
- **systemd Hardening**: ProtectSystem, ProtectHome, PrivateTmp, NoNewPrivileges
- **Input Validation**: All configuration values validated before use
- **Memory Safety**: Careful bounds checking, tested with Valgrind and AddressSanitizer
- **Fuzzing**: /proc/net/tcp parser fuzzed with AFL++

## Project Structure

```
synflood-detector/
├── meson.build                 # Build configuration
├── src/
│   ├── main.c                  # Entry point, signal handling
│   ├── capture/                # Packet capture (NFQUEUE, raw sockets)
│   ├── analysis/               # IP tracking, whitelist, /proc parsing
│   ├── enforce/                # ipset management, expiration
│   ├── observe/                # Logging, metrics
│   └── config/                 # Configuration parsing
├── include/
│   └── common.h                # Shared types, macros
├── conf/
│   ├── synflood-detector.conf  # Default configuration
│   ├── whitelist.conf          # Default whitelist
│   └── synflood-detector.service # systemd unit file
├── docs/
│   ├── INSTALL.md              # Installation guide
│   ├── CONFIGURATION.md        # Configuration reference
│   └── TROUBLESHOOTING.md      # Common issues and solutions
└── tests/                      # Unit and integration tests
```

## Documentation

- **[INSTALL.md](docs/INSTALL.md)** - Complete installation instructions
- **[CONFIGURATION.md](docs/CONFIGURATION.md)** - Configuration reference and tuning guide
- **[TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)** - Common issues and solutions

## SDLC: V-Model

This project was developed following the V-Model methodology:

| Development Phase | Verification Phase |
|-------------------|-------------------|
| Requirements Analysis | Acceptance Testing |
| System Design | System Testing |
| Architecture Design | Integration Testing |
| Module Design | Unit Testing |

Each development phase has corresponding testing to ensure quality and correctness.

## Requirements (FR/NFR)

### Functional Requirements
- ✅ FR-01: Capture TCP SYN packets via NFQUEUE or raw sockets
- ✅ FR-02: Maintain per-IP counters with sliding windows
- ✅ FR-03: Validate via /proc/net/tcp SYN_RECV state
- ✅ FR-04: Automatic ipset blacklist management
- ✅ FR-05: Automatic IP expiration from blacklist
- ✅ FR-06: IP/CIDR whitelist support
- ✅ FR-07: Configurable logging with verbosity
- ✅ FR-08: Metrics via Unix socket
- ⏳ FR-09: Configuration reload via SIGHUP (planned)
- ✅ FR-10: Graceful shutdown with cleanup

### Non-Functional Requirements
- ✅ NFR-01: Detection latency <100ms
- ✅ NFR-02: Sustain 50,000 SYN/s without packet loss
- ✅ NFR-03: Memory footprint <50MB
- ✅ NFR-04: CPU <5% during baseline
- ✅ NFR-05: CAP_NET_ADMIN + CAP_NET_RAW (no full root)
- ✅ NFR-06: Configuration validation
- ✅ NFR-07: Recover from transient failures
- ⏳ NFR-08: 80% branch coverage (in progress)

## Contributing

This project was developed as a demonstration of low-level network programming and security automation. Contributions, issues, and feature requests are welcome.

## License

MIT License - See LICENSE file for details

## Author

Developed as part of a portfolio demonstrating:
- Low-level C systems programming
- Network packet processing and filtering
- Security automation and threat mitigation
- Linux kernel interfaces (netfilter, ipset, /proc)
- Performance optimization and profiling
- Production-grade daemon development
- V-Model SDLC methodology

## Acknowledgments

- libnetfilter_queue documentation and examples
- Linux kernel netfilter documentation
- ipset project and documentation
- systemd service hardening best practices

---

**Note**: This software is intended for educational and legitimate security testing purposes only. Ensure you have proper authorization before deploying in production environments.
