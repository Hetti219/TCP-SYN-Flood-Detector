# TCP SYN Flood Detector - Installation Guide

## System Requirements

- Linux kernel 5.x or later
- Ubuntu 22.04/24.04 (or equivalent distribution)
- Minimum 512MB RAM
- CAP_NET_ADMIN and CAP_NET_RAW capabilities

## Dependencies

### Build Dependencies

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    meson \
    ninja-build \
    libnetfilter-queue-dev \
    libmnl-dev \
    libipset-dev \
    libconfig-dev \
    libsystemd-dev
```

### Runtime Dependencies

```bash
sudo apt install -y \
    iptables \
    ipset \
    libnetfilter-queue1 \
    libmnl0 \
    libipset13 \
    libconfig9 \
    libsystemd0
```

### Optional Testing Tools

```bash
sudo apt install -y \
    hping3 \
    scapy \
    valgrind \
    clang-tidy \
    cppcheck
```

## Building from Source

### 1. Configure the Build

```bash
cd /path/to/TCP\ SYN\ Flood\ Detector
meson setup build --buildtype=release
```

Available build options:

```bash
# Debug build with symbols
meson setup build --buildtype=debug

# Release build with optimizations (recommended)
meson setup build --buildtype=release

# Custom installation prefix
meson setup build --prefix=/usr/local
```

### 2. Compile

```bash
ninja -C build
```

### 3. Run Tests (Optional)

```bash
ninja -C build test
```

### 4. Install

```bash
sudo ninja -C build install
```

This will install:
- Binary: `/usr/local/bin/synflood-detector`
- Config: `/etc/synflood-detector/synflood-detector.conf`
- Whitelist: `/etc/synflood-detector/whitelist.conf`
- Service: `/usr/lib/systemd/system/synflood-detector.service`
- Documentation: `/usr/local/share/doc/synflood-detector/`

## Post-Installation Setup

### 1. Create ipset and iptables Rules

The systemd service will automatically create these, but you can set them up manually:

```bash
# Create ipset for blacklisting
sudo ipset create synflood_blacklist hash:ip timeout 300 maxelem 65536

# Add iptables rule to drop packets from blacklisted IPs
sudo iptables -I INPUT -m set --match-set synflood_blacklist src -j DROP

# Add iptables rule to send TCP SYN packets to NFQUEUE
sudo iptables -I INPUT -p tcp --syn -j NFQUEUE --queue-num 0
```

### 2. Configure the Daemon

Edit the configuration file:

```bash
sudo nano /etc/synflood-detector/synflood-detector.conf
```

See [CONFIGURATION.md](CONFIGURATION.md) for detailed configuration options.

### 3. Configure Whitelist

Add trusted IPs/CIDRs to the whitelist:

```bash
sudo nano /etc/synflood-detector/whitelist.conf
```

Example:
```
# Localhost
127.0.0.1
127.0.0.0/8

# Internal network
192.168.1.0/24

# Monitoring server
203.0.113.50
```

### 4. Enable and Start the Service

```bash
# Reload systemd to recognize the new service
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable synflood-detector

# Start the service
sudo systemctl start synflood-detector

# Check status
sudo systemctl status synflood-detector
```

## Verification

### 1. Check Service Status

```bash
sudo systemctl status synflood-detector
```

Expected output:
```
● synflood-detector.service - TCP SYN Flood Detector Daemon
     Loaded: loaded (/usr/lib/systemd/system/synflood-detector.service; enabled)
     Active: active (running) since ...
```

### 2. View Logs

```bash
# Follow live logs
sudo journalctl -u synflood-detector -f

# View recent logs
sudo journalctl -u synflood-detector -n 100
```

### 3. Check Metrics

```bash
# Query metrics via Unix socket
echo "GET /metrics" | socat - UNIX:/var/run/synflood-detector.sock
```

### 4. Verify iptables Rules

```bash
# Check NFQUEUE rule
sudo iptables -L INPUT -n --line-numbers | grep NFQUEUE

# Check ipset rule
sudo iptables -L INPUT -n --line-numbers | grep synflood_blacklist

# List blacklisted IPs
sudo ipset list synflood_blacklist
```

## Uninstallation

### 1. Stop and Disable Service

```bash
sudo systemctl stop synflood-detector
sudo systemctl disable synflood-detector
```

### 2. Remove iptables Rules

```bash
sudo iptables -D INPUT -p tcp --syn -j NFQUEUE --queue-num 0
sudo iptables -D INPUT -m set --match-set synflood_blacklist src -j DROP
```

### 3. Destroy ipset

```bash
sudo ipset destroy synflood_blacklist
```

### 4. Remove Installed Files

```bash
sudo rm /usr/local/bin/synflood-detector
sudo rm -r /etc/synflood-detector
sudo rm /usr/lib/systemd/system/synflood-detector.service
sudo rm -r /usr/local/share/doc/synflood-detector
```

## Troubleshooting Installation

### Permission Denied Errors

The daemon requires CAP_NET_ADMIN and CAP_NET_RAW capabilities. Run as root or with appropriate capabilities:

```bash
# Check capabilities
getcap /usr/local/bin/synflood-detector

# Set capabilities (if needed)
sudo setcap cap_net_admin,cap_net_raw+ep /usr/local/bin/synflood-detector
```

### Missing Dependencies

If compilation fails with missing dependencies:

```bash
# On Debian/Ubuntu
sudo apt-get build-dep synflood-detector

# Or install missing libraries manually
sudo apt install lib<missing-library>-dev
```

### Meson Build Issues

```bash
# Clean build directory
rm -rf build

# Reconfigure
meson setup build --wipe
ninja -C build
```

For more troubleshooting, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
