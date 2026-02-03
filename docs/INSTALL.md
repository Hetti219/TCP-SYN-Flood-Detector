# TCP SYN Flood Detector - Installation Guide

## Installation Methods

### Method 1: Automated Installer (Recommended)

The easiest way to install TCP SYN Flood Detector is using our automated installer:

```bash
curl -fsSL https://raw.githubusercontent.com/Hetti219/TCP-SYN-Flood-Detector/main/install.sh | sudo bash
```

**What the installer does:**
1. Verifies system compatibility (Ubuntu 22.04/24.04, Debian 11/12, x86_64)
2. Installs runtime dependencies via apt
3. Downloads latest release from GitHub
4. Verifies SHA256 checksums
5. Installs binary, configs, service, and documentation
6. Runs interactive guided setup wizard (new!)
7. Interactively configures service and whitelist
8. Sets up iptables/ipset rules

**Installation options:**

```bash
# Install specific version
curl -fsSL https://raw.githubusercontent.com/Hetti219/TCP-SYN-Flood-Detector/main/install.sh | sudo bash -s -- --version v1.0.0

# Non-interactive mode (use defaults, skip wizard)
curl -fsSL https://raw.githubusercontent.com/Hetti219/TCP-SYN-Flood-Detector/main/install.sh | sudo bash -s -- --non-interactive

# Force guided setup wizard (even on upgrades)
curl -fsSL https://raw.githubusercontent.com/Hetti219/TCP-SYN-Flood-Detector/main/install.sh | sudo bash -s -- --guided

# Skip guided setup wizard
curl -fsSL https://raw.githubusercontent.com/Hetti219/TCP-SYN-Flood-Detector/main/install.sh | sudo bash -s -- --no-wizard

# Skip dependency installation (if already installed)
curl -fsSL https://raw.githubusercontent.com/Hetti219/TCP-SYN-Flood-Detector/main/install.sh | sudo bash -s -- --skip-deps

# Don't enable or start service automatically
curl -fsSL https://raw.githubusercontent.com/Hetti219/TCP-SYN-Flood-Detector/main/install.sh | sudo bash -s -- --no-service

# Combine options
curl -fsSL https://raw.githubusercontent.com/Hetti219/TCP-SYN-Flood-Detector/main/install.sh | sudo bash -s -- --no-wizard --no-service
```

#### Guided Setup Wizard (New!)

The installer includes an interactive guided setup wizard that helps you configure the optimal protection settings for your server type.

**Wizard Features:**
- ✅ Server type detection (Web, Database, Application)
- ✅ Intelligent preset recommendations
- ✅ Detailed configuration explanations
- ✅ Preview of preset settings
- ✅ Automatic preset application
- ✅ Configuration backup

**Example Wizard Flow:**

```
╔════════════════════════════════════════════════════╗
║                                                    ║
║   Welcome to SYN Flood Detector Setup!             ║
║                                                    ║
╚════════════════════════════════════════════════════╝

This wizard will help you configure optimal protection
settings for your server type.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Server Configuration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

What type of server is this?

  1) Web server (Apache/Nginx)
  2) Database server (MySQL/PostgreSQL)
  3) Application server
  4) I'm not sure
  5) Skip this wizard

Enter choice [1-5]: 1

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Recommended Configuration: BALANCED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Based on "Web server", we recommend the BALANCED preset.

Why BALANCED?
  ✓ Optimized for web servers and applications
  ✓ Blocks IPs sending 100+ SYN packets/second
  ✓ 5-minute block duration (good deterrent)
  ✓ Low false positive rate
  ✓ Suitable for most production environments

What would you like to do?
  1) Apply this preset now (recommended)
  2) Show detailed settings first
  3) Skip and use defaults

Enter choice [1-3]: 1

✓ Backing up default configuration...
✓ Applying balanced preset...
✓ Preset applied successfully!
```

**When the wizard runs:**
- Default: Interactive installs (unless piped or non-interactive flag)
- Fresh installs: Always shows wizard
- Upgrades: Skipped by default (preserves existing config)
- Force with `--guided` flag

**When the wizard is skipped:**
- Non-interactive mode (`--non-interactive`)
- Skip flag (`--no-wizard`)
- Piped installs without TTY
- Configuration already exists (upgrade)

**Security note:** If you prefer to review the script before running:
```bash
curl -fsSL https://raw.githubusercontent.com/Hetti219/TCP-SYN-Flood-Detector/main/install.sh | less
curl -fsSL https://raw.githubusercontent.com/Hetti219/TCP-SYN-Flood-Detector/main/install.sh -o install.sh
chmod +x install.sh
sudo ./install.sh
```

---

### Method 2: Manual Binary Installation

Download pre-built binaries from [GitHub Releases](https://github.com/Hetti219/TCP-SYN-Flood-Detector/releases):

```bash
# Set version
VERSION="v1.0.0"  # Replace with desired version

# Download release
wget "https://github.com/Hetti219/TCP-SYN-Flood-Detector/releases/download/${VERSION}/synflood-detector-${VERSION}-linux-x86_64.tar.gz"

# Download and verify checksum
wget "https://github.com/Hetti219/TCP-SYN-Flood-Detector/releases/download/${VERSION}/synflood-detector-${VERSION}-linux-x86_64.tar.gz.sha256"
sha256sum -c "synflood-detector-${VERSION}-linux-x86_64.tar.gz.sha256"

# Extract
tar -xzf "synflood-detector-${VERSION}-linux-x86_64.tar.gz"
cd "synflood-detector-${VERSION}-linux-x86_64"

# Run bundled installer
sudo ./install.sh
```

---

### Method 3: Build from Source

For development or customization, you can build from source.

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

### Automated Uninstallation (Recommended)

The easiest way to uninstall:

```bash
curl -fsSL https://raw.githubusercontent.com/Hetti219/TCP-SYN-Flood-Detector/main/uninstall.sh | sudo bash
```

Or if you have the repository cloned:

```bash
sudo ./uninstall.sh
```

**Uninstaller options:**

```bash
# Force uninstall without confirmation
sudo ./uninstall.sh --force

# Keep configuration files
sudo ./uninstall.sh --keep-configs

# Remove dependencies (use with caution)
sudo ./uninstall.sh --remove-deps
```

For complete uninstallation details, see [UNINSTALL.md](UNINSTALL.md).

### Manual Uninstallation

If the automated uninstaller is not available:

#### 1. Stop and Disable Service

```bash
sudo systemctl stop synflood-detector
sudo systemctl disable synflood-detector
```

#### 2. Remove iptables Rules

```bash
sudo iptables -D INPUT -p tcp --syn -j NFQUEUE --queue-num 0
sudo iptables -D INPUT -m set --match-set synflood_blacklist src -j DROP
```

#### 3. Destroy ipset

```bash
sudo ipset destroy synflood_blacklist
```

#### 4. Remove Installed Files

```bash
sudo rm /usr/local/bin/synflood-detector
sudo rm -r /etc/synflood-detector
sudo rm /usr/local/lib/systemd/system/synflood-detector.service
sudo rm -r /usr/local/share/doc/synflood-detector
sudo rm /usr/local/share/man/man8/synflood-detector.8
sudo systemctl daemon-reload
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
