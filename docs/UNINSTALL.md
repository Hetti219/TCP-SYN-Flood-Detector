# TCP SYN Flood Detector - Uninstallation Guide

## Automated Uninstallation (Recommended)

The easiest way to uninstall TCP SYN Flood Detector:

```bash
curl -fsSL https://raw.githubusercontent.com/Hetti219/TCP-SYN-Flood-Detector/main/uninstall.sh | sudo bash
```

Or if you have the repository cloned:

```bash
sudo ./uninstall.sh
```

### Uninstaller Options

```bash
# Force uninstall without confirmation
sudo ./uninstall.sh --force

# Keep configuration files (preserves your settings)
sudo ./uninstall.sh --keep-configs

# Remove installed dependencies (use with caution - may affect other software)
sudo ./uninstall.sh --remove-deps

# Show help
sudo ./uninstall.sh --help
```

### Examples

```bash
# Interactive uninstall with prompts (default)
sudo ./uninstall.sh

# Quick uninstall keeping configs
sudo ./uninstall.sh --force --keep-configs

# Complete removal including dependencies
sudo ./uninstall.sh --force --remove-deps
```

---

## What Gets Removed

### Always Removed:
- **Binary**: `/usr/local/bin/synflood-detector`
- **Systemd service**: `/usr/local/lib/systemd/system/synflood-detector.service`
- **Documentation**: `/usr/local/share/doc/synflood-detector/`
- **Man page**: `/usr/local/share/man/man8/synflood-detector.8`
- **iptables rules**: NFQUEUE and DROP rules for synflood_blacklist
- **ipset blacklist**: synflood_blacklist ipset
- **Runtime artifacts**: Unix socket, PID files

### Optional (You'll be prompted):
- **Configuration files**: `/etc/synflood-detector/`
  - `synflood-detector.conf` - Main configuration
  - `whitelist.conf` - IP whitelist
- **Runtime dependencies**:
  - libnetfilter-queue1
  - libmnl0
  - libipset13
  - libconfig9
  - libsystemd0
  - iptables
  - ipset

**Note**: We recommend keeping configuration files unless you're certain you won't reinstall. Dependencies should only be removed if you're certain no other software needs them.

---

## Manual Uninstallation

If the automated uninstaller is not available, follow these steps:

### 1. Stop the Service

```bash
# Stop the running service
sudo systemctl stop synflood-detector

# Check status
sudo systemctl status synflood-detector
```

### 2. Disable the Service

```bash
# Disable from starting on boot
sudo systemctl disable synflood-detector

# Reload systemd
sudo systemctl daemon-reload
```

### 3. Remove iptables Rules

```bash
# Remove NFQUEUE rule (sends SYN packets to userspace)
sudo iptables -D INPUT -p tcp --syn -j NFQUEUE --queue-num 0

# Remove DROP rule (blocks blacklisted IPs)
sudo iptables -D INPUT -m set --match-set synflood_blacklist src -j DROP

# Verify removal
sudo iptables -L INPUT -n --line-numbers
```

### 4. Destroy ipset

```bash
# Flush all entries
sudo ipset flush synflood_blacklist

# Destroy the ipset
sudo ipset destroy synflood_blacklist

# Verify removal
sudo ipset list
```

### 5. Remove Binary

```bash
sudo rm /usr/local/bin/synflood-detector
```

### 6. Remove Systemd Service

```bash
sudo rm /usr/local/lib/systemd/system/synflood-detector.service
sudo systemctl daemon-reload
```

### 7. Remove Documentation

```bash
sudo rm -r /usr/local/share/doc/synflood-detector
sudo rm /usr/local/share/man/man8/synflood-detector.8

# Update man database
sudo mandb -q
```

### 8. Remove Configuration Files (Optional)

**Warning**: This will delete your custom settings and whitelist.

```bash
# Backup first (optional)
sudo cp -r /etc/synflood-detector ~/synflood-detector-backup

# Remove
sudo rm -r /etc/synflood-detector
```

### 9. Clean Runtime Artifacts

```bash
# Remove Unix socket
sudo rm -f /var/run/synflood-detector.sock

# Remove PID file
sudo rm -f /var/run/synflood-detector.pid
```

### 10. Remove Dependencies (Optional)

**Warning**: Only remove if you're certain no other software needs these libraries.

```bash
sudo apt remove -y \
    libnetfilter-queue1 \
    libmnl0 \
    libipset13 \
    libconfig9 \
    iptables \
    ipset

# Clean up unused dependencies
sudo apt autoremove -y
```

---

## Verification

After uninstallation, verify everything is removed:

### Check Service

```bash
# Should return "Unit synflood-detector.service could not be found"
sudo systemctl status synflood-detector
```

### Check Binary

```bash
# Should return "no synflood-detector in /usr/local/bin"
which synflood-detector
```

### Check iptables Rules

```bash
# Should not show any synflood-related rules
sudo iptables -L INPUT -n | grep -E "(NFQUEUE|synflood)"
```

### Check ipset

```bash
# Should return "The set with the given name does not exist"
sudo ipset list synflood_blacklist
```

### Check Files

```bash
# Should return "No such file or directory"
ls /usr/local/bin/synflood-detector
ls /usr/local/lib/systemd/system/synflood-detector.service
ls /etc/synflood-detector
```

---

## Reinstallation

If you uninstalled and want to reinstall:

```bash
# Quick reinstall
curl -fsSL https://raw.githubusercontent.com/Hetti219/TCP-SYN-Flood-Detector/main/install.sh | sudo bash
```

If you kept your configuration files (recommended), they will be preserved and used by the new installation.

---

## Troubleshooting Uninstallation

### "ipset is in use and can't be destroyed"

The ipset is still being referenced by iptables. Remove the iptables rule first:

```bash
# Remove the iptables rule referencing ipset
sudo iptables -D INPUT -m set --match-set synflood_blacklist src -j DROP

# Then destroy ipset
sudo ipset destroy synflood_blacklist
```

### "iptables: Bad rule"

The rule might already be removed. List all rules to verify:

```bash
# List all INPUT chain rules with line numbers
sudo iptables -L INPUT -n --line-numbers

# Remove by line number instead
sudo iptables -D INPUT <line_number>
```

### "Service still running after stop"

Force kill the process:

```bash
# Find the process
ps aux | grep synflood-detector

# Kill it
sudo pkill -9 synflood-detector

# Or use systemctl
sudo systemctl kill -s SIGKILL synflood-detector
```

### "Permission denied"

Uninstallation requires root privileges:

```bash
# Run with sudo
sudo ./uninstall.sh

# Or become root
sudo -i
./uninstall.sh
```

### Configuration Files Won't Delete

They might be in use or have special permissions:

```bash
# Check what's using them
sudo lsof | grep synflood-detector

# Force remove
sudo rm -rf /etc/synflood-detector
```

---

## Partial Uninstallation

If you only want to stop the service temporarily without full uninstallation:

```bash
# Stop service
sudo systemctl stop synflood-detector

# Disable on boot (but keep installed)
sudo systemctl disable synflood-detector
```

To re-enable later:

```bash
sudo systemctl enable synflood-detector
sudo systemctl start synflood-detector
```

---

## Complete System Cleanup

For a complete cleanup including all traces:

```bash
# Run automated uninstaller with all options
sudo ./uninstall.sh --force --remove-deps

# Remove any logs
sudo journalctl --vacuum-time=1s

# Remove build artifacts (if you built from source)
rm -rf ~/TCP\ SYN\ Flood\ Detector/build

# Clear bash history of install commands (optional)
history -c
```

---

## Support

If you encounter issues during uninstallation:

1. Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues
2. Review the uninstall script output for specific error messages
3. Report issues at: https://github.com/Hetti219/TCP-SYN-Flood-Detector/issues

For complete installation instructions, see [INSTALL.md](INSTALL.md).
