---
name: Bug Report
about: Create a report to help us improve
title: '[BUG] '
labels: bug
assignees: ''
---

## Bug Description

<!-- A clear and concise description of what the bug is -->

## Environment

**System Information**:
- OS: <!-- e.g., Ubuntu 22.04 -->
- Kernel Version: <!-- output of `uname -r` -->
- synflood-detector Version: <!-- output of `synflood-detector --version` or commit hash -->
- Installation Method: <!-- e.g., built from source, package manager, etc. -->

**Dependencies**:
```bash
# Output of: dpkg -l | grep -E 'libnetfilter-queue|libmnl|ipset|libconfig|libsystemd'


```

## Steps to Reproduce

1.
2.
3.
4.

## Expected Behavior

<!-- What you expected to happen -->

## Actual Behavior

<!-- What actually happened -->

## Configuration

**synflood-detector.conf**:
```ini
# Paste relevant configuration sections


```

**whitelist.conf** (if relevant):
```
# Paste whitelist configuration


```

## Logs

**System Logs** (`journalctl -u synflood-detector -n 50`):
```


```

**Error Messages**:
```


```

## Network Traffic

<!-- If applicable, describe the network traffic conditions when the bug occurred -->

- Network traffic rate: <!-- e.g., "~10k packets/sec" -->
- Attack detected: <!-- Yes/No -->
- False positives: <!-- Yes/No -->

## Additional Context

<!-- Add any other context about the problem here -->

## Possible Solution

<!-- If you have ideas on how to fix this, please share -->

## Screenshots/Packet Captures

<!-- If applicable, add screenshots or packet capture files -->
