# Quick Testing Guide

## Running Automated Tests

All automated tests are now set up and passing! Run them with:

```bash
# From project root
meson test -C build
```

Or with verbose output:

```bash
meson test -C build --verbose
```

## Test Results Summary

✅ **All 32 automated tests PASSING**

- Common utilities: 6 tests
- Configuration: 6 tests
- Whitelist: 6 tests
- IP Tracker: 9 tests
- Detection Flow: 5 tests

## Manual Tests (YOU NEED TO RUN THESE)

Some tests require root access and real network traffic. See **tests/MANUAL_TESTING.md** for detailed procedures.

### Critical Manual Tests:

1. **NFQUEUE Integration Test** ⚠️ HIGH PRIORITY
   - Verifies packet capture from netfilter
   - Requires: root, iptables, network traffic

2. **IPSet Integration Test** ⚠️ HIGH PRIORITY
   - Verifies automatic IP blocking
   - Requires: root, ipset, SYN flood generator

3. **Performance Test** ⚠️ HIGH PRIORITY
   - Verifies 50,000 PPS handling requirement
   - Requires: root, hping3 or packet generator

4. **False Positive Test** ⚠️ HIGH PRIORITY
   - Verifies legitimate traffic isn't blocked
   - Requires: root, web traffic generator

5. **/proc/net/tcp Parsing Test**
   - Verifies connection state detection
   - Requires: network traffic

6. **Whitelist Functionality Test**
   - Verifies whitelisted IPs aren't blocked
   - Requires: root, controlled traffic source

7. **Metrics Socket Test**
   - Verifies metrics export
   - Requires: root

8. **Signal Handling Test**
   - Verifies graceful shutdown
   - Requires: root

9. **Configuration Reload Test**
   - Verifies SIGHUP handling
   - Requires: root

10. **Multi-Source Attack Test**
    - Verifies distributed attack handling
    - Requires: root, multiple traffic sources

## Quick Manual Test Example

```bash
# 1. Setup NFQUEUE
sudo iptables -I INPUT -p tcp --syn -j NFQUEUE --queue-num 0

# 2. Start detector
sudo ./build/synflood-detector

# 3. From another machine, send test traffic
hping3 -S -p 80 -c 100 <your-server-ip>

# 4. Check logs
sudo journalctl -u synflood-detector -f

# 5. Cleanup
sudo iptables -D INPUT -p tcp --syn -j NFQUEUE --queue-num 0
```

## Documentation

- **tests/README.md** - Test suite overview and how to run tests
- **tests/MANUAL_TESTING.md** - Detailed manual test procedures
- **tests/TEST_SUMMARY.md** - Complete test results and coverage

## Test Files Created

```
tests/
├── unity/                      # Test framework
│   ├── unity.h
│   └── unity.c
├── unit/                       # Unit tests
│   ├── test_common.c          # Utility functions
│   ├── test_config.c          # Configuration
│   ├── test_whitelist.c       # IP whitelisting
│   └── test_tracker.c         # IP tracking
├── integration/                # Integration tests
│   └── test_detection_flow.c  # End-to-end detection
├── README.md                   # Test documentation
├── MANUAL_TESTING.md          # Manual test procedures
└── TEST_SUMMARY.md            # Test results summary
```

## Need Help?

- See tests/README.md for detailed test information
- See tests/MANUAL_TESTING.md for step-by-step manual test procedures
- Run `meson test -C build --list` to see all available tests
