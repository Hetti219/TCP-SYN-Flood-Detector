# TCP SYN Flood Detector - Test Suite

This directory contains automated and manual tests for the TCP SYN Flood Detector.

## Test Structure

```
tests/
├── unity/              # Unity test framework
│   ├── unity.h
│   └── unity.c
├── unit/               # Unit tests for individual modules
│   ├── test_common.c
│   ├── test_config.c
│   ├── test_whitelist.c
│   ├── test_whitelist_advanced.c
│   ├── test_tracker.c
│   ├── test_tracker_advanced.c
│   ├── test_logger.c
│   └── test_procparse.c
├── integration/        # Integration tests
│   ├── test_detection_flow.c
│   ├── test_config_integration.c
│   ├── test_whitelist_integration.c
│   ├── test_blocking_scenarios.c
│   └── test_performance_stress.c
├── fuzz/               # Fuzzing tests (future)
├── MANUAL_TESTING.md   # Manual test procedures
└── README.md          # This file
```

## Running Automated Tests

### Build and Run All Tests

```bash
# From project root
meson setup build
ninja -C build
meson test -C build
```

### Run Specific Tests

```bash
# Run individual unit tests
meson test -C build "Common utilities"
meson test -C build "Configuration"
meson test -C build "Whitelist"
meson test -C build "Whitelist Advanced"
meson test -C build "IP Tracker"
meson test -C build "IP Tracker Advanced"
meson test -C build "Logger"
meson test -C build "Proc Parser"

# Run integration tests
meson test -C build "Detection Flow"
meson test -C build "Config Integration"
meson test -C build "Whitelist Integration"
meson test -C build "Blocking Scenarios"
meson test -C build "Performance Stress"
```

### Run Tests with Verbose Output

```bash
meson test -C build --verbose
```

### Run Tests Directly

```bash
# Unit tests
./build/test_common
./build/test_config
./build/test_whitelist
./build/test_whitelist_advanced
./build/test_tracker
./build/test_tracker_advanced
./build/test_logger
./build/test_procparse

# Integration tests
./build/test_detection_flow
./build/test_config_integration
./build/test_whitelist_integration
./build/test_blocking_scenarios
./build/test_performance_stress
```

## Test Coverage

### Unit Tests

#### test_common.c
Tests utility functions in `common.h`:
- IP hash function consistency and distribution
- Time conversion functions (ms/s to nanoseconds)
- Monotonic clock function

#### test_config.c
Tests configuration module (`config.c`):
- Loading configuration from file
- Default value handling
- Configuration validation
- Log level parsing
- Invalid configuration detection

#### test_whitelist.c
Tests whitelist module (`whitelist.c`):
- Adding CIDR blocks to whitelist
- IP address checking against whitelist
- Single IP (/32) whitelisting
- Localhost range handling
- Loading whitelist from file
- Whitelist entry counting

#### test_tracker.c
Tests IP tracker module (`tracker.c`):
- Tracker table creation/destruction
- IP entry creation and retrieval
- Multiple IP tracking
- Entry removal
- SYN count tracking
- Blocked IP tracking
- Expiry detection
- Table statistics

### Integration Tests

#### test_detection_flow.c
Tests the complete detection flow:
- Basic SYN flood detection
- Whitelist integration with detection
- Time window expiry handling
- Multiple simultaneous attackers
- Block expiry and unblocking

#### test_config_integration.c
Tests configuration integration with system components:
- Config affecting tracker table size and behavior
- Config affecting whitelist file loading
- Config validation with real components
- Dynamic configuration reload scenarios

#### test_whitelist_integration.c
Tests whitelist integration with detection and blocking:
- Whitelist preventing false positives in detection
- Whitelist override during active attacks
- Multiple CIDR ranges interacting with tracker
- Whitelist file format and reload behavior

#### test_blocking_scenarios.c
Tests various IP blocking and expiry scenarios:
- Automatic blocking on threshold breach
- Block expiry and IP unblocking
- Multiple IPs blocked simultaneously
- Block duration configuration effects
- Tracker state during and after blocking

#### test_performance_stress.c
Performance and stress testing:
- High-volume SYN packet processing
- Tracker performance under load (10,000+ IPs)
- Memory usage and leak detection
- Concurrent access patterns
- Rate limiting edge cases

## Test Requirements

### Automated Tests
- No special privileges required
- No network access required
- All dependencies mocked or isolated

### Manual Tests
See [MANUAL_TESTING.md](MANUAL_TESTING.md) for:
- Root access requirements
- Network setup
- System dependencies
- Performance testing

## Adding New Tests

### Creating a New Unit Test

1. Create test file in `tests/unit/`:
```c
#include "../unity/unity.h"
#include "../../include/common.h"
#include "../../src/module/yourmodule.h"

TEST_CASE(test_your_feature) {
    // Test code
    TEST_ASSERT_EQUAL(expected, actual);
}

int main(void) {
    UnityBegin("test_yourmodule.c");
    RUN_TEST(test_your_feature);
    return UnityEnd();
}
```

2. Add to `meson.build`:
```meson
test_yourmodule = executable('test_yourmodule',
  'tests/unit/test_yourmodule.c',
  test_sources_common,
  unity_sources,
  include_directories: [inc, unity_inc],
  dependencies: deps,
)

test('Your Module', test_yourmodule)
```

3. Build and run:
```bash
meson setup build --reconfigure
ninja -C build
meson test -C build
```

## Unity Test Framework

This project uses a minimal Unity test framework for C testing.

### Available Assertions

```c
TEST_ASSERT(condition)
TEST_ASSERT_TRUE(condition)
TEST_ASSERT_FALSE(condition)
TEST_ASSERT_EQUAL(expected, actual)
TEST_ASSERT_NOT_EQUAL(expected, actual)
TEST_ASSERT_EQUAL_INT(expected, actual)
TEST_ASSERT_EQUAL_UINT32(expected, actual)
TEST_ASSERT_EQUAL_UINT64(expected, actual)
TEST_ASSERT_EQUAL_STRING(expected, actual)
TEST_ASSERT_NULL(pointer)
TEST_ASSERT_NOT_NULL(pointer)
TEST_ASSERT_GREATER_THAN(threshold, actual)
TEST_ASSERT_LESS_THAN(threshold, actual)
```

### Test Structure

```c
TEST_CASE(test_name) {
    // Setup
    // Execute
    // Assert
    // Cleanup (if needed)
}

int main(void) {
    UnityBegin("test_file.c");
    RUN_TEST(test_name);
    return UnityEnd();
}
```

## Continuous Integration

Tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions
test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v2
    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y meson ninja-build \
          libnetfilter-queue-dev libmnl-dev \
          libipset-dev libconfig-dev libsystemd-dev
    - name: Build
      run: |
        meson setup build
        ninja -C build
    - name: Test
      run: meson test -C build --verbose
```

## Test Results

Test results are stored in `build/meson-logs/testlog.txt`.

View detailed results:
```bash
cat build/meson-logs/testlog.txt
```

## Debugging Failed Tests

### Verbose Test Output
```bash
meson test -C build --verbose
```

### Run Test Under GDB
```bash
gdb ./build/test_common
(gdb) run
```

### Run Test Under Valgrind
```bash
valgrind --leak-check=full ./build/test_common
```

## Performance Benchmarks

Some tests include basic performance assertions:
- IP hash distribution
- Tracker table operations
- Whitelist lookups

For detailed performance testing, see MANUAL_TESTING.md section on Performance Test.

## Test Maintenance

- Update tests when adding new features
- Ensure backward compatibility
- Keep test coverage above 80%
- Run tests before committing changes

## Contributing Tests

When contributing:
1. Write tests for new features
2. Ensure all tests pass
3. Follow existing test patterns
4. Document test purpose and setup
5. Include both positive and negative test cases
