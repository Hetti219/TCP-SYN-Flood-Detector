# Contributing to TCP SYN Flood Detector

Thank you for your interest in contributing to the TCP SYN Flood Detector project! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Security](#security)

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. We expect all contributors to:

- Be respectful and constructive in all interactions
- Focus on what is best for the project and community
- Show empathy towards other community members
- Accept constructive criticism gracefully

---

## Getting Started

### Prerequisites

Before you begin, ensure you have the required dependencies installed:

```bash
sudo apt-get install -y \
  meson \
  ninja-build \
  libnetfilter-queue-dev \
  libmnl-dev \
  libipset-dev \
  libconfig-dev \
  libsystemd-dev \
  pkg-config \
  git
```

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/Hetti219/TCP-SYN-Flood-Detector.git
   cd TCP-SYN-Flood-Detector
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/ORIGINAL-OWNER/synflood-detector.git
   ```

### Build the Project

```bash
meson setup build
ninja -C build
meson test -C build
```

---

## Development Workflow

### Branching Strategy

- `main`: Stable, production-ready code
- `develop`: Integration branch for features (if used)
- Feature branches: `feature/description` or `fix/description`

### Creating a Feature Branch

```bash
git checkout -b feature/my-new-feature
```

### Keeping Your Fork Updated

```bash
git fetch upstream
git checkout main
git merge upstream/main
git push origin main
```

---

## Coding Standards

### C Code Style

Follow these conventions for consistency:

**Naming Conventions**:
- Functions: `snake_case` (e.g., `tracker_add_ip`)
- Variables: `snake_case` (e.g., `packet_count`)
- Constants/Macros: `UPPER_SNAKE_CASE` (e.g., `MAX_CONNECTIONS`)
- Structs/Typedefs: `snake_case_t` (e.g., `synflood_config_t`)

**Indentation**:
- Use 4 spaces (no tabs)
- Opening brace on same line for functions
- K&R style bracing

**Example**:
```c
int tracker_add_ip(tracker_t *tracker, uint32_t ip_addr) {
    if (!tracker) {
        return -1;
    }

    // Implementation here
    for (int i = 0; i < MAX_IPS; i++) {
        if (tracker->ips[i] == 0) {
            tracker->ips[i] = ip_addr;
            return 0;
        }
    }

    return -1;
}
```

**Comments**:
- Use `//` for single-line comments
- Use `/* */` for multi-line comments
- Document complex algorithms and non-obvious logic
- Add function-level documentation for public APIs

**Security**:
- Always validate input parameters
- Check buffer bounds
- Use safe string functions (`strncpy`, `snprintf`)
- Avoid `system()` calls - use `fork()` + `exec()`
- Clear sensitive data after use

### Static Analysis

Before submitting, run static analysis tools:

```bash
# cppcheck
cppcheck --enable=all --suppress=missingIncludeSystem -I include/ src/

# clang-tidy
clang-tidy src/**/*.c -p=build
```

---

## Testing

### Running Tests

Run all tests:
```bash
meson test -C build --verbose
```

Run specific test:
```bash
meson test -C build test_tracker --verbose
```

### Writing Tests

We use the Unity test framework. Place tests in `tests/unit/` or `tests/integration/`.

**Example Unit Test**:
```c
#include "unity.h"
#include "tracker.h"

void setUp(void) {
    // Setup before each test
}

void tearDown(void) {
    // Cleanup after each test
}

void test_tracker_add_ip_success(void) {
    tracker_t tracker = {0};
    uint32_t ip = 0x01020304;

    int result = tracker_add_ip(&tracker, ip);

    TEST_ASSERT_EQUAL(0, result);
    TEST_ASSERT_EQUAL(ip, tracker.ips[0]);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_tracker_add_ip_success);
    return UNITY_END();
}
```

### Test Coverage

Aim for:
- Unit tests: All public APIs
- Integration tests: Critical workflows
- Edge cases: Boundary conditions, error paths

---

## Submitting Changes

### Before Submitting

1. **Update your branch**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run all tests**:
   ```bash
   meson test -C build
   ```

3. **Run static analysis**:
   ```bash
   cppcheck --enable=all -I include/ src/
   ```

4. **Build successfully**:
   ```bash
   ninja -C build
   ```

5. **Update documentation** if needed

### Commit Messages

Write clear, descriptive commit messages:

**Format**:
```
type(scope): Brief description (50 chars max)

Detailed explanation of what and why (wrap at 72 chars).

Fixes #123
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `build`: Build system changes
- `ci`: CI/CD changes

**Example**:
```
fix(tracker): Prevent integer overflow in packet counter

The packet counter could overflow on high-traffic systems, causing
incorrect detection. Added bounds checking and wraparound handling.

Fixes #42
```

### Creating a Pull Request

1. Push your changes:
   ```bash
   git push origin feature/my-new-feature
   ```

2. Go to GitHub and create a Pull Request

3. Fill out the PR template completely

4. Link related issues

5. Wait for CI/CD checks to pass

6. Address review feedback

### PR Review Process

- All PRs require at least one approval
- CI/CD checks must pass
- Code must follow project standards
- Tests must be included for new features

---

## Security

### Reporting Security Vulnerabilities

**DO NOT** open a public issue for security vulnerabilities.

Instead:
1. Go to the repository's **Security** tab
2. Click **Report a vulnerability**
3. Provide details privately

Or email: [security contact if available]

### Security Best Practices

When contributing code that handles:
- Network packets
- System calls
- File I/O
- External commands

Please ensure:
- Input validation is thorough
- Buffer overflows are impossible
- No command injection vulnerabilities
- Proper error handling
- Security flags are enabled (FORTIFY_SOURCE, stack protector, etc.)

---

## Recognition

Contributors will be:
- Listed in the project's contributors
- Mentioned in release notes for significant contributions
- Given credit in commit history

---

## Questions?

- Check existing [Issues](https://github.com/Hetti219/TCP-SYN-Flood-Detector/issues)
- Start a [Discussion](https://github.com/Hetti219/TCP-SYN-Flood-Detector/discussions)
- Review the [Documentation](../docs/)

---

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (MIT License).

---

Thank you for contributing to making the internet more secure!
