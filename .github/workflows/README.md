# GitHub Actions Workflows

This directory contains CI/CD workflows for the TCP SYN Flood Detector project. These workflows are configured for a public repository accepting community contributions.

## 🔒 Security Model

**Important:** These workflows DO NOT auto-merge PRs. All contributions require manual review by maintainers after passing automated checks.

## Workflows Overview

### 1. CI/CD Pipeline ([ci.yml](ci.yml))

**Triggers**: Push to main/develop, Pull Requests, Manual dispatch

**Jobs**:
- **Build & Test**: Compiles the project and runs all tests on multiple configurations
  - Platforms: Ubuntu 22.04, Ubuntu 24.04
  - Compilers: GCC, Clang
  - Validates successful installation

- **Static Analysis**: Runs code quality checks
  - `cppcheck`: General C/C++ static analysis
  - `clang-tidy`: Advanced linting and code quality checks

- **Security Hardening Check**: Verifies security features
  - Full RELRO (Relocation Read-Only)
  - Stack canaries
  - NX (No Execute)
  - PIE (Position Independent Executable)

- **Documentation Validation**: Ensures documentation quality
  - Man page syntax validation
  - Required documentation files check

**Artifacts**: Build logs (on failure), static analysis reports

---

### 2. CodeQL Security Analysis ([codeql.yml](codeql.yml))

**Triggers**: Push to main/develop, Pull Requests to main, Weekly schedule (Mondays 2:30 AM UTC), Manual dispatch

**Purpose**: Automated security vulnerability scanning using GitHub's semantic code analysis engine

**Features**:
- Detects common security vulnerabilities (SQL injection, XSS, buffer overflows, etc.)
- Runs security-and-quality query suite
- Results appear in GitHub Security tab
- Scheduled weekly scans for continuous monitoring

**Language**: C/C++

---

### 3. Release Automation ([release.yml](release.yml))

**Triggers**:
- Git tags matching `v*.*.*` (e.g., v1.0.0, v1.2.3)
- Manual dispatch with version input

**Jobs**:
- **Build Release Artifacts**:
  - Builds optimized release binary
  - Runs full test suite
  - Creates installation tarball
  - Generates SHA256 checksums
  - Creates source tarball

- **Create GitHub Release**:
  - Automatically creates GitHub release
  - Attaches build artifacts and checksums
  - Extracts release notes from CHANGELOG.md (if available)

- **Publish Documentation**:
  - Deploys documentation to GitHub Pages (optional)

**Artifacts**:
- Binary tarball: `synflood-detector-{version}-linux-x86_64.tar.gz`
- Source tarball: `synflood-detector-{version}-source.tar.gz`
- SHA256 checksums for both

---

### 4. Dependency Review ([dependency-review.yml](dependency-review.yml))

**Triggers**: All Pull Requests

**Purpose**: Scan dependencies for security vulnerabilities and license compliance

**Features**:
- Fails on moderate+ severity vulnerabilities
- Checks for incompatible licenses (GPL-3.0, AGPL-3.0)
- Verifies system dependencies can be installed
- Comments on PRs when issues are found

**Required for PR Merge**: ✅ Yes

---

### 5. Code Quality ([code-quality.yml](code-quality.yml))

**Triggers**: Pull Requests modifying C/H files

**Purpose**: Enforce code quality standards and best practices

**Checks**:
- Code style (debug prints, hardcoded paths, TODOs)
- File permissions (source files shouldn't be executable)
- Trailing whitespace and indentation consistency
- Cyclomatic complexity analysis (with lizard)
- Security patterns (unsafe functions, potential vulnerabilities)

**Required for PR Merge**: ⚠️ Warning only (non-blocking, but should be addressed)

---

### 6. PR Validation ([pr-checks.yml](pr-checks.yml))

**Triggers**: PR opened, updated, or edited

**Purpose**: Validate PR structure and guide contributors

**Checks**:
- Commit message quality
- Breaking changes detection
- PR size warnings (>1000 lines or >20 files)
- Required file updates (docs, tests)
- Auto-merge prevention
- First-time contributor welcome

**Required for PR Merge**: ℹ️ Informational (provides guidance)

---

### 7. PR Labels ([pr-labels.yml](pr-labels.yml))

**Triggers**: PR opened or updated

**Purpose**: Automatic PR organization and contributor guidance

**Features**:
- Auto-labels based on changed files (documentation, core, tests, build, etc.)
- Checks PR description quality
- Reminds contributors to add tests for code changes
- Adds `needs-tests` label when applicable

**Configuration**: See [.github/labeler.yml](../labeler.yml)

---

## Required Status Checks for PR Merge

To merge a PR, the following must be satisfied:

1. ✅ **CI/CD Pipeline** - All jobs pass (build-and-test, static-analysis, security-hardening-check, documentation-check)
2. ✅ **CodeQL Security Analysis** - No critical vulnerabilities detected
3. ✅ **Dependency Review** - No vulnerable dependencies or license conflicts
4. 👀 **Manual Review** - At least one maintainer approval required
5. 🚫 **No Auto-Merge** - All PRs merged manually by maintainers

---

## Workflow Status Badges

Add these badges to your README.md to show build status:

```markdown
![CI/CD Pipeline](https://github.com/Hetti219/TCP-SYN-Flood-Detector/actions/workflows/ci.yml/badge.svg)
![CodeQL](https://github.com/Hetti219/TCP-SYN-Flood-Detector/actions/workflows/codeql.yml/badge.svg)
```

---

## For Contributors

### What to Expect When Opening a PR

When you submit a pull request:

1. **Automated checks start immediately**
   - Build & test on multiple platforms/compilers
   - Security scanning with CodeQL
   - Code quality analysis
   - Dependency security review

2. **You'll receive automated feedback**
   - Bot comments about PR structure and quality
   - Auto-labeling based on changed files
   - Reminders about tests/documentation if needed
   - Welcome message (for first-time contributors)

3. **Maintainer review**
   - After automated checks pass, maintainers review manually
   - They may request changes or ask questions
   - Once approved, maintainers merge manually (no auto-merge)

### Making Checks Pass

**If CI/CD Pipeline fails:**
- Check build logs in the Actions tab
- Run tests locally: `meson test -C build --verbose`
- Fix any compiler warnings or errors

**If CodeQL finds issues:**
- Review security findings in the Security tab
- Address identified vulnerabilities
- Run `cppcheck` locally to catch issues early

**If Dependency Review fails:**
- Check for vulnerable dependencies
- Update to patched versions if available

**If Code Quality warns:**
- Review the complexity and security reports
- Fix security patterns (unsafe string functions, etc.)
- Clean up code style issues

---

## For Maintainers

### Merging PRs - Required Checklist

Before merging any PR:

1. ✅ All automated checks pass
2. 👀 Manual code review completed
3. 🔒 Security implications considered
4. 📚 Documentation updated (if behavior changed)
5. 🧪 Tests added/updated (for new features or fixes)
6. ✍️ Merge manually - never use auto-merge

### Branch Protection Settings

Configure these settings on `main` branch:

```yaml
Require pull request reviews: 1 approval
Require status checks to pass:
  - build-and-test (Ubuntu 22.04, gcc)
  - build-and-test (Ubuntu 22.04, clang)
  - build-and-test (Ubuntu 24.04, gcc)
  - build-and-test (Ubuntu 24.04, clang)
  - static-analysis
  - security-hardening-check
  - CodeQL
  - dependency-review
Require conversation resolution: true
Do not allow bypassing: true
Restrict pushes to admins only
```

---

## How to Use

### Running Workflows Manually

All workflows support manual triggering via the GitHub Actions UI:

1. Go to your repository's **Actions** tab
2. Select the workflow you want to run
3. Click **Run workflow**
4. Select the branch and fill in any required inputs
5. Click **Run workflow**

### Creating a Release

**Option 1: Using Git Tags (Recommended)**
```bash
# Create and push a new tag
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0
```

**Option 2: Manual Workflow Dispatch**
1. Go to Actions > Release
2. Click "Run workflow"
3. Enter version (e.g., v1.0.0)
4. Click "Run workflow"

### Viewing Security Scan Results

CodeQL results appear in:
- **Security** tab > **Code scanning alerts**
- Pull request checks (for PRs)

---

## Dependencies

The workflows require these system packages (automatically installed):
- meson
- ninja-build
- libnetfilter-queue-dev
- libmnl-dev
- libipset-dev
- libconfig-dev
- libsystemd-dev
- pkg-config

For static analysis:
- cppcheck
- clang-tidy
- checksec

---

## Workflow Configuration

### Customizing Build Matrix

Edit [ci.yml](ci.yml) to change platforms or compilers:

```yaml
matrix:
  os: [ubuntu-22.04, ubuntu-24.04]  # Add more Ubuntu versions
  compiler: [gcc, clang]              # Add specific versions like gcc-12
```

### Adjusting Security Checks

Modify the `checksec` verification in [ci.yml](ci.yml) to add/remove security features.

### Changing CodeQL Schedule

Edit the cron schedule in [codeql.yml](codeql.yml):

```yaml
schedule:
  - cron: '30 2 * * 1'  # Every Monday at 2:30 AM UTC
```

---

## Troubleshooting

### Build Failures

1. Check the **Actions** tab for detailed logs
2. Download build artifacts if available
3. Review meson-logs for compilation errors

### Test Failures

Tests run with `--verbose --print-errorlogs` for maximum detail. Check:
- Test output in the workflow log
- Uploaded test logs (if available)

### Security Scan False Positives

CodeQL may report false positives. To suppress:
1. Review the alert in GitHub Security tab
2. If it's a false positive, dismiss it with a reason
3. Consider adding inline suppression comments in code

### Release Workflow Issues

- Ensure you have write permissions to create releases
- Check that the tag format matches `v*.*.*`
- Verify GITHUB_TOKEN has necessary permissions

---

## Contributing

When modifying workflows:
1. Test changes in a fork or feature branch first
2. Use `workflow_dispatch` trigger for testing
3. Document any new jobs or steps
4. Update this README with changes

---

## Security Considerations

### Workflow Security

- Workflows run in isolated GitHub-hosted runners
- Minimal permissions (principle of least privilege)
- No secrets exposed in logs
- CodeQL scans are private and only visible to repository collaborators
- Release artifacts are signed with SHA256 checksums
- **No auto-merge capabilities** - all PRs require manual review

### Security Best Practices Implemented

- ✅ All workflows have explicit `permissions:` blocks
- ✅ Pull request workflows are read-only by default
- ✅ No execution of untrusted code from PRs
- ✅ Dependency scanning on all PRs
- ✅ Automated security vulnerability detection
- ✅ Manual approval required before merge

### Reporting Workflow Security Issues

If you discover a security vulnerability in these workflows:

1. **Do not open a public issue**
2. Contact maintainers privately via email
3. See SECURITY.md for responsible disclosure process

---

## Further Reading

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [Meson Build System](https://mesonbuild.com/)
