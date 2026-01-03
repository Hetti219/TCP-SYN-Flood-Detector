# GitHub Actions Workflows

This directory contains CI/CD workflows for the TCP SYN Flood Detector project.

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

## Workflow Status Badges

Add these badges to your README.md to show build status:

```markdown
![CI/CD Pipeline](https://github.com/USERNAME/REPO/actions/workflows/ci.yml/badge.svg)
![CodeQL](https://github.com/USERNAME/REPO/actions/workflows/codeql.yml/badge.svg)
```

Replace `USERNAME` and `REPO` with your GitHub username and repository name.

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

- Workflows run in isolated GitHub-hosted runners
- No secrets are exposed in logs
- CodeQL scans are private and only visible to repository collaborators
- Release artifacts are signed with SHA256 checksums

---

## Further Reading

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [Meson Build System](https://mesonbuild.com/)
