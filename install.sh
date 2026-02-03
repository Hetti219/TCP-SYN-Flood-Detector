#!/usr/bin/env bash
#
# TCP SYN Flood Detector - Installation Script
# Supports: Ubuntu 22.04, 24.04, Debian 11, 12 (x86_64 only)
#
# Usage: curl -fsSL https://raw.githubusercontent.com/Hetti219/TCP-SYN-Flood-Detector/main/install.sh | sudo bash
#

set -euo pipefail

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Installation paths (matching meson.build with --prefix=/usr/local)
readonly INSTALL_PREFIX="/usr/local"
readonly BIN_DIR="${INSTALL_PREFIX}/bin"
readonly SYSCONF_DIR="/etc/synflood-detector"
readonly SYSTEMD_DIR="/usr/local/lib/systemd/system"
readonly DOC_DIR="${INSTALL_PREFIX}/share/doc/synflood-detector"
readonly MAN_DIR="${INSTALL_PREFIX}/share/man/man8"

# GitHub repository information
readonly GITHUB_REPO="Hetti219/TCP-SYN-Flood-Detector"
readonly GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"
readonly GITHUB_RAW="https://raw.githubusercontent.com/${GITHUB_REPO}"

# Runtime variables
INSTALL_VERSION=""
NON_INTERACTIVE=false
SKIP_DEPS=false
NO_SERVICE=false
TEMP_DIR=""

# ============================================================================
# Utility Functions
# ============================================================================

info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

cleanup_on_error() {
    local exit_code=$?
    if [[ ${exit_code} -ne 0 ]]; then
        error "Installation failed with exit code ${exit_code}"

        # Clean up temporary files
        if [[ -n "${TEMP_DIR}" && -d "${TEMP_DIR}" ]]; then
            rm -rf "${TEMP_DIR}"
        fi

        echo ""
        echo "Partial installation may exist. To clean up, run:"
        echo "  curl -fsSL ${GITHUB_RAW}/main/uninstall.sh | sudo bash"
    fi
}

trap cleanup_on_error EXIT

show_help() {
    cat << EOF
TCP SYN Flood Detector - Installation Script

Usage: $0 [OPTIONS]

Options:
  --version VERSION     Install specific version (e.g., v1.0.0)
  --non-interactive    Skip all prompts, use defaults
  --skip-deps          Skip dependency installation
  --no-service         Don't enable or start service
  --help               Show this help message

Examples:
  # Interactive install (default)
  sudo $0

  # Install specific version
  sudo $0 --version v1.0.0

  # Non-interactive with defaults
  sudo $0 --non-interactive

  # Install without starting service
  sudo $0 --no-service

For more information, visit: https://github.com/${GITHUB_REPO}
EOF
    exit 0
}

# ============================================================================
# Pre-flight Checks
# ============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root or with sudo"
        echo "Please run: sudo $0"
        exit 1
    fi
}

check_os_compatibility() {
    info "Checking OS compatibility..."

    if [[ ! -f /etc/os-release ]]; then
        error "Unable to detect operating system"
        exit 2
    fi

    source /etc/os-release

    case "${ID}" in
        ubuntu)
            if [[ "${VERSION_ID}" != "22.04" && "${VERSION_ID}" != "24.04" ]]; then
                error "Unsupported Ubuntu version: ${VERSION_ID}"
                error "Supported versions: 22.04, 24.04"
                exit 2
            fi
            ;;
        debian)
            if [[ "${VERSION_ID}" != "11" && "${VERSION_ID}" != "12" ]]; then
                error "Unsupported Debian version: ${VERSION_ID}"
                error "Supported versions: 11, 12"
                exit 2
            fi
            ;;
        *)
            error "Unsupported operating system: ${ID}"
            error "Supported: Ubuntu 22.04/24.04, Debian 11/12"
            exit 2
            ;;
    esac

    success "OS compatible: ${PRETTY_NAME}"
}

check_architecture() {
    info "Checking architecture..."

    local arch
    arch=$(uname -m)

    if [[ "${arch}" != "x86_64" ]]; then
        error "Unsupported architecture: ${arch}"
        error "Only x86_64 is supported for pre-built binaries"
        exit 3
    fi

    success "Architecture compatible: ${arch}"
}

check_internet_connectivity() {
    info "Checking internet connectivity..."

    if ! curl -sI https://github.com --max-time 5 > /dev/null 2>&1; then
        error "No internet connection detected"
        error "Cannot download release from GitHub"
        exit 4
    fi

    success "Internet connection available"
}

# ============================================================================
# Dependency Management
# ============================================================================

install_runtime_dependencies() {
    if [[ "${SKIP_DEPS}" == "true" ]]; then
        info "Skipping dependency installation (--skip-deps specified)"
        return 0
    fi

    info "Installing runtime dependencies..."

    # Update package lists
    if ! apt-get update -qq; then
        error "Failed to update package lists"
        exit 5
    fi

    # Install dependencies
    local deps=(
        libnetfilter-queue1
        libmnl0
        libipset13
        libconfig9
        libsystemd0
        iptables
        ipset
    )

    if ! apt-get install -y "${deps[@]}"; then
        error "Failed to install runtime dependencies"
        exit 5
    fi

    success "Runtime dependencies installed"
}

# ============================================================================
# Download and Verification
# ============================================================================

get_latest_release_version() {
    info "Fetching latest release version..."

    local version

    # Try using jq if available
    if command -v jq &> /dev/null; then
        version=$(curl -sL "${GITHUB_API}/releases/latest" | jq -r '.tag_name')
    else
        # Fallback to grep/sed parsing
        version=$(curl -sL "${GITHUB_API}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"tag_name": "([^"]+)".*/\1/')
    fi

    if [[ -z "${version}" || "${version}" == "null" ]]; then
        error "Failed to fetch latest release version"
        error "Please specify version with --version flag"
        exit 6
    fi

    echo "${version}"
}

download_release_tarball() {
    local version="$1"
    local arch="linux-x86_64"
    local filename="synflood-detector-${version}-${arch}.tar.gz"
    local url="https://github.com/${GITHUB_REPO}/releases/download/${version}/${filename}"

    info "Downloading ${filename}..."

    if ! curl -fL --progress-bar -o "${TEMP_DIR}/${filename}" "${url}"; then
        error "Failed to download release tarball"
        error "URL: ${url}"
        exit 7
    fi

    success "Downloaded ${filename}"

    # Download checksum file
    if curl -fsSL -o "${TEMP_DIR}/${filename}.sha256" "${url}.sha256" 2>/dev/null; then
        success "Downloaded checksum file"
    else
        warn "Checksum file not available, skipping verification"
    fi

    echo "${filename}"
}

verify_checksum() {
    local filename="$1"

    if [[ ! -f "${TEMP_DIR}/${filename}.sha256" ]]; then
        warn "Skipping checksum verification (no checksum file)"
        return 0
    fi

    info "Verifying SHA256 checksum..."

    cd "${TEMP_DIR}"
    if ! sha256sum -c "${filename}.sha256" 2>&1 | grep -q "OK"; then
        error "Checksum verification failed!"
        error "Downloaded file may be corrupted or tampered with"
        exit 8
    fi

    success "Checksum verified successfully"
}

extract_tarball() {
    local filename="$1"

    info "Extracting tarball..."

    if ! tar -xzf "${TEMP_DIR}/${filename}" -C "${TEMP_DIR}"; then
        error "Failed to extract tarball"
        exit 9
    fi

    # Find the extracted directory
    local extract_dir
    extract_dir=$(find "${TEMP_DIR}" -maxdepth 1 -type d -name "synflood-detector-*" | head -n1)

    if [[ -z "${extract_dir}" ]]; then
        error "Failed to locate extracted directory"
        exit 9
    fi

    success "Extracted to ${extract_dir}"
    echo "${extract_dir}"
}

# ============================================================================
# Installation Functions
# ============================================================================

install_binary() {
    local extract_dir="$1"

    info "Installing binary to ${BIN_DIR}..."

    if [[ ! -f "${extract_dir}/bin/synflood-detector" ]]; then
        error "Binary not found in tarball"
        exit 10
    fi

    install -D -m 0755 "${extract_dir}/bin/synflood-detector" "${BIN_DIR}/synflood-detector"

    success "Binary installed to ${BIN_DIR}/synflood-detector"
}

install_config_files() {
    local extract_dir="$1"

    info "Installing configuration files..."

    # Create config directory
    install -d -m 0755 "${SYSCONF_DIR}"

    # Install main config file
    if [[ -f "${SYSCONF_DIR}/synflood-detector.conf" ]]; then
        warn "Config file exists, installing as synflood-detector.conf.new"
        install -m 0644 "${extract_dir}/conf/synflood-detector.conf" \
            "${SYSCONF_DIR}/synflood-detector.conf.new"
    else
        install -m 0644 "${extract_dir}/conf/synflood-detector.conf" \
            "${SYSCONF_DIR}/synflood-detector.conf"
        success "Installed synflood-detector.conf"
    fi

    # Install whitelist config
    if [[ -f "${SYSCONF_DIR}/whitelist.conf" ]]; then
        warn "Whitelist exists, installing as whitelist.conf.new"
        install -m 0644 "${extract_dir}/conf/whitelist.conf" \
            "${SYSCONF_DIR}/whitelist.conf.new"
    else
        install -m 0644 "${extract_dir}/conf/whitelist.conf" \
            "${SYSCONF_DIR}/whitelist.conf"
        success "Installed whitelist.conf"
    fi

    # Install configuration presets
    if [[ -d "${extract_dir}/conf/presets" ]]; then
        install -d -m 0755 "${SYSCONF_DIR}/presets"
        for preset_file in "${extract_dir}"/conf/presets/*.conf; do
            if [[ -f "$preset_file" ]]; then
                install -m 0644 "$preset_file" "${SYSCONF_DIR}/presets/"
            fi
        done
        # Install README if present
        if [[ -f "${extract_dir}/conf/presets/README.md" ]]; then
            install -m 0644 "${extract_dir}/conf/presets/README.md" "${SYSCONF_DIR}/presets/"
        fi
        success "Installed configuration presets to ${SYSCONF_DIR}/presets"
    fi

    success "Configuration files installed to ${SYSCONF_DIR}"
}

install_systemd_service() {
    local extract_dir="$1"

    info "Installing systemd service..."

    install -D -m 0644 "${extract_dir}/conf/synflood-detector.service" \
        "${SYSTEMD_DIR}/synflood-detector.service"

    # Reload systemd
    if ! systemctl daemon-reload; then
        warn "Failed to reload systemd daemon"
    fi

    success "Systemd service installed"
}

install_documentation() {
    local extract_dir="$1"

    info "Installing documentation..."

    install -d -m 0755 "${DOC_DIR}"

    if [[ -d "${extract_dir}/docs" ]]; then
        for doc in "${extract_dir}"/docs/*.md; do
            if [[ -f "$doc" ]]; then
                install -m 0644 "$doc" "${DOC_DIR}/"
            fi
        done
        success "Documentation installed to ${DOC_DIR}"
    else
        warn "Documentation not found in tarball"
    fi
}

install_man_page() {
    local extract_dir="$1"

    info "Installing man page..."

    if [[ -f "${extract_dir}/man/synflood-detector.8" ]]; then
        install -D -m 0644 "${extract_dir}/man/synflood-detector.8" \
            "${MAN_DIR}/synflood-detector.8"

        # Update man database
        mandb -q 2>/dev/null || true

        success "Man page installed"
    else
        warn "Man page not found in tarball"
    fi
}

install_management_tool() {
    local extract_dir="$1"

    info "Installing synflood-ctl management tool..."

    if [[ -f "${extract_dir}/tools/synflood-ctl" ]]; then
        install -D -m 0755 "${extract_dir}/tools/synflood-ctl" \
            "${BIN_DIR}/synflood-ctl"
        success "synflood-ctl installed to ${BIN_DIR}/synflood-ctl"
    else
        warn "synflood-ctl not found in tarball"
    fi
}

# ============================================================================
# Interactive Configuration
# ============================================================================

prompt_yes_no() {
    local prompt="$1"
    local default="${2:-y}" # Default to yes

    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
        return 0 # Default to yes in non-interactive mode
    fi

    local reply
    read -p "${prompt} " -n 1 -r reply
    echo

    if [[ -z "${reply}" ]]; then
        reply="${default}"
    fi

    [[ "${reply}" =~ ^[Yy]$ ]]
}

prompt_enable_service() {
    if [[ "${NO_SERVICE}" == "true" ]]; then
        info "Skipping service configuration (--no-service specified)"
        return 0
    fi

    echo ""
    if prompt_yes_no "Enable synflood-detector service on boot? [Y/n]:" "y"; then
        if systemctl enable synflood-detector 2>/dev/null; then
            success "Service enabled"
        else
            error "Failed to enable service"
            return 1
        fi
    else
        info "Service not enabled"
        info "You can enable it later with: systemctl enable synflood-detector"
    fi
}

prompt_start_service() {
    if [[ "${NO_SERVICE}" == "true" ]]; then
        return 0
    fi

    echo ""
    if prompt_yes_no "Start synflood-detector service now? [Y/n]:" "y"; then
        if systemctl start synflood-detector 2>/dev/null; then
            success "Service started"

            # Show status
            sleep 1
            echo ""
            systemctl status synflood-detector --no-pager -l || true
        else
            error "Failed to start service"
            echo "Check logs with: journalctl -u synflood-detector -n 50"
            return 1
        fi
    else
        info "Service not started"
        info "You can start it later with: systemctl start synflood-detector"
    fi
}

prompt_whitelist_ips() {
    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
        return 0
    fi

    echo ""
    echo "The whitelist prevents legitimate IPs from being blocked."
    echo "Current whitelist location: ${SYSCONF_DIR}/whitelist.conf"
    echo ""

    if prompt_yes_no "Add IPs to whitelist now? [y/N]:" "n"; then
        configure_whitelist
    else
        info "You can edit the whitelist later: ${SYSCONF_DIR}/whitelist.conf"
    fi
}

configure_whitelist() {
    echo ""
    echo "Enter IP addresses or CIDR ranges to whitelist (one per line)."
    echo "Examples: 192.168.1.100 or 10.0.0.0/8"
    echo "Press Ctrl+D when done."
    echo ""

    local tmpfile
    tmpfile=$(mktemp)

    while IFS= read -r line; do
        # Basic validation (simple IPv4 regex)
        if [[ ${line} =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
            echo "$line" >> "$tmpfile"
        else
            warn "Invalid IP/CIDR: $line (skipped)"
        fi
    done

    if [[ -s "$tmpfile" ]]; then
        cat "$tmpfile" >> "${SYSCONF_DIR}/whitelist.conf"
        local count
        count=$(wc -l < "$tmpfile")
        success "Added ${count} entries to whitelist"
    fi

    rm -f "$tmpfile"
}

# ============================================================================
# Post-Installation Setup
# ============================================================================

setup_ipset() {
    info "Setting up ipset..."

    # Check if ipset already exists
    if ipset list synflood_blacklist &>/dev/null; then
        info "ipset 'synflood_blacklist' already exists"
        return 0
    fi

    # Create ipset (this is also done by systemd service)
    if ipset create synflood_blacklist hash:ip timeout 300 maxelem 65536 2>/dev/null; then
        success "ipset created"
    else
        info "ipset will be created by systemd service"
    fi
}

setup_iptables_rules() {
    info "Setting up iptables rules..."

    # Note: These rules are also set by systemd service ExecStartPre

    # Rule 1: Drop packets from blacklisted IPs
    if ! iptables -C INPUT -m set --match-set synflood_blacklist src -j DROP 2>/dev/null; then
        if iptables -I INPUT -m set --match-set synflood_blacklist src -j DROP 2>/dev/null; then
            success "Added iptables DROP rule"
        else
            info "iptables DROP rule will be added by systemd service"
        fi
    else
        info "iptables DROP rule already exists"
    fi

    # Rule 2: Send TCP SYN packets to NFQUEUE
    if ! iptables -C INPUT -p tcp --syn -j NFQUEUE --queue-num 0 2>/dev/null; then
        if iptables -I INPUT -p tcp --syn -j NFQUEUE --queue-num 0 2>/dev/null; then
            success "Added iptables NFQUEUE rule"
        else
            info "iptables NFQUEUE rule will be added by systemd service"
        fi
    else
        info "iptables NFQUEUE rule already exists"
    fi
}

# ============================================================================
# Display Functions
# ============================================================================

display_status() {
    echo ""
    echo "=========================================="
    echo "  Installation Complete!"
    echo "=========================================="
    echo ""
    echo "Installed components:"
    echo "  Binary:        ${BIN_DIR}/synflood-detector"
    echo "  Management:    ${BIN_DIR}/synflood-ctl"
    echo "  Config:        ${SYSCONF_DIR}/synflood-detector.conf"
    echo "  Whitelist:     ${SYSCONF_DIR}/whitelist.conf"
    echo "  Presets:       ${SYSCONF_DIR}/presets/"
    echo "  Service:       ${SYSTEMD_DIR}/synflood-detector.service"
    echo "  Documentation: ${DOC_DIR}/"
    echo "  Man page:      man synflood-detector"
    echo ""
}

# ============================================================================
# Post-Installation Health Verification
# ============================================================================

verify_installation_health() {
    echo ""
    echo "Installation Health Check:"
    echo "--------------------------"

    local all_ok=true
    local warnings=0

    # Check 1: Service is running (skip if --no-service)
    if [[ "${NO_SERVICE}" == "true" ]]; then
        echo -e "${YELLOW}!${NC} Service not started (--no-service specified)"
        ((warnings++))
    elif systemctl is-active --quiet synflood-detector; then
        echo -e "${GREEN}✓${NC} Service is running"
    else
        echo -e "${RED}✗${NC} Service is not running"
        all_ok=false
    fi

    # Check 2: Firewall rules configured (ipset)
    if ipset list synflood_blacklist &>/dev/null; then
        echo -e "${GREEN}✓${NC} Firewall rules configured"
    else
        if [[ "${NO_SERVICE}" == "true" ]] || ! systemctl is-active --quiet synflood-detector; then
            echo -e "${YELLOW}!${NC} Firewall rules pending (service not running)"
            ((warnings++))
        else
            echo -e "${RED}✗${NC} Firewall rules not configured"
            all_ok=false
        fi
    fi

    # Check 3: NFQUEUE rule active (listening for SYN packets)
    if iptables -L INPUT -n 2>/dev/null | grep -q "NFQUEUE"; then
        echo -e "${GREEN}✓${NC} Listening for SYN packets"
    else
        if [[ "${NO_SERVICE}" == "true" ]] || ! systemctl is-active --quiet synflood-detector; then
            echo -e "${YELLOW}!${NC} NFQUEUE rule pending (service not running)"
            ((warnings++))
        else
            echo -e "${YELLOW}!${NC} NFQUEUE rule not detected"
            ((warnings++))
        fi
    fi

    # Check 4: Metrics endpoint accessible
    local metrics_socket="/var/run/synflood-detector.sock"
    if [[ -S "${metrics_socket}" ]]; then
        echo -e "${GREEN}✓${NC} Metrics endpoint accessible"
    else
        if [[ "${NO_SERVICE}" == "true" ]] || ! systemctl is-active --quiet synflood-detector; then
            echo -e "${YELLOW}!${NC} Metrics endpoint pending (service not running)"
            ((warnings++))
        else
            echo -e "${YELLOW}!${NC} Metrics endpoint not found"
            ((warnings++))
        fi
    fi

    # Check 5: Whitelist status (advisory)
    local whitelist_path="${SYSCONF_DIR}/whitelist.conf"
    if [[ -f "${whitelist_path}" ]]; then
        local whitelist_count
        whitelist_count=$(grep -cvE '^\s*#|^\s*$' "${whitelist_path}" 2>/dev/null || echo "0")
        if [[ "${whitelist_count}" -eq 0 ]]; then
            echo -e "${YELLOW}!${NC} Whitelist is empty (consider adding trusted IPs)"
            ((warnings++))
        else
            echo -e "${GREEN}✓${NC} Whitelist configured (${whitelist_count} entries)"
        fi
    else
        echo -e "${YELLOW}!${NC} Whitelist file not found"
        ((warnings++))
    fi

    echo ""

    # Summary line
    if [[ "${all_ok}" == "true" && ${warnings} -eq 0 ]]; then
        success "All health checks passed"
    elif [[ "${all_ok}" == "true" ]]; then
        info "Health checks passed with ${warnings} advisory note(s)"
    else
        warn "Some health checks failed - review above for details"
    fi
}

print_next_steps() {
    echo "Quick Start with synflood-ctl:"
    echo ""
    echo "  Check status and statistics:"
    echo "     sudo synflood-ctl status"
    echo ""
    echo "  View service health:"
    echo "     sudo synflood-ctl health"
    echo ""
    echo "  Apply a configuration preset:"
    echo "     sudo synflood-ctl preset apply balanced"
    echo ""
    echo "  View and follow logs:"
    echo "     sudo synflood-ctl logs -f"
    echo ""
    echo "  Manage whitelist:"
    echo "     sudo synflood-ctl whitelist add 192.168.1.100"
    echo "     sudo synflood-ctl whitelist list"
    echo ""
    echo "  View blocked IPs:"
    echo "     sudo synflood-ctl blocked list"
    echo ""
    echo "  Get full command reference:"
    echo "     synflood-ctl help"
    echo ""
    echo "For documentation: cat ${DOC_DIR}/CONFIGURATION.md"
    echo "For man page:      man synflood-detector"
    echo ""
}

# ============================================================================
# Main Installation Flow
# ============================================================================

main() {
    # Parse command-line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version)
                INSTALL_VERSION="$2"
                shift 2
                ;;
            --non-interactive)
                NON_INTERACTIVE=true
                shift
                ;;
            --skip-deps)
                SKIP_DEPS=true
                shift
                ;;
            --no-service)
                NO_SERVICE=true
                shift
                ;;
            --help)
                show_help
                ;;
            *)
                error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    # Print banner
    echo ""
    echo "=========================================="
    echo "  TCP SYN Flood Detector - Installer"
    echo "=========================================="
    echo ""

    # Pre-flight checks
    check_root
    check_os_compatibility
    check_architecture
    check_internet_connectivity

    # Install dependencies
    install_runtime_dependencies

    # Create temporary directory
    TEMP_DIR=$(mktemp -d)

    # Download and extract
    if [[ -z "${INSTALL_VERSION}" ]]; then
        INSTALL_VERSION=$(get_latest_release_version)
        info "Using latest version: ${INSTALL_VERSION}"
    else
        info "Using specified version: ${INSTALL_VERSION}"
    fi

    local tarball_name
    tarball_name=$(download_release_tarball "${INSTALL_VERSION}")

    verify_checksum "${tarball_name}"

    local extract_dir
    extract_dir=$(extract_tarball "${tarball_name}")

    # Install components
    install_binary "${extract_dir}"
    install_config_files "${extract_dir}"
    install_systemd_service "${extract_dir}"
    install_documentation "${extract_dir}"
    install_man_page "${extract_dir}"
    install_management_tool "${extract_dir}"

    # Setup firewall rules
    setup_ipset
    setup_iptables_rules

    # Interactive configuration
    prompt_enable_service
    prompt_start_service
    prompt_whitelist_ips

    # Cleanup
    rm -rf "${TEMP_DIR}"

    # Display final status
    display_status

    # Verify installation health
    verify_installation_health

    # Show next steps
    print_next_steps

    success "Installation completed successfully!"
}

# Run main function
main "$@"
