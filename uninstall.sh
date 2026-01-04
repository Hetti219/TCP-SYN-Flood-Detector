#!/usr/bin/env bash
#
# TCP SYN Flood Detector - Uninstallation Script
#
# Usage: curl -fsSL https://raw.githubusercontent.com/Hetti219/TCP-SYN-Flood-Detector/main/uninstall.sh | sudo bash
#

set -euo pipefail

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Installation paths
readonly INSTALL_PREFIX="/usr/local"
readonly BIN_DIR="${INSTALL_PREFIX}/bin"
readonly SYSCONF_DIR="/etc/synflood-detector"
readonly SYSTEMD_DIR="/usr/local/lib/systemd/system"
readonly DOC_DIR="${INSTALL_PREFIX}/share/doc/synflood-detector"
readonly MAN_DIR="${INSTALL_PREFIX}/share/man/man8"

# Runtime variables
FORCE_UNINSTALL=false
KEEP_CONFIGS=false
REMOVE_DEPS=false

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

show_help() {
    cat << EOF
TCP SYN Flood Detector - Uninstallation Script

Usage: $0 [OPTIONS]

Options:
  --force           Skip confirmation prompt
  --keep-configs    Don't remove configuration files
  --remove-deps     Remove installed dependencies
  --help            Show this help message

Examples:
  # Interactive uninstall (default)
  sudo $0

  # Force uninstall keeping configs
  sudo $0 --force --keep-configs

  # Complete removal including dependencies
  sudo $0 --remove-deps

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

# ============================================================================
# Confirmation
# ============================================================================

confirm_uninstall() {
    if [[ "${FORCE_UNINSTALL}" == "true" ]]; then
        return 0
    fi

    echo ""
    echo "This will uninstall TCP SYN Flood Detector from your system."
    echo ""

    local reply
    read -p "Are you sure you want to continue? [y/N]: " -n 1 -r reply
    echo

    if [[ ! "${reply}" =~ ^[Yy]$ ]]; then
        echo "Uninstallation cancelled."
        exit 0
    fi
}

# ============================================================================
# Service Management
# ============================================================================

stop_service() {
    if systemctl is-active --quiet synflood-detector 2>/dev/null; then
        info "Stopping synflood-detector service..."
        if systemctl stop synflood-detector 2>/dev/null; then
            success "Service stopped"
        else
            error "Failed to stop service"
            return 1
        fi
    else
        info "Service not running"
    fi
}

disable_service() {
    if systemctl is-enabled --quiet synflood-detector 2>/dev/null; then
        info "Disabling synflood-detector service..."
        if systemctl disable synflood-detector 2>/dev/null; then
            success "Service disabled"
        else
            error "Failed to disable service"
            return 1
        fi
    else
        info "Service not enabled"
    fi
}

# ============================================================================
# Firewall Cleanup
# ============================================================================

remove_iptables_rules() {
    info "Removing iptables rules..."

    local removed=false

    # Remove NFQUEUE rule
    if iptables -C INPUT -p tcp --syn -j NFQUEUE --queue-num 0 2>/dev/null; then
        if iptables -D INPUT -p tcp --syn -j NFQUEUE --queue-num 0 2>/dev/null; then
            success "Removed NFQUEUE rule"
            removed=true
        else
            warn "Failed to remove NFQUEUE rule"
        fi
    fi

    # Remove blacklist DROP rule
    if iptables -C INPUT -m set --match-set synflood_blacklist src -j DROP 2>/dev/null; then
        if iptables -D INPUT -m set --match-set synflood_blacklist src -j DROP 2>/dev/null; then
            success "Removed DROP rule"
            removed=true
        else
            warn "Failed to remove DROP rule"
        fi
    fi

    if [[ "${removed}" == "false" ]]; then
        info "No iptables rules found"
    fi
}

remove_ipset() {
    info "Removing ipset..."

    if ipset list synflood_blacklist &>/dev/null; then
        if ipset destroy synflood_blacklist 2>/dev/null; then
            success "ipset removed"
        else
            warn "Failed to destroy ipset (may be in use)"
            warn "Try running: sudo ipset flush synflood_blacklist && sudo ipset destroy synflood_blacklist"
        fi
    else
        info "ipset not found"
    fi
}

# ============================================================================
# File Removal
# ============================================================================

remove_binary() {
    info "Removing binary..."

    if [[ -f "${BIN_DIR}/synflood-detector" ]]; then
        rm -f "${BIN_DIR}/synflood-detector"
        success "Binary removed from ${BIN_DIR}"
    else
        info "Binary not found"
    fi
}

remove_systemd_service() {
    info "Removing systemd service..."

    if [[ -f "${SYSTEMD_DIR}/synflood-detector.service" ]]; then
        rm -f "${SYSTEMD_DIR}/synflood-detector.service"
        success "Service file removed"

        # Reload systemd
        if systemctl daemon-reload 2>/dev/null; then
            success "Systemd daemon reloaded"
        else
            warn "Failed to reload systemd daemon"
        fi
    else
        info "Service file not found"
    fi
}

prompt_remove_configs() {
    if [[ "${KEEP_CONFIGS}" == "true" ]]; then
        info "Preserving configuration files (--keep-configs specified)"
        return 0
    fi

    echo ""
    echo "Configuration files:"
    if [[ -f "${SYSCONF_DIR}/synflood-detector.conf" ]]; then
        echo "  - ${SYSCONF_DIR}/synflood-detector.conf"
    fi
    if [[ -f "${SYSCONF_DIR}/whitelist.conf" ]]; then
        echo "  - ${SYSCONF_DIR}/whitelist.conf"
    fi

    if [[ ! -d "${SYSCONF_DIR}" ]]; then
        info "No configuration files found"
        return 0
    fi

    echo ""
    local reply
    read -p "Remove configuration files? [y/N]: " -n 1 -r reply
    echo

    if [[ "${reply}" =~ ^[Yy]$ ]]; then
        remove_config_files
    else
        info "Configuration files preserved at ${SYSCONF_DIR}"
    fi
}

remove_config_files() {
    info "Removing configuration files..."

    if [[ -d "${SYSCONF_DIR}" ]]; then
        rm -rf "${SYSCONF_DIR}"
        success "Configuration files removed"
    else
        info "Configuration directory not found"
    fi
}

remove_documentation() {
    info "Removing documentation..."

    if [[ -d "${DOC_DIR}" ]]; then
        rm -rf "${DOC_DIR}"
        success "Documentation removed"
    else
        info "Documentation not found"
    fi
}

remove_man_page() {
    info "Removing man page..."

    if [[ -f "${MAN_DIR}/synflood-detector.8" ]]; then
        rm -f "${MAN_DIR}/synflood-detector.8"
        success "Man page removed"

        # Update man database
        mandb -q 2>/dev/null || true
    else
        info "Man page not found"
    fi
}

# ============================================================================
# Dependency Removal
# ============================================================================

prompt_remove_dependencies() {
    if [[ "${REMOVE_DEPS}" != "true" ]]; then
        return 0
    fi

    info "Removing runtime dependencies..."

    local deps=(
        libnetfilter-queue1
        libmnl0
        libipset13
        libconfig9
        libsystemd0
        iptables
        ipset
    )

    echo ""
    echo "WARNING: Removing these dependencies may affect other software:"
    for dep in "${deps[@]}"; do
        echo "  - ${dep}"
    done
    echo ""

    local reply
    read -p "Continue with dependency removal? [y/N]: " -n 1 -r reply
    echo

    if [[ "${reply}" =~ ^[Yy]$ ]]; then
        if apt-get remove -y "${deps[@]}" 2>/dev/null; then
            success "Dependencies removed"
        else
            warn "Some dependencies may not have been removed"
        fi
    else
        info "Dependencies preserved"
    fi
}

# ============================================================================
# Runtime Cleanup
# ============================================================================

cleanup_runtime_artifacts() {
    info "Cleaning up runtime artifacts..."

    local cleaned=false

    # Remove Unix socket
    if [[ -e /var/run/synflood-detector.sock ]]; then
        rm -f /var/run/synflood-detector.sock
        cleaned=true
    fi

    # Remove PID files
    if [[ -f /var/run/synflood-detector.pid ]]; then
        rm -f /var/run/synflood-detector.pid
        cleaned=true
    fi

    if [[ "${cleaned}" == "true" ]]; then
        success "Runtime artifacts cleaned"
    else
        info "No runtime artifacts found"
    fi
}

# ============================================================================
# Display Functions
# ============================================================================

display_uninstall_summary() {
    echo ""
    echo "=========================================="
    echo "  Uninstallation Complete!"
    echo "=========================================="
    echo ""
    echo "The following components were removed:"
    echo "  - Binary (synflood-detector)"
    echo "  - Systemd service"
    echo "  - Documentation and man page"
    echo "  - iptables rules and ipset"
    echo ""

    if [[ -d "${SYSCONF_DIR}" ]]; then
        echo "Configuration files preserved at:"
        echo "  ${SYSCONF_DIR}"
        echo ""
        echo "To remove them manually:"
        echo "  sudo rm -rf ${SYSCONF_DIR}"
        echo ""
    fi

    success "TCP SYN Flood Detector has been uninstalled"
    echo ""
}

# ============================================================================
# Main Uninstallation Flow
# ============================================================================

main() {
    # Parse command-line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --force)
                FORCE_UNINSTALL=true
                shift
                ;;
            --keep-configs)
                KEEP_CONFIGS=true
                shift
                ;;
            --remove-deps)
                REMOVE_DEPS=true
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
    echo "  TCP SYN Flood Detector - Uninstaller"
    echo "=========================================="
    echo ""

    # Pre-flight checks
    check_root

    # Confirm uninstallation
    confirm_uninstall

    # Stop and disable service
    stop_service
    disable_service

    # Remove firewall rules
    remove_iptables_rules
    remove_ipset

    # Remove files
    remove_binary
    remove_systemd_service
    remove_documentation
    remove_man_page

    # Handle configs
    prompt_remove_configs

    # Clean up runtime artifacts
    cleanup_runtime_artifacts

    # Optional: Remove dependencies
    if [[ "${REMOVE_DEPS}" == "true" ]]; then
        prompt_remove_dependencies
    fi

    # Display summary
    display_uninstall_summary
}

# Run main function
main "$@"
