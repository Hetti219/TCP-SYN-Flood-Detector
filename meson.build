project('synflood-detector', 'c',
  version: '1.0.0',
  license: 'MIT',
  default_options: [
    'c_std=c11',
    'warning_level=3',
    'werror=false',
    'optimization=2',
  ]
)

# Project information
project_description = 'TCP SYN Flood Detector with Rate-Limiting Automation'

# Compiler setup
cc = meson.get_compiler('c')

# Compiler flags
add_project_arguments(
  [
    '-D_GNU_SOURCE',
    '-D_POSIX_C_SOURCE=200809L',
    '-pedantic',
    '-Wno-unused-parameter',
  ],
  language: 'c'
)

# Security hardening flags
security_flags = [
  '-fstack-protector-strong',
  '-D_FORTIFY_SOURCE=2',
  '-Wformat',
  '-Wformat-security',
  '-fPIE',
]
add_project_arguments(security_flags, language: 'c')

add_project_link_arguments(
  [
    '-pie',
    '-Wl,-z,relro',
    '-Wl,-z,now',
    '-Wl,-z,noexecstack',
  ],
  language: 'c'
)

# Dependencies
libnetfilter_queue_dep = dependency('libnetfilter_queue', required: true)
libmnl_dep = dependency('libmnl', required: true)
libipset_dep = cc.find_library('ipset', required: true)
libconfig_dep = dependency('libconfig', required: true)
libsystemd_dep = dependency('libsystemd', required: true)
threads_dep = dependency('threads', required: true)

# Collect all dependencies
deps = [
  libnetfilter_queue_dep,
  libmnl_dep,
  libipset_dep,
  libconfig_dep,
  libsystemd_dep,
  threads_dep,
]

# Include directories
inc = include_directories('include')

# Source files
sources = files(
  'src/main.c',
  'src/capture/nfqueue.c',
  'src/capture/rawsock.c',
  'src/analysis/tracker.c',
  'src/analysis/procparse.c',
  'src/analysis/whitelist.c',
  'src/enforce/ipset_mgr.c',
  'src/enforce/expiry.c',
  'src/observe/logger.c',
  'src/observe/metrics.c',
  'src/config/config.c',
)

# Main executable
executable('synflood-detector',
  sources,
  include_directories: inc,
  dependencies: deps,
  install: true,
  install_dir: get_option('bindir')
)

# Configuration files
install_data('conf/synflood-detector.conf',
  install_dir: get_option('sysconfdir') / 'synflood-detector'
)

install_data('conf/whitelist.conf',
  install_dir: get_option('sysconfdir') / 'synflood-detector'
)

# Systemd service file
install_data('conf/synflood-detector.service',
  install_dir: get_option('prefix') / 'lib' / 'systemd' / 'system'
)

# Documentation
install_data('docs/INSTALL.md',
  install_dir: get_option('datadir') / 'doc' / 'synflood-detector'
)

install_data('docs/CONFIGURATION.md',
  install_dir: get_option('datadir') / 'doc' / 'synflood-detector'
)

install_data('docs/TROUBLESHOOTING.md',
  install_dir: get_option('datadir') / 'doc' / 'synflood-detector'
)

# Man page
install_man('docs/synflood-detector.8')

# Summary
summary({
  'prefix': get_option('prefix'),
  'bindir': get_option('bindir'),
  'sysconfdir': get_option('sysconfdir'),
}, section: 'Directories')

summary({
  'C Compiler': cc.get_id(),
  'C Standard': 'C11',
}, section: 'Compiler')

summary({
  'libnetfilter_queue': libnetfilter_queue_dep.found(),
  'libmnl': libmnl_dep.found(),
  'libipset': libipset_dep.found(),
  'libconfig': libconfig_dep.found(),
  'libsystemd': libsystemd_dep.found(),
}, section: 'Dependencies')

# ============================================
# Testing
# ============================================

# Unity test framework
unity_sources = files(
  'tests/unity/unity.c',
)

unity_inc = include_directories('tests/unity')

# Common test dependencies (modules without dependencies on system libs)
test_sources_common = files(
  'src/config/config.c',
  'src/analysis/tracker.c',
  'src/analysis/whitelist.c',
  'src/observe/logger.c',
)

# Unit tests
test_common = executable('test_common',
  'tests/unit/test_common.c',
  unity_sources,
  include_directories: [inc, unity_inc],
  dependencies: deps,
)

test_config = executable('test_config',
  'tests/unit/test_config.c',
  test_sources_common,
  unity_sources,
  include_directories: [inc, unity_inc],
  dependencies: deps,
)

test_whitelist = executable('test_whitelist',
  'tests/unit/test_whitelist.c',
  test_sources_common,
  unity_sources,
  include_directories: [inc, unity_inc],
  dependencies: deps,
)

test_tracker = executable('test_tracker',
  'tests/unit/test_tracker.c',
  test_sources_common,
  unity_sources,
  include_directories: [inc, unity_inc],
  dependencies: deps,
)

test_logger = executable('test_logger',
  'tests/unit/test_logger.c',
  test_sources_common,
  unity_sources,
  include_directories: [inc, unity_inc],
  dependencies: deps,
)

test_procparse = executable('test_procparse',
  'tests/unit/test_procparse.c',
  'src/analysis/procparse.c',
  test_sources_common,
  unity_sources,
  include_directories: [inc, unity_inc],
  dependencies: deps,
)

test_tracker_advanced = executable('test_tracker_advanced',
  'tests/unit/test_tracker_advanced.c',
  test_sources_common,
  unity_sources,
  include_directories: [inc, unity_inc],
  dependencies: deps,
)

test_whitelist_advanced = executable('test_whitelist_advanced',
  'tests/unit/test_whitelist_advanced.c',
  test_sources_common,
  unity_sources,
  include_directories: [inc, unity_inc],
  dependencies: deps,
)

# Integration tests
test_detection_flow = executable('test_detection_flow',
  'tests/integration/test_detection_flow.c',
  test_sources_common,
  unity_sources,
  include_directories: [inc, unity_inc],
  dependencies: deps,
)

# Register tests with meson
test('Common utilities', test_common)
test('Configuration', test_config)
test('Whitelist', test_whitelist)
test('IP Tracker', test_tracker)
test('Logger', test_logger)
test('Proc Parser', test_procparse)
test('IP Tracker Advanced', test_tracker_advanced)
test('Whitelist Advanced', test_whitelist_advanced)
test('Detection Flow', test_detection_flow)
