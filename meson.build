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
