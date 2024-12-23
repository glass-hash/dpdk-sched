project('dpdk-sched', 'cpp',
  version : '1.0.0',
  default_options : [
    'buildtype=release',
    'cpp_std=c++17',
    'warning_level=3'
  ]
)

# Find DPDK dependency
dpdk_dep = dependency('libdpdk')

# Source files
sources = files(
  'src/sched.cpp',
  'src/flows.cpp',
  'src/config.cpp',
  'src/clock.cpp'
)

# Include directories
inc = include_directories('include')

# Create executable
executable('dpdk_sched',
  sources,
  dependencies : dpdk_dep,
  include_directories : inc
)
