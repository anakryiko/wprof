# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is wprof, a workload profiler for Linux that uses eBPF to collect detailed system tracing data and outputs Perfetto-compatible traces. The project consists of:

- **C/eBPF main application** (`src/`): Core profiling tool with BPF programs for kernel-space data collection
- **blazesym library** (git submodule): Rust library for address symbolization used for stack traces
- **libbpf** (git submodule): Library for eBPF program loading and management
- **bpftool** (git submodule): Tool for eBPF object manipulation

## Build Commands

### Prerequisites
```bash
sudo dnf -y install elfutils-devel zlib-devel
# Install Rust toolchain if needed:
# curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Building wprof
```bash
# Initialize submodules (first time only)
git submodule update --init --recursive

# Build release version
cd src
make RELEASE=1 -j$(nproc)

# Build debug version
make -j$(nproc)

# Clean build artifacts
make clean
```

### Docker Build (for macOS or non-Linux systems)
```bash
# Build development container
docker build -t wprof-build .

# Build inside container
docker run -it --rm -v $(pwd):/src wprof-build bash
make -j$(nproc) -C src
```

## Testing

### Main wprof tests
The main C application doesn't have automated unit tests. Testing is done manually by:
```bash
# Build and test basic functionality
sudo ./src/wprof -d1000 -T trace.pb

# Test replay mode with existing data
./src/wprof -R -d500 -T trace-500ms.pb
```

### blazesym library tests
```bash
cd blazesym
cargo test --workspace
```

## Architecture

### Core Components

**Data Collection Flow:**
1. **BPF Programs** (`wprof.bpf.c`, `utils.bpf.c`) - Kernel-space collectors for scheduler events, IRQs, context switches
2. **Ring Buffer Processing** (`wprof.c`) - User-space handlers that consume BPF events via ring buffers
3. **Stack Trace Resolution** (`stacktrace.c`) - Interfaces with blazesym for symbolizing addresses
4. **Protobuf Emission** (`emit.c`, `protobuf.c`) - Converts events to Perfetto trace format

**Key Data Structures:**
- `struct wprof_event` - Universal event container for all trace events (switches, timers, IRQs, etc.)
- `struct task_state` - Per-task BPF map tracking waking times, waker tasks, performance counters
- `struct cpu_state` - Per-CPU BPF map for IPI tracking and CPU-local state

**Event Types:**
- Context switches with waker attribution
- Timer interrupts with stack traces
- Hardware/software IRQ handling
- IPI (Inter-Processor Interrupt) send/receive
- Task lifecycle (fork, exec, rename, exit)
- Custom request tracing via USDT probes

### Key Files

- `src/wprof.c` - Main application entry point and event processing loop
- `src/wprof.bpf.c` - BPF programs for kernel-space tracing
- `src/wprof.h` - Core data structure definitions shared between BPF and userspace
- `src/emit.c` - Perfetto trace output generation
- `src/stacktrace.c` - Stack trace collection and symbolization
- `src/Makefile` - Build configuration with libbpf/blazesym integration

### Build Dependencies

The build process automatically handles:
- **libbpf**: Built from source in `../libbpf/src`
- **bpftool**: Built from source for BPF skeleton generation
- **blazesym**: Rust library built via Cargo, produces `libblazesym_c.a`
- **BPF compilation**: Uses Clang with `-target bpf` for kernel programs
- **Skeleton generation**: `bpftool gen skeleton` creates `wprof.skel.h` for BPF program loading

### Development Notes

- BPF programs use `vmlinux.h` for kernel type definitions
- Stack traces support both kernel and user space (via blazesym)
- Performance counters integration for hardware metrics
- Ring buffer batching for efficient event delivery
- Task and CPU state tracking via BPF maps
- NUMA topology awareness for scheduling analysis