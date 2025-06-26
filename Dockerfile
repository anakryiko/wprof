FROM ubuntu:24.04

# Install build dependencies
RUN apt update && apt install -y \
    build-essential \
    libbpf-dev \
    libelf-dev \
    pkg-config \
    clang \
    llvm \
    git \
    zlib1g-dev \
    libcap-dev \
    vim \
    curl \
    linux-headers-generic \
    linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /src

# Set up environment
ENV CC=clang
ENV CXX=clang++
