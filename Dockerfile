FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev linux-tools-generic cmake make gcc g++ pkg-config \
    iproute2 ethtool iperf3 nmap python3 python3-matplotlib ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /work
CMD ["bash"]
