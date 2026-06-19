FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install prerequisites
RUN apt update && apt install -y \
    git build-essential gdb cmake autoconf \
    clang-format doxygen graphviz nano tmux \
    libtool python3 && \
    rm -rf /var/lib/apt/lists/*

# Clone the OpenFHE Configurator
RUN git clone https://github.com/openfheorg/openfhe-configurator.git

# Modify the script to use nproc instead of unbound -j
# The script has 'make -j', we replace it with 'make -j$(nproc)'
RUN sed -i 's/make -j/make -j$(nproc)/g' openfhe-configurator/scripts/build-openfhe-development.sh

# Inject environment variables
ENV OPENFHE_INSTALL_DIR=/usr/local
ENV CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Release"

# Stage and build OpenFHE [hexl-enabled]
RUN cd openfhe-configurator && \
    ./scripts/stage-openfhe-development-hexl.sh && \
    ./scripts/build-openfhe-development.sh

# Update system library cache
RUN ldconfig

# Clone, build, and install ComputeFHE
RUN git clone https://github.com/fstasel/compute-fhe.git && \
    cd compute-fhe && \
    mkdir build && cd build && \
    cmake -DWITH_HEXL=ON -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc) && \
    make doc && \
    make install && \
    ldconfig

WORKDIR /workspace
