FROM ubuntu:latest

#install pre-requisites for OpenFHE
RUN apt update && apt install -y git build-essential gdb cmake autoconf

#install pre-requisites for ComputeFHE
RUN apt install -y clang-format doxygen graphviz

#install tools
RUN apt install -y nano tmux

#git clone the openfhe-development configurator
RUN git clone https://github.com/openfheorg/openfhe-configurator.git

#building and installing OpenFHE-Hexl
RUN cd openfhe-configurator && ./scripts/stage-openfhe-development-hexl.sh && ./scripts/build-openfhe-development.sh
RUN ldconfig

#git clone the compute-fhe-dev repository
RUN git clone https://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@github.com/fstasel/compute-fhe-dev.git

#building and installing compute-fhe
RUN cd compute-fhe-dev && mkdir build && cd build && cmake -DWITH_HEXL=ON -DHEXL_DIR=/openfhe-configurator/openfhe-staging/install/lib/cmake/hexl-1.2.6 -DCMAKE_PREFIX_PATH=/openfhe-configurator/openfhe-staging/install .. && make -j && make doc