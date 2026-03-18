FROM ubuntu:latest

ARG OPENFHE_TAG=v1.4.2.1
ARG no_threads=10

#install pre-requisites for OpenFHE
RUN apt update && apt install -y git build-essential gdb cmake autoconf nano tmux

#git clone the openfhe-development repository
RUN git clone --branch ${OPENFHE_TAG} --depth 1 https://github.com/openfheorg/openfhe-development.git

#building and installing OpenFHE
RUN mkdir /openfhe-development/build && cd /openfhe-development/build && cmake .. && make -j $no_threads && make install #&& make testall
RUN ldconfig

#git clone the compute-fhe repository
RUN git clone https://github.com/fstasel/compute-fhe.git

#building and installing compute-fhe 
RUN cd compute-fhe && mkdir build && cd build && cmake .. && make -j $no_threads

