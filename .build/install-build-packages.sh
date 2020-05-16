#!/bin/bash

apt-get clean -y && apt-get update -y && apt-get install -y \
    build-essential \
    libcurl4-openssl-dev \
    libssl-dev \
    uuid-dev \
    valgrind \
    xsltproc \
    lcov \
    gcovr

# Install cmake 3.15.0
wget https://cmake.org/files/v3.15/cmake-3.15.0-Linux-x86_64.sh && \
    chmod +x cmake-3.15.0-Linux-x86_64.sh && \
    ./cmake-3.15.0-Linux-x86_64.sh --skip-license --prefix=/usr/local --exclude-subdir && \
    rm cmake-3.15.0-Linux-x86_64.sh

# Install cmocka 1.1.5
wget https://cmocka.org/files/1.1/cmocka-1.1.5.tar.xz && \
    tar xf cmocka-1.1.5.tar.xz && \
    cd cmocka-1.1.5 && \
    mkdir -p bin && \
    cd bin && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Debug .. && \
    sudo make install