FROM ubuntu:rolling

RUN apt-get update && \
    apt-get install -y git xz-utils curl clang clangd lld llvm-20-linker-tools make libmimalloc3

ENV LD_PRELOAD=libmimalloc.so.3.0
RUN curl -L https://github.com/Kitware/CMake/releases/download/v4.2.3/cmake-4.2.3-linux-x86_64.sh -o install_cmake.sh && bash install_cmake.sh --skip-license --prefix=/usr/local --exclude-subdir && rm install_cmake.sh
