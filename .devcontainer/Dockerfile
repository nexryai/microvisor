FROM ubuntu:rolling AS mimalloc-builder

RUN apt-get update && \
    apt-get install -y git curl clang libclang-rt-dev make && \
    useradd -m -d /var/build builder

RUN curl -L https://github.com/Kitware/CMake/releases/download/v4.2.3/cmake-4.2.3-linux-x86_64.sh -o install_cmake.sh && \
    bash install_cmake.sh --skip-license --prefix=/usr/local --exclude-subdir && \
    rm install_cmake.sh

USER builder
RUN git clone --depth 1 https://github.com/microsoft/mimalloc /var/build/mimalloc

WORKDIR /var/build/mimalloc/out
RUN CC=clang CXX=clang++ cmake \
    -Dmi_has_libatomic=OFF \
    -DMI_LIBPATH_atomic=OFF \
    -DCMAKE_C_FLAGS="-rtlib=compiler-rt" \
    -DCMAKE_CXX_FLAGS="-rtlib=compiler-rt" \
    -DCMAKE_SHARED_LINKER_FLAGS="-rtlib=compiler-rt" \
    -DMI_SECURE=ON \
    -DMI_BUILD_SHARED=ON \
    -DMI_BUILD_STATIC=OFF \
    -DMI_BUILD_TESTS=OFF \
    .. && \
    make -j$(nproc)


# Runtime
FROM ubuntu:rolling

COPY --chown=root:root --from=mimalloc-builder /var/build/mimalloc/out/libmimalloc-secure.so /usr/local/lib/libmimalloc.so

ENV LD_PRELOAD=/usr/local/lib/libmimalloc.so
ENV MIMALLOC_SECURE=4

RUN apt-get update && \
    apt-get install -y git curl xz-utils clang clangd lld llvm-20-linker-tools && \
    rm -rf /var/lib/apt/lists/*

RUN curl -L https://github.com/Kitware/CMake/releases/download/v4.2.3/cmake-4.2.3-linux-x86_64.sh -o install_cmake.sh && \
    bash install_cmake.sh --skip-license --prefix=/usr/local --exclude-subdir && \
    rm install_cmake.sh