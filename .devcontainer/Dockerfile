FROM alpine:edge AS mimalloc-builder

RUN apk add --no-cache git curl clang clang-static cmake make compiler-rt linux-headers && \
    adduser -D -h /var/build builder

USER builder
RUN git clone --depth 1 https://github.com/microsoft/mimalloc /var/build/mimalloc

WORKDIR /var/build/mimalloc/out
RUN CC=clang CXX=clang++ cmake \
    -Dmi_has_libatomic=OFF \
    -DMI_LIBPATH_atomic=OFF \
    -DCMAKE_C_FLAGS="-rtlib=compiler-rt" \
    -DCMAKE_CXX_FLAGS="-rtlib=compiler-rt" \
    -DCMAKE_SHARED_LINKER_FLAGS="-rtlib=compiler-rt" \
    -DMI_LIBC_MUSL=ON \
    -DMI_SECURE=ON \
    -DMI_BUILD_SHARED=ON \
    -DMI_BUILD_STATIC=OFF \
    -DMI_BUILD_TESTS=OFF \
    .. && \
    make -j$(nproc)


# Runtime
FROM alpine:edge

COPY --chown=root:root --from=mimalloc-builder /var/build/mimalloc/out/libmimalloc-secure.so /usr/local/lib/libmimalloc.so
ENV LD_PRELOAD=/usr/local/lib/libmimalloc.so
ENV MIMALLOC_SECURE=4

RUN apk add --no-cache uutils-coreutils nushell git curl xz clang cmake make lld
RUN rm -f /usr/bin/c89 /usr/bin/c99 /usr/bin/cc /usr/bin/cpp /usr/bin/gcc* /usr/bin/gcov* /usr/bin/x86_64-alpine-linux-musl-cc /usr/bin/x86_64-alpine-linux-musl-gcc*
RUN adduser -D -s /usr/bin/nu runtime
