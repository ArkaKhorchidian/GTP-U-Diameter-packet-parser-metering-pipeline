# Multi-stage build. The runtime image carries the binary, the traffic tools
# and nothing else — no compiler, no build tree.
#
# The pipeline pins threads to cores, so run it with an explicit CPU set:
#   docker run --rm --cpuset-cpus=2,3 \
#     -v "$PWD:/data" -p 9109:9109 gtp-meter \
#     --pcap /data/capture.pcap --sessions /data/sessions.csv \
#     --ingest-cpu 0 --meter-cpu 1 --http 9109 --http-bind 0.0.0.0
#
# Live capture additionally needs --cap-add=NET_RAW --cap-add=NET_ADMIN
# --network=host.

FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY CMakeLists.txt ./
COPY include ./include
COPY src ./src
COPY tests ./tests
COPY bench ./bench

# NATIVE_ARCH off: the build host is not the deployment host, and a binary
# tuned for the wrong microarchitecture either crashes or silently underperforms.
RUN cmake -S . -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DGTPM_NATIVE_ARCH=OFF \
        -DGTPM_BUILD_TESTS=ON \
        -DGTPM_BUILD_BENCH=ON \
        -DGTPM_BUILD_FUZZ=OFF \
    && cmake --build build -j"$(nproc)" \
    && ctest --test-dir build --output-on-failure --timeout 300

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --shell /usr/sbin/nologin gtpm

COPY --from=build /src/build/bin/gtp-meter /usr/local/bin/gtp-meter
COPY --from=build /src/build/bin/bench_parse /usr/local/bin/bench_parse
COPY --from=build /src/build/bin/bench_e2e /usr/local/bin/bench_e2e
COPY tools/gen_traffic.py /usr/local/bin/gen_traffic.py
COPY tools/tshark_totals.py /usr/local/bin/tshark_totals.py

USER gtpm
WORKDIR /data
EXPOSE 9109

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/bin/sh", "-c", "exec 3<>/dev/tcp/127.0.0.1/9109 && printf 'GET /healthz HTTP/1.0\\r\\n\\r\\n' >&3 && head -1 <&3 | grep -q 200"]

ENTRYPOINT ["/usr/local/bin/gtp-meter"]
CMD ["--help"]
