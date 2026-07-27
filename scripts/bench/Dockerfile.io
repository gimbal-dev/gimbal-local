# Dockerfile.io — the Docker Desktop side of the M32.2 I/O + network benchmark.
#
# Ships the shared command definitions plus the timing wrapper, so the container
# runs the byte-identical inner command the gimbal guest runs. Constrain to the
# guest's shape for fairness, e.g.
#   docker run --rm --cpus 1 --memory 1g -e BENCH_WORKLOAD=diskwrite <image>
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl coreutils \
    && rm -rf /var/lib/apt/lists/*

COPY workloads/commands.sh /opt/bench/commands.sh
COPY workloads/io.sh /opt/bench/io.sh
RUN chmod +x /opt/bench/io.sh /opt/bench/commands.sh

CMD ["/opt/bench/io.sh"]
