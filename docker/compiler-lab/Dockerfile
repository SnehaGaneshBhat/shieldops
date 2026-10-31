FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang gcc binutils universal-ctags python3 file \
 && rm -rf /var/lib/apt/lists/*
COPY lab_run.sh /usr/local/bin/lab_run.sh
RUN chmod 755 /usr/local/bin/lab_run.sh && useradd -m -u 10001 bg
USER bg
WORKDIR /work
