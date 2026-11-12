FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Makefile ./
COPY lib ./lib
COPY server.cpp client.cpp crypto.cpp crypto.h ./
COPY demo.sh ./

RUN make && chmod +x demo.sh \
    && useradd --system --uid 10001 appuser

USER appuser

EXPOSE 8032/udp

CMD ["./server"]
