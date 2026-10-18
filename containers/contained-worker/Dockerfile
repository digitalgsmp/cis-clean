FROM alpine:latest
RUN addgroup -g 65532 cisworker && adduser -D -H -u 65532 -G cisworker cisworker
COPY worker.sh /usr/local/bin/cis-contained-worker
RUN chmod 0555 /usr/local/bin/cis-contained-worker
USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/cis-contained-worker"]
