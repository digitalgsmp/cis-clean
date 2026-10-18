FROM alpine:latest
# python3 is required to execute the declared verification workload for the
# verify-authored-source operation. It is the only addition to the proof-v2
# image: no network tooling, no package manager left usable at runtime, no
# compiler, and no change to the identity or filesystem posture below.
RUN apk add --no-cache python3
RUN addgroup -g 65532 cisworker && adduser -D -H -u 65532 -G cisworker cisworker
COPY worker.sh /usr/local/bin/cis-contained-worker
COPY verify_source.py /usr/local/bin/cis-verify-source
# The trusted runner is baked in at 0555 on a read-only root. It is never read
# from /contract, which carries untrusted model-authored material.
RUN chmod 0555 /usr/local/bin/cis-contained-worker /usr/local/bin/cis-verify-source
USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/cis-contained-worker"]
