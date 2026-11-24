FROM alpine:3.13

ARG TARGETOS
ARG TARGETARCH

RUN addgroup pingpong && adduser -S -G pingpong pingpong
COPY pingpong.${TARGETOS}.${TARGETARCH} /bin/pingpong
USER pingpong
ENTRYPOINT ["/bin/pingpong"]
