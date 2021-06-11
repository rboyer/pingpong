FROM alpine:3.13
RUN addgroup pingpong && adduser -S -G pingpong pingpong
COPY pingpong /bin/pingpong
USER pingpong
ENTRYPOINT ["/bin/pingpong"]
