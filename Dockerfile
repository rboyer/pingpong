FROM alpine:3.12
RUN addgroup pingpong && adduser -S -G pingpong pingpong
COPY pingpong /bin/pingpong
USER pingpong
ENTRYPOINT ["/bin/pingpong"]
