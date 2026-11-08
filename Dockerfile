# The proxy in front of the bundled simulated tool server: a self-contained demo, and what MCP
# directories run to check that the server starts and lists its tools. Nothing is sent, fetched or
# executed. For real use, run authz next to your MCP client (see the README), or override CMD.
#
#   docker build -t authz . && docker run -i --rm authz

FROM rust:1.99.1-slim-trixie@sha256:f6c4a35d21dbb3c89d7a8d056c193e94fc09037f2b58dd858b09c39a47dd02d7 AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p authz-cli --bin authz

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
COPY --from=build /src/target/release/authz /usr/local/bin/authz
COPY policies.yaml /app/policies.yaml
COPY policies /app/policies
COPY fixtures /app/fixtures
ENV AUTHZ_SANDBOX=/tmp/sandbox AUTHZ_FIXTURES=/app/fixtures
WORKDIR /tmp
USER 65534
ENTRYPOINT ["authz"]
CMD ["proxy", "--policy", "/app/policies.yaml", "--audit", "/tmp/audit.jsonl", "--", "authz", "serve-tools"]
