# syntax=docker/dockerfile:1.4

# Sentinel ModSecurity Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY sentinel-modsec-agent /sentinel-modsec-agent

LABEL org.opencontainers.image.title="Sentinel ModSecurity Agent" \
      org.opencontainers.image.description="Sentinel ModSecurity Agent for Sentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel-agent-modsec"

ENV RUST_LOG=info,sentinel_modsec_agent=debug \
    SOCKET_PATH=/var/run/sentinel/modsec.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-modsec-agent"]
