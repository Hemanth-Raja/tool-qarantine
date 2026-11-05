# Tool Quarantine sandbox image.
# Untrusted MCP servers run inside this image under strace, as an unprivileged user,
# with decoy credentials planted in a fake home directory. No real secrets ever enter.
# BASE can be overridden for offline/proxied dev builds (see build-local.sh).
ARG BASE=python:3.12-slim
FROM ${BASE}

# The optional "extra_ca" secret only exists for builds behind a TLS-intercepting proxy;
# a normal build (e.g. on the Vultr VM) ignores it.
RUN --mount=type=secret,id=extra_ca,required=false \
    if command -v strace >/dev/null; then exit 0; fi; \
    if [ -f /run/secrets/extra_ca ]; then \
      sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources; \
      echo "Acquire::https::CaInfo \"/run/secrets/extra_ca\";" > /etc/apt/apt.conf.d/99ca; \
    fi \
 && apt-get update \
 && apt-get install -y --no-install-recommends strace ca-certificates \
 && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/99ca

# Optional: the official MCP Python SDK so submitted SDK-based servers can run.
RUN --mount=type=secret,id=extra_ca,required=false \
    PIP_CERT=$( [ -f /run/secrets/extra_ca ] && echo /run/secrets/extra_ca ) \
    pip install --no-cache-dir "mcp>=1.2,<2" || true

RUN useradd --create-home --uid 1000 --shell /bin/bash dev
COPY decoys/ /home/dev/
COPY workspace/ /workspace/
RUN chown -R dev:dev /home/dev /workspace && chmod 600 /home/dev/.aws/credentials /home/dev/.ssh/id_ed25519

COPY entrypoint.sh /usr/local/bin/tq-entrypoint
RUN chmod +x /usr/local/bin/tq-entrypoint

USER dev
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/tq-entrypoint"]
