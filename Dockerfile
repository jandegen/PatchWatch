# SPDX-License-Identifier: Apache-2.0
FROM python:3.14-alpine3.22
LABEL org.opencontainers.image.title="Patchwatch" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Patch the base image's OS packages (musl, zlib, busybox) and drop pip: the bridge
# has no third-party dependencies and installs nothing at runtime.
RUN apk upgrade --no-cache \
    && python -m pip uninstall -y pip setuptools wheel \
    && addgroup -g 10001 patchwatch && adduser -D -u 10001 -G patchwatch patchwatch \
    && mkdir /data && chown 10001:10001 /data
WORKDIR /app
COPY patchwatch /app/patchwatch
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)"
CMD ["python", "-m", "patchwatch.bridge"]
