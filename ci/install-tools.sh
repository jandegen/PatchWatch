#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
# Versioned releases with their upstream SHA256 checksums. Executed in Alpine CI images.
apk add --no-cache bash curl python3 py3-yaml git ca-certificates
fetch_tool() {
  name=$1 version=$2 archive=$3 base=$4
  work=$(mktemp -d)
  curl --fail --silent --show-error --location "$base/$archive" -o "$work/$archive"
  case "$name" in
    helm)
      curl --fail --silent --show-error --location "$base/$archive.sha256sum" -o "$work/checksums"
      ;;
    helmfile)
      curl --fail --silent --show-error --location "$base/helmfile_${version}_checksums.txt" -o "$work/checksums"
      ;;
  esac
  (cd "$work" && awk -v file="$archive" '$2 == file || $2 == "*"file {print}' checksums > selected && test -s selected && sha256sum -c selected)
  tar -xzf "$work/$archive" -C "$work"
  if [ "$name" = helm ]; then install "$work/linux-amd64/helm" /usr/local/bin/helm;
  else install "$work/helmfile" /usr/local/bin/helmfile; fi
  rm -rf "$work"
}
fetch_tool helm 3.21.2 helm-v3.21.2-linux-amd64.tar.gz https://get.helm.sh
fetch_tool helmfile 1.8.4 helmfile_1.8.4_linux_amd64.tar.gz https://github.com/helmfile/helmfile/releases/download/v1.8.4
