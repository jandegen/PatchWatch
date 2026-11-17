#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Install the agent from a source checkout into a private virtualenv (development and small fleets).
# Managed fleets should use the .deb/.pkg packages built by packaging/build.py instead.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $EUID -ne 0 ]]; then echo 'Run as root (sudo).' >&2; exit 1; fi
command -v syft >/dev/null || { echo 'Install Syft first; see docs/usage/agent.md.' >&2; exit 1; }
python3 -c 'import sys; assert sys.version_info >= (3,12), "Python >= 3.12 required"'
case "$(uname -s)" in
  Linux)  bin=/usr/bin ;;
  Darwin) bin=/usr/local/bin ;;
  *) echo 'Supported platforms: Linux, macOS' >&2; exit 1 ;;
esac
install -d -m 0755 /opt/patchwatch "$bin"
install -d -m 0700 /etc/patchwatch /var/lib/patchwatch
python3 -m venv /opt/patchwatch/venv
/opt/patchwatch/venv/bin/pip install --no-deps .
# The unit files and the LaunchDaemon start $bin/patchwatch-agent, the same path the packages use.
ln -sf /opt/patchwatch/venv/bin/patchwatch-agent "$bin/patchwatch-agent"
"$bin/patchwatch-agent" --init-config
case "$(uname -s)" in
  Linux)
    install -m 0644 agent/systemd/patchwatch-agent.{service,timer} /etc/systemd/system/
    systemctl daemon-reload
    ;;
  Darwin)
    install -m 0644 agent/launchd/eu.patchwatch.agent.plist /Library/LaunchDaemons/
    ;;
esac
echo 'Installed. Configure /etc/patchwatch/agent.json and api-key (0600), then enable the timer/launchd job; see docs/usage/agent.md.'
