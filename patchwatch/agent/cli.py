# SPDX-License-Identifier: Apache-2.0
"""Command line entry point of the host agent."""
import argparse
import os
import ssl
import subprocess

from .config import DEFAULT_CONFIG_PATH, AgentConfig
from .profile import initialize_profile
from .runner import run

DESCRIPTION = "Privacy-minimized Syft inventory and repeatable host upload."


def build_parser():
    """Argument parser of ``patchwatch-agent``."""
    parser = argparse.ArgumentParser(prog="patchwatch-agent", description=DESCRIPTION)
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--init-config", action="store_true",
                        help="create the profile with a new host_id if it does not exist, then exit (used by packages)")
    parser.add_argument("--syft", help="with --init-config: absolute path of the Syft binary to record in the profile")
    return parser


def main(argv=None):
    """Entry point: run one inventory (default) or create the profile (``--init-config``). Failures exit 1 with a secret-free message."""
    parser = build_parser()
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.init_config:
            created = initialize_profile(args.config, syft=args.syft)
            print(("Created " if created else "Kept existing ") + args.config)
            return
        run(AgentConfig.load(args.config))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, ssl.SSLError) as error:
        # No URLs, HTTP response bodies or credentials in logs.
        parser.exit(1, f"Agent failed: {type(error).__name__}; check config, Syft and API connectivity\n")
