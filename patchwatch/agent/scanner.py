# SPDX-License-Identifier: Apache-2.0
"""Syft invocation: one CycloneDX SBOM per scan source."""
import json
from pathlib import Path
import subprocess

# Pseudo file systems, container storage and volatile directories never contain installed software.
EXCLUDES = ("./proc/**", "./sys/**", "./dev/**", "./run/**", "./tmp/**",
            "./var/lib/docker/**", "./var/lib/containerd/**", "./System/**", "./Volumes/**")


def source_spec(root_or_image: str, is_directory: bool) -> str:
    """Syft source expression: ``dir:<resolved path>`` for directories, the image reference otherwise."""
    return "dir:" + str(Path(root_or_image).resolve()) if is_directory else root_or_image


def syft_command(syft: str, source: str, output: Path, excludes=()) -> list:
    """Command line of ``syft scan`` for one source with the default and extra exclusions."""
    command = [syft, "scan", source, "-o", "cyclonedx-json=" + str(output),
               "--select-catalogers", "+javascript-package-cataloger"]
    for excluded in (*EXCLUDES, *excludes):
        command.extend(["--exclude", excluded])
    return command


def scan(syft: str, source: str, output: Path, excludes=(), timeout=7200) -> dict:
    """Run Syft and return the decoded SBOM. Syft output and errors are discarded: they may contain paths."""
    subprocess.run(syft_command(syft, source, output, excludes), check=True, timeout=timeout,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return json.loads(output.read_text())
