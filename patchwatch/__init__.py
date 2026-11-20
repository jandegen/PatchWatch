# SPDX-License-Identifier: Apache-2.0
"""PatchWatch: developer software inventory and alerting on top of Dependency-Track.

Layers (imports only point downwards; ``tests/test_boundaries.py`` enforces this)::

    core    shared building blocks, standard library only: http, tags, sbom, services, quality
    agent   host agent (Syft scan + upload); ships on its own in .deb/.pkg/zipapp packages
    dtrack  Dependency-Track client and administration: setup, policies, groups, versions,
            register, monitor, compliance, scopes, legacy
    ci      GitLab CI jobs: pipeline (inventory job), bsi (BSI SBOM checks), mr (merge-request
            and branch feedback), delta (version comparison)
    bridge  webhook receiver that turns Dependency-Track notifications into alerts

Every command is runnable as ``python -m patchwatch.<layer>.<module>``; ``python -m patchwatch.agent``
and ``python -m patchwatch.ci`` run the agent and the CI job.
"""
__version__ = "1.0.8"
