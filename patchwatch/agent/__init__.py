# SPDX-License-Identifier: Apache-2.0
"""The PatchWatch host agent.

Deliberately self-contained: this package and :mod:`patchwatch.core` are everything an installation
package (``.deb``, ``.pkg``, zipapp) must ship. Nothing in here may import :mod:`patchwatch.dtrack`,
:mod:`patchwatch.ci` or :mod:`patchwatch.bridge`; ``tests/test_boundaries.py`` enforces that.

Modules: ``config`` (validated profile), ``scanner`` (Syft), ``extensions`` (editor/browser plugins),
``runner`` (one run), ``cli`` (entry point).
"""
from .config import AgentConfig
from .runner import run
from .cli import main

__all__ = ["AgentConfig", "run", "main"]
