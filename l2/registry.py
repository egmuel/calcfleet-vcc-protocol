"""Local, statically-defined L2 formula allowlist.

SECURITY MODEL (ADR-005 — "local allowlisted formulas only")
------------------------------------------------------------
L2 answers the question "does re-running the formula reproduce the declared
outputs?". Executing anything *named by the certificate* would be remote code
execution by construction: a hostile certificate could point ``formula.registry``
at an attacker-controlled URL (or otherwise smuggle code) and the verifier would
run it. ``node:vm`` / Python sandboxes are explicitly NOT security boundaries.

Therefore this registry:

  1. Resolves executors EXCLUSIVELY from this local, statically-declared
     allowlist. The certificate contributes ONLY the lookup key ``(slug, version)``.
  2. NEVER reads ``formula.registry`` (or any URL/field from the certificate) to
     locate, import, fetch, download, ``eval``, or execute code. Nothing from the
     certificate is ever evaluated.
  3. Refuses any ``(slug, version)`` not present here, returning ``None`` so the
     caller reports ``formula-unavailable`` — a *reproducibility* outcome, never an
     authenticity/integrity (L1) failure.

Adding a formula is a deliberate, reviewed act: you add an entry below and ship the
package under ``l2/registry/<slug>/<version>/``. There is deliberately NO plugin
surface, NO dynamic discovery, and NO network path.
"""

from __future__ import annotations

import importlib.util
import os
from types import ModuleType
from typing import Callable, Dict, Optional, Tuple

# Directory holding the local formula packages: registry/<slug>/<version>/formula.py
_REGISTRY_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "registry")


# The allowlist. Keys are (slug, version). Values describe where the LOCAL package
# lives. NOTHING here is ever taken from a certificate.
_ALLOWLIST: Dict[Tuple[str, str], Dict[str, str]] = {
    ("compound-interest-calculator", "1.0.0"): {
        "package_dir": "compound-interest-calculator/1.0.0",
        "module": "formula",
        "callable": "compute",
    },
}


def is_allowed(slug: str, version: str) -> bool:
    """True iff (slug, version) is in the static local allowlist."""
    return (slug, version) in _ALLOWLIST


def _load_module(package_dir: str, module: str) -> ModuleType:
    """Load a local formula module by explicit file path.

    We resolve the path ourselves from the allowlist entry (never from certificate
    input), so an attacker cannot influence which file is imported.
    """
    module_path = os.path.join(_REGISTRY_ROOT, package_dir, module + ".py")
    # Defense in depth: ensure the resolved path stays inside the registry root.
    real_root = os.path.realpath(_REGISTRY_ROOT)
    real_path = os.path.realpath(module_path)
    if not real_path.startswith(real_root + os.sep):
        raise RuntimeError("refusing to load formula module outside the registry root")

    spec = importlib.util.spec_from_file_location(
        f"l2_formula_{package_dir.replace('/', '_')}", real_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not create import spec for local formula module")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def resolve(slug: str, version: str) -> Optional[Callable[[dict], dict]]:
    """Return the pure ``compute`` function for an ALLOWLISTED (slug, version).

    Returns ``None`` when the formula is not in the local allowlist. NEVER consults
    the certificate to locate code. Never raises on an unknown formula; callers
    treat ``None`` as ``formula-unavailable``.
    """
    entry = _ALLOWLIST.get((slug, version))
    if entry is None:
        return None
    mod = _load_module(entry["package_dir"], entry["module"])
    fn = getattr(mod, entry["callable"], None)
    if not callable(fn):
        return None
    return fn
