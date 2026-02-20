import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests

from .models import Dependency, Ecosystem

logger = logging.getLogger(__name__)

SESSION = requests.Session()
SESSION.headers.update({"Accept": "application/json"})

PYPI_CACHE = {}
NPM_CACHE = {}
_cache_lock = threading.Lock()
MAX_DEPTH = 4
REQUEST_TIMEOUT = 10


class _ThreadSafeSet:
    """Thread-safe set for tracking visited packages across threads."""

    def __init__(self):
        self._set = set()
        self._lock = threading.Lock()

    def try_add(self, item) -> bool:
        """Atomically check and add. Returns True if item was new."""
        with self._lock:
            if item in self._set:
                return False
            self._set.add(item)
            return True

    def __contains__(self, item):
        with self._lock:
            return item in self._set


def _fetch_pypi_metadata(package_name: str) -> Optional[dict]:
    """Retrieve package metadata from PyPI."""
    normalized = package_name.lower().replace("_", "-")
    with _cache_lock:
        if normalized in PYPI_CACHE:
            return PYPI_CACHE[normalized]

    url = f"https://pypi.org/pypi/{normalized}/json"
    try:
        resp = SESSION.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            with _cache_lock:
                PYPI_CACHE[normalized] = data
            return data
    except Exception as exc:
        logger.debug("PyPI lookup failed for %s: %s", package_name, exc)

    with _cache_lock:
        PYPI_CACHE[normalized] = None
    return None


def _fetch_npm_metadata(package_name: str) -> Optional[dict]:
    """Retrieve package metadata from the npm registry."""
    with _cache_lock:
        if package_name in NPM_CACHE:
            return NPM_CACHE[package_name]

    url = f"https://registry.npmjs.org/{package_name}"
    try:
        resp = SESSION.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            with _cache_lock:
                NPM_CACHE[package_name] = data
            return data
    except Exception as exc:
        logger.debug("npm lookup failed for %s: %s", package_name, exc)

    with _cache_lock:
        NPM_CACHE[package_name] = None
    return None


def _get_pypi_latest(metadata: dict) -> str:
    """Extract latest version from PyPI metadata."""
    return metadata.get("info", {}).get("version", "")


def _get_pypi_license(metadata: dict) -> str:
    """Extract license info from PyPI metadata."""
    info = metadata.get("info", {})
    lic = info.get("license", "")
    if lic and len(lic) < 100:
        return lic
    classifiers = info.get("classifiers", [])
    for c in classifiers:
        if "License" in c:
            parts = c.split("::")
            return parts[-1].strip() if parts else c
    return "Unknown"


def _get_pypi_deps(metadata: dict, version: str) -> list:
    """Extract direct dependencies of a PyPI package for a given version."""
    deps = []
    requires = metadata.get("info", {}).get("requires_dist")
    if not requires:
        return deps

    for req_str in requires:
        if "extra ==" in req_str:
            continue
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)", req_str)
        if match:
            dep_name = match.group(1)
            ver_match = re.search(r"\(([^)]+)\)", req_str)
            ver = ""
            if ver_match:
                ver_spec = ver_match.group(1)
                exact = re.search(r"==\s*([\d\.]+)", ver_spec)
                gte = re.search(r">=\s*([\d\.]+)", ver_spec)
                if exact:
                    ver = exact.group(1)
                elif gte:
                    ver = gte.group(1)
            deps.append((dep_name, ver))
    return deps


def _get_npm_latest(metadata: dict) -> str:
    """Extract latest version from npm metadata."""
    dist_tags = metadata.get("dist-tags", {})
    return dist_tags.get("latest", "")


def _get_npm_license(metadata: dict) -> str:
    """Extract license from npm metadata."""
    latest = _get_npm_latest(metadata)
    versions = metadata.get("versions", {})
    ver_data = versions.get(latest, {})
    lic = ver_data.get("license", metadata.get("license", ""))
    if isinstance(lic, dict):
        return lic.get("type", "Unknown")
    return lic or "Unknown"


def _get_npm_deps(metadata: dict, version: str) -> list:
    """Extract dependencies for a specific npm package version."""
    deps = []
    versions = metadata.get("versions", {})
    ver_data = versions.get(version, {})
    if not ver_data:
        latest = _get_npm_latest(metadata)
        ver_data = versions.get(latest, {})

    prod_deps = ver_data.get("dependencies", {})
    for name, ver_range in prod_deps.items():
        clean = re.sub(r"[^0-9\.]", "", ver_range.split(" ")[0])
        deps.append((name, clean))
    return deps


def resolve_python_package(
    name: str, version: str, depth: int = 0, visited=None
) -> Dependency:
    """Build a dependency node for a Python package, resolving children recursively."""
    if visited is None:
        visited = _ThreadSafeSet()

    normalized = name.lower().replace("_", "-")
    dep = Dependency(
        name=name,
        version=version,
        ecosystem=Ecosystem.PYTHON,
        is_direct=(depth == 0),
        depth=depth,
    )

    metadata = _fetch_pypi_metadata(name)
    if metadata:
        dep.latest_version = _get_pypi_latest(metadata)
        dep.license_type = _get_pypi_license(metadata)
        dep.description = (metadata.get("info", {}).get("summary") or "")[:200]

        if depth < MAX_DEPTH and visited.try_add(normalized):
            child_deps = _get_pypi_deps(metadata, version)
            for child_name, child_ver in child_deps:
                child_norm = child_name.lower().replace("_", "-")
                if child_norm not in visited:
                    child = resolve_python_package(
                        child_name, child_ver, depth + 1, visited
                    )
                    dep.children.append(child)

    return dep


def resolve_node_package(
    name: str, version: str, depth: int = 0, visited=None
) -> Dependency:
    """Build a dependency node for an npm package, resolving children recursively."""
    if visited is None:
        visited = _ThreadSafeSet()

    dep = Dependency(
        name=name,
        version=version,
        ecosystem=Ecosystem.NODE,
        is_direct=(depth == 0),
        depth=depth,
    )

    metadata = _fetch_npm_metadata(name)
    if metadata:
        dep.latest_version = _get_npm_latest(metadata)
        dep.license_type = _get_npm_license(metadata)
        info = metadata.get("versions", {}).get(version, {})
        dep.description = (info.get("description") or metadata.get("description") or "")[:200]

        if depth < MAX_DEPTH and visited.try_add(name):
            child_deps = _get_npm_deps(metadata, version)
            for child_name, child_ver in child_deps:
                if child_name not in visited:
                    child = resolve_node_package(
                        child_name, child_ver, depth + 1, visited
                    )
                    dep.children.append(child)

    return dep


def resolve_all(
    python_deps: list, node_deps: list, max_workers: int = 8
) -> list:
    """
    Resolve all dependencies in parallel, returning a list of fully-populated
    Dependency trees.
    """
    results = []
    visited_py = _ThreadSafeSet()
    visited_node = _ThreadSafeSet()

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {}
        for name, ver in python_deps:
            f = pool.submit(resolve_python_package, name, ver, 0, visited_py)
            futures[f] = name
        for name, ver in node_deps:
            f = pool.submit(resolve_node_package, name, ver, 0, visited_node)
            futures[f] = name

        for future in as_completed(futures):
            try:
                dep = future.result()
                results.append(dep)
            except Exception as exc:
                logger.warning("Failed to resolve %s: %s", futures[future], exc)

    results.sort(key=lambda d: d.name.lower())
    return results


def flatten_tree(deps: list) -> list:
    """Flatten a dependency tree list into a unique package list."""
    seen = set()
    flat = []

    def _walk(dep: Dependency):
        key = (dep.name.lower(), dep.ecosystem)
        if key not in seen:
            seen.add(key)
            flat.append(dep)
        for child in dep.children:
            _walk(child)

    for d in deps:
        _walk(d)
    return flat
