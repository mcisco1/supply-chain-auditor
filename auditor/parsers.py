import json
import os
import re
from pathlib import Path
from typing import Tuple

from .models import Ecosystem


def _clean_version(version_spec: str) -> str:
    """Strip comparison operators and extras, return a usable version string."""
    if not version_spec:
        return ""
    version_spec = version_spec.strip()
    version_spec = re.sub(r"\[.*?\]", "", version_spec)
    match = re.search(r"(\d+\.\d+[\.\d]*)", version_spec)
    return match.group(1) if match else version_spec.lstrip("^~>=!<")


def parse_requirements_txt(filepath: str) -> list:
    """Parse a requirements.txt file into (name, version) tuples."""
    deps = []
    path = Path(filepath)
    if not path.exists():
        return deps

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "==" in line:
            name, ver = line.split("==", 1)
            deps.append((name.strip().split("[")[0], _clean_version(ver)))
        elif ">=" in line:
            name, ver = line.split(">=", 1)
            ver = ver.split(",")[0]
            deps.append((name.strip().split("[")[0], _clean_version(ver)))
        elif "~=" in line:
            name, ver = line.split("~=", 1)
            deps.append((name.strip().split("[")[0], _clean_version(ver)))
        else:
            name = re.split(r"[<>=!~]", line)[0].strip().split("[")[0]
            if name:
                deps.append((name, ""))
    return deps


def parse_pipfile(filepath: str) -> list:
    """Parse a Pipfile for dependencies."""
    deps = []
    path = Path(filepath)
    if not path.exists():
        return deps

    in_packages = False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line == "[packages]":
            in_packages = True
            continue
        elif line.startswith("["):
            in_packages = False
            continue
        if in_packages and "=" in line:
            parts = line.split("=", 1)
            name = parts[0].strip().strip('"')
            ver = parts[1].strip().strip('"').strip("'")
            if ver == "*":
                ver = ""
            deps.append((name, _clean_version(ver)))
    return deps


def parse_pyproject_toml(filepath: str) -> list:
    """Parse pyproject.toml for dependencies."""
    deps = []
    path = Path(filepath)
    if not path.exists():
        return deps

    try:
        import toml
        data = toml.loads(path.read_text(encoding="utf-8"))
    except ImportError:
        return _parse_pyproject_fallback(path)
    except Exception:
        return deps

    dep_list = []
    if "project" in data and "dependencies" in data["project"]:
        dep_list = data["project"]["dependencies"]
    elif "tool" in data:
        poetry = data["tool"].get("poetry", {})
        poetry_deps = poetry.get("dependencies", {})
        for name, ver_info in poetry_deps.items():
            if name.lower() == "python":
                continue
            ver = ""
            if isinstance(ver_info, str):
                ver = ver_info
            elif isinstance(ver_info, dict):
                ver = ver_info.get("version", "")
            deps.append((name, _clean_version(ver)))
        return deps

    for dep_str in dep_list:
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(.*)$", dep_str)
        if match:
            name = match.group(1)
            ver = _clean_version(match.group(2))
            deps.append((name, ver))
    return deps


def _parse_pyproject_fallback(path: Path) -> list:
    """Regex-based fallback when toml is unavailable."""
    deps = []
    content = path.read_text(encoding="utf-8", errors="replace")
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if "dependencies" in stripped and "=" in stripped and "[" in stripped:
            in_deps = True
            continue
        if in_deps:
            if stripped == "]":
                in_deps = False
                continue
            cleaned = stripped.strip('",').strip("',")
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(.*)$", cleaned)
            if match:
                deps.append((match.group(1), _clean_version(match.group(2))))
    return deps


def parse_setup_py(filepath: str) -> list:
    """Extract dependencies from setup.py using regex."""
    deps = []
    path = Path(filepath)
    if not path.exists():
        return deps

    content = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"install_requires\s*=\s*\[(.*?)\]", content, re.DOTALL)
    if match:
        block = match.group(1)
        for dep_str in re.findall(r"""['"]([^'"]+)['"]""", block):
            m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(.*)$", dep_str)
            if m:
                deps.append((m.group(1), _clean_version(m.group(2))))
    return deps


def parse_setup_cfg(filepath: str) -> list:
    """Extract dependencies from setup.cfg."""
    deps = []
    path = Path(filepath)
    if not path.exists():
        return deps

    in_install = False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip() == "install_requires =":
            in_install = True
            continue
        if in_install:
            if line and not line[0].isspace():
                break
            cleaned = line.strip()
            if cleaned:
                m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(.*)$", cleaned)
                if m:
                    deps.append((m.group(1), _clean_version(m.group(2))))
    return deps


def parse_package_json(filepath: str) -> list:
    """Parse package.json for production and dev dependencies."""
    deps = []
    path = Path(filepath)
    if not path.exists():
        return deps

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return deps

    for section in ["dependencies", "devDependencies"]:
        for name, ver in data.get(section, {}).items():
            deps.append((name, _clean_version(ver)))
    return deps


def parse_package_lock_json(filepath: str) -> list:
    """Parse package-lock.json for resolved dependency versions."""
    deps = []
    path = Path(filepath)
    if not path.exists():
        return deps

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return deps

    packages = data.get("packages", data.get("dependencies", {}))
    for pkg_path, info in packages.items():
        name = pkg_path
        if pkg_path.startswith("node_modules/"):
            name = pkg_path.split("node_modules/")[-1]
        if not name:
            continue
        ver = info.get("version", "")
        if ver:
            deps.append((name, ver))
    return deps


def parse_yarn_lock(filepath: str) -> list:
    """Parse yarn.lock for resolved versions."""
    deps = []
    path = Path(filepath)
    if not path.exists():
        return deps

    current_name = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith(" ") and line.endswith(":"):
            match = re.match(r'^"?(@?[^@"]+)@', line)
            if match:
                current_name = match.group(1)
        elif current_name and "version" in line:
            match = re.search(r'version\s+"?([^"]+)"?', line)
            if match:
                deps.append((current_name, match.group(1)))
                current_name = None
    return deps


PYTHON_PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "requirements-dev.txt": parse_requirements_txt,
    "requirements_dev.txt": parse_requirements_txt,
    "Pipfile": parse_pipfile,
    "pyproject.toml": parse_pyproject_toml,
    "setup.py": parse_setup_py,
    "setup.cfg": parse_setup_cfg,
}

NODE_PARSERS = {
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock_json,
    "yarn.lock": parse_yarn_lock,
}


def scan_directory(target_path: str) -> Tuple[list, list]:
    """
    Walk the target directory and extract all dependencies.
    Returns (python_deps, node_deps) as lists of (name, version) tuples.
    """
    python_deps = {}
    node_deps = {}
    target = Path(target_path)

    if not target.exists():
        raise FileNotFoundError(f"Target path not found: {target_path}")

    skip_dirs = {"node_modules", ".venv", "venv", "__pycache__", ".git", ".tox", "env"}

    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            fpath = os.path.join(root, fname)

            if fname in PYTHON_PARSERS:
                for name, ver in PYTHON_PARSERS[fname](fpath):
                    normalized = name.lower().replace("-", "_")
                    if normalized not in python_deps or (ver and not python_deps[normalized][1]):
                        python_deps[normalized] = (name, ver)

            if fname in NODE_PARSERS:
                for name, ver in NODE_PARSERS[fname](fpath):
                    if name not in node_deps or (ver and not node_deps[name][1]):
                        node_deps[name] = (name, ver)

    return list(python_deps.values()), list(node_deps.values())
