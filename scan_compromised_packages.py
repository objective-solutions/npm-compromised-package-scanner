#!/usr/bin/env python3

"""Scan lock/manifest files in the current directory tree for compromised packages.

- Reads compromised packages from all `bom-*.json` files (in current dir or script dir).
- Each BOM file has format: {"name": "BOM Name", "compromised-packages": [{"pkg": "version"}, ...]}
- Recursively scans for common JavaScript/TypeScript dependency lock/manifest files.
- Searches each file's text for package name and version occurrences.
- Prints each match as:
    Compromised package found: <package name>:<version>
- Prints a summary at the end, showing which BOM each finding came from.

This script uses only the Python standard library.
"""

import json
import os
from collections import defaultdict
from typing import DefaultDict, Dict, List, Set, Tuple


Node = Tuple[str, str]

# Common JS/TS dependency lock files to scan. Extend if needed.
LOCKFILE_NAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pnpm-lock.yml",
    "npm-shrinkwrap.json",
    "bun.lockb",  # binary, but we still try a naive text search
}


def find_bom_files(root: str = ".") -> List[str]:
    """Find all bom-*.json files in the current directory or script directory."""
    candidates: List[str] = []

    # 1) Look in the current working directory.
    abs_root = os.path.abspath(root)
    try:
        for filename in os.listdir(abs_root):
            if filename.startswith("bom-") and filename.endswith(".json"):
                candidates.append(os.path.join(abs_root, filename))
    except OSError:
        pass

    # 2) Look in the script directory.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir != abs_root:
        try:
            for filename in os.listdir(script_dir):
                if filename.startswith("bom-") and filename.endswith(".json"):
                    script_bom = os.path.join(script_dir, filename)
                    if script_bom not in candidates:
                        candidates.append(script_bom)
        except OSError:
            pass

    return sorted(candidates)


def load_bom_file(path: str) -> tuple:
    """Load a BOM file and return (bom_name, list_of_packages).

    Expected format:
    {
        "name": "BOM Name",
        "compromised-packages": [ {"pkg": "version"}, ... ]
    }

    Returns (None, []) if the file cannot be parsed.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to read {path}: {exc}")
        return None, []

    if not isinstance(data, dict):
        print(f"Invalid BOM format in {path}: expected a JSON object.")
        return None, []

    bom_name = data.get("name", "Unknown")
    packages_list = data.get("compromised-packages", [])

    if not isinstance(packages_list, list):
        print(f"Invalid BOM format in {path}: 'compromised-packages' must be a list.")
        return bom_name, []

    compromised: List[Tuple[str, str]] = []
    for idx, item in enumerate(packages_list):
        if not isinstance(item, dict) or not item:
            continue
        # Each item is expected to have a single key: package name.
        for name, version in item.items():
            if isinstance(name, str) and isinstance(version, str):
                compromised.append((name, version))
            else:
                print(f"Skipping invalid entry in {path} at index {idx}: {item!r}")
            break

    return bom_name, compromised


def load_all_boms() -> tuple:
    """Load all bom-*.json files and return (all_packages, package_to_bom_name).

    Returns:
        - List of (package_name, version) tuples from all BOMs
        - Dict mapping (package_name, version) -> bom_name
    """
    bom_files = find_bom_files(".")

    if not bom_files:
        print("No bom-*.json files found. Nothing to scan.")
        return [], {}

    all_packages: List[Tuple[str, str]] = []
    package_to_bom: Dict[Tuple[str, str], str] = {}

    for bom_file in bom_files:
        bom_name, packages = load_bom_file(bom_file)
        if bom_name is None:
            continue
        for pkg_tuple in packages:
            all_packages.append(pkg_tuple)
            package_to_bom[pkg_tuple] = bom_name

    return all_packages, package_to_bom


def iter_lockfiles(root: str = ".") -> List[str]:
    """Return a list of lock/manifest files under the given root directory."""
    matches: List[str] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for filename in filenames:
            if filename in LOCKFILE_NAMES:
                matches.append(os.path.join(dirpath, filename))
    return matches


def scan_file_for_packages(path: str, compromised: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Return list of (package, version) from `compromised` found in the file text.

    We use a simple substring search: name and version must both appear in the file
    (not necessarily adjacent). This is conservative but easy and dependency-free.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except Exception as exc:  # noqa: BLE001
        print(f"Could not read {path}: {exc}")
        return []

    found: List[Tuple[str, str]] = []
    for name, version in compromised:
        if name in text and version in text:
            found.append((name, version))
    return found


def _build_graph_lock_v1(data: Dict) -> Tuple[Dict[Node, List[Node]], Dict[str, List[Node]]]:
    graph: DefaultDict[Node, List[Node]] = defaultdict(list)
    name_to_nodes: DefaultDict[str, List[Node]] = defaultdict(list)

    def walk(name: str, info: Dict) -> None:
        version = str(info.get("version", "?"))
        node: Node = (name, version)
        if node not in name_to_nodes[name]:
            name_to_nodes[name].append(node)
        deps = info.get("dependencies") or {}
        if not isinstance(deps, dict):
            return
        for child_name, child_info in deps.items():
            if not isinstance(child_info, dict):
                continue
            child_version = str(child_info.get("version", "?"))
            child_node: Node = (child_name, child_version)
            graph[node].append(child_node)
            if child_node not in name_to_nodes[child_name]:
                name_to_nodes[child_name].append(child_node)
            walk(child_name, child_info)

    root_deps = data.get("dependencies") or {}
    if isinstance(root_deps, dict):
        for root_name, root_info in root_deps.items():
            if isinstance(root_info, dict):
                walk(root_name, root_info)

    return graph, name_to_nodes


def _build_graph_lock_v2(data: Dict) -> Tuple[Dict[Node, List[Node]], Dict[str, List[Node]]]:
    graph: DefaultDict[Node, List[Node]] = defaultdict(list)
    name_to_nodes: DefaultDict[str, List[Node]] = defaultdict(list)

    deps = data.get("dependencies") or {}
    if not isinstance(deps, dict):
        return {}, {}

    for name, info in deps.items():
        if not isinstance(info, Dict):
            continue
        version = str(info.get("version", "?"))
        node: Node = (name, version)
        if node not in name_to_nodes[name]:
            name_to_nodes[name].append(node)

    for name, info in deps.items():
        if not isinstance(info, Dict):
            continue
        version = str(info.get("version", "?"))
        parent: Node = (name, version)
        children_names: Set[str] = set()
        requires = info.get("requires") or {}
        if isinstance(requires, dict):
            children_names.update(requires.keys())
        child_deps = info.get("dependencies") or {}
        if isinstance(child_deps, dict):
            children_names.update(child_deps.keys())
        for child_name in children_names:
            child_info = deps.get(child_name)
            if isinstance(child_info, Dict):
                child_version = str(child_info.get("version", "?"))
            else:
                child_version = "?"
            child: Node = (child_name, child_version)
            graph[parent].append(child)
            if child not in name_to_nodes[child_name]:
                name_to_nodes[child_name].append(child)

    return graph, name_to_nodes


def build_graph_from_package_lock(lockfile_path: str) -> Tuple[Dict[Node, List[Node]], Dict[str, List[Node]]]:
    try:
        with open(lockfile_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}, {}

    if not isinstance(data, dict):
        return {}, {}

    lockfile_version = data.get("lockfileVersion")
    if "packages" in data or (isinstance(lockfile_version, int) and lockfile_version >= 2):
        return _build_graph_lock_v2(data)
    return _build_graph_lock_v1(data)


def _find_paths(
    graph: Dict[Node, List[Node]],
    roots: List[Node],
    target: Node,
    max_paths: int = 20,
    max_depth: int = 20,
) -> List[List[Node]]:
    paths: List[List[Node]] = []

    def dfs(node: Node, path: List[Node], visited: Set[Node]) -> None:
        if node in visited:
            return
        if len(path) >= max_depth:
            return
        visited.add(node)
        path.append(node)
        if node == target:
            paths.append(list(path))
        else:
            for child in graph.get(node, []):
                dfs(child, path, visited)
        path.pop()
        visited.remove(node)

    for root in roots:
        dfs(root, [], set())
        if len(paths) >= max_paths:
            break
    return paths


def print_dependency_trees(matches_per_lockfile: Dict[str, Set[Tuple[str, str]]]) -> None:
    for lockfile, compromised_set in sorted(matches_per_lockfile.items()):
        if os.path.basename(lockfile) != "package-lock.json":
            continue

        package_json = os.path.join(os.path.dirname(lockfile), "package.json")
        if not os.path.exists(package_json):
            print(f"No package.json next to {lockfile}; cannot build dependency trees.")
            continue

        try:
            with open(package_json, "r", encoding="utf-8") as f:
                pkg_data = json.load(f)
        except Exception as exc:
            print(f"Failed to read {package_json}: {exc}")
            continue

        root_dep_names: Set[str] = set()
        for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps = pkg_data.get(key)
            if isinstance(deps, dict):
                root_dep_names.update(str(k) for k in deps.keys())

        if not root_dep_names:
            print(f"No root dependencies in {package_json}; skipping dependency trees for {lockfile}.")
            continue

        graph, name_to_nodes = build_graph_from_package_lock(lockfile)
        if not graph or not name_to_nodes:
            print(f"Could not build dependency graph from {lockfile}; skipping dependency trees.")
            continue

        root_nodes: List[Node] = []
        for dep_name in root_dep_names:
            for node in name_to_nodes.get(dep_name, []):
                root_nodes.append(node)

        if not root_nodes:
            print(f"No root dependency nodes found in lockfile {lockfile}; skipping dependency trees.")
            continue

        for comp_name, comp_version in sorted(compromised_set):
            candidates: List[Node] = [
                node for node in name_to_nodes.get(comp_name, [])
                if node[1] == comp_version
            ]
            if not candidates:
                continue

            print(
                f"\nDependency paths for compromised package {comp_name}:{comp_version} (lockfile: {lockfile}):",
            )
            any_paths = False
            path_index = 1
            for target in candidates:
                paths = _find_paths(graph, root_nodes, target)
                for path in paths:
                    any_paths = True
                    print(f"  Path {path_index}:")
                    for index, (name, version) in enumerate(path):
                        indent = "    "
                        if index == 0:
                            print(f"{indent}{name}:{version}")
                        else:
                            print(f"{indent}-> {name}:{version}")
                    path_index += 1

            if not any_paths:
                print("  (No path from package.json root dependencies to this package could be determined.)")


def main() -> None:
    compromised, package_to_bom = load_all_boms()
    if not compromised:
        return

    lockfiles = iter_lockfiles(".")
    if not lockfiles:
        # Check if package.json exists to provide a helpful warning
        if os.path.exists("package.json") or os.path.exists(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "package.json")
        ):
            print("⚠️  Warning: package.json found, but no lock files detected.")
            print("Lock files (package-lock.json, yarn.lock, pnpm-lock.yaml, etc.) are required for a complete scan.")
            print("\nTo safely scan this project without running install commands:")
            print("  1. Ensure lockfiles already exist in the project")
            print("  2. If you don't have a lockfile, don't run install in your local machine, it might compromise your workstation. Create a docker environment or a sandboxed virtual machine")
        else:
            print("No lock or manifest files found to scan.")
        return

    total_matches: Dict[Tuple[str, str], int] = {}
    matches_per_lockfile: Dict[str, Set[Tuple[str, str]]] = {}

    for lockfile in lockfiles:
        matches = scan_file_for_packages(lockfile, compromised)
        if not matches:
            continue
        lockfile_matches = matches_per_lockfile.setdefault(lockfile, set())
        for name, version in matches:
            print(f"Compromised package found: {name}:{version}")
            total_matches[(name, version)] = total_matches.get((name, version), 0) + 1
            lockfile_matches.add((name, version))

    print("\nSummary:")
    if not total_matches:
        print("No compromised packages found in scanned files.")
    else:
        unique_count = len(total_matches)
        total_hits = sum(total_matches.values())
        print(f"Unique compromised packages found: {unique_count}")
        print(f"Total occurrences across files: {total_hits}")
        print("Details:")
        for (name, version), count in sorted(total_matches.items()):
            bom_name = package_to_bom.get((name, version), "Unknown")
            print(f"  - {name}:{version} (BOM: {bom_name}, occurrences: {count})")

        print_dependency_trees(matches_per_lockfile)

    print("\nScanned files:")
    for scanned in sorted(lockfiles):
        print(f"  - {scanned}")


if __name__ == "__main__":  # pragma: no cover
    main()
