#!/usr/bin/env python3
"""
Static analysis tool for skill quality review.

Performs automated checks on a skill directory and outputs structured JSON
with findings. This handles the objective, mechanical checks — the reviewing
agent handles subjective quality assessment.

Usage:
    python3 analyze.py /path/to/skill-directory
"""

import argparse
import ast
import json
import os
import re
import sys

SCRIPT_EXTENSIONS = {
    ".py", ".sh", ".bash", ".zsh", ".fish", ".rb", ".js", ".ts"
}
REFERENCE_EXTENSIONS = {
    ".md", ".txt", ".rst", ".adoc", ".json", ".yaml", ".yml", ".toml", ".csv"
}
ASSET_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".pdf", ".pptx",
    ".docx", ".xlsx", ".zip", ".tar", ".gz", ".tgz", ".ttf", ".otf", ".woff",
    ".woff2", ".html", ".css"
}

STDLIB_MODULES = {
    "abc", "argparse", "ast", "asyncio", "atexit", "base64", "bisect",
    "calendar", "cgi", "cmd", "codecs", "collections", "colorsys",
    "concurrent", "configparser", "contextlib", "copy", "csv", "ctypes",
    "dataclasses", "datetime", "decimal", "difflib", "dis", "email",
    "encodings", "enum", "errno", "faulthandler", "filecmp", "fileinput",
    "fnmatch", "fractions", "ftplib", "functools", "gc", "getopt",
    "getpass", "gettext", "glob", "gzip", "hashlib", "heapq", "hmac",
    "html", "http", "imaplib", "importlib", "inspect", "io", "ipaddress",
    "itertools", "json", "keyword", "linecache", "locale", "logging",
    "lzma", "mailbox", "math", "mimetypes", "mmap", "multiprocessing",
    "numbers", "operator", "optparse", "os", "pathlib", "pdb", "pickle",
    "pkgutil", "platform", "plistlib", "poplib", "posixpath", "pprint",
    "profile", "pstats", "queue", "quopri", "random", "re", "readline",
    "reprlib", "resource", "rlcompleter", "sched", "secrets", "select",
    "selectors", "shelve", "shlex", "shutil", "signal", "site", "smtplib",
    "socket", "socketserver", "sqlite3", "ssl", "stat", "statistics",
    "string", "struct", "subprocess", "sys", "sysconfig", "syslog",
    "tarfile", "tempfile", "textwrap", "threading", "time", "timeit",
    "tkinter", "token", "tokenize", "tomllib", "trace", "traceback",
    "tracemalloc", "turtle", "types", "typing", "unicodedata", "unittest",
    "urllib", "uuid", "venv", "warnings", "wave", "weakref", "webbrowser",
    "xml", "xmlrpc", "zipfile", "zipimport", "zlib",
}


def suggest_resource_folder(skill_dir: str, entry_name: str) -> str:
    """Suggest where a misplaced top-level entry should live."""
    full_path = os.path.join(skill_dir, entry_name)
    if os.path.isdir(full_path):
        lowered = entry_name.lower()
        if "script" in lowered or "bin" in lowered:
            return "scripts"
        if "reference" in lowered or "docs" in lowered or "doc" in lowered:
            return "references"
        return "assets"

    _, ext = os.path.splitext(entry_name.lower())
    if ext in SCRIPT_EXTENSIONS:
        return "scripts"
    if ext in REFERENCE_EXTENSIONS:
        return "references"
    if ext in ASSET_EXTENSIONS:
        return "assets"
    return "unknown"


def analyze_frontmatter(skill_md_path: str) -> dict:
    """Check SKILL.md frontmatter for required fields and quality."""
    findings = []
    metadata = {}

    with open(skill_md_path) as f:
        content = f.read()

    # Check frontmatter exists
    if not content.startswith("---"):
        findings.append({
            "severity": "error",
            "check": "frontmatter_exists",
            "message": "SKILL.md must start with YAML frontmatter (---)"
        })
        return {"findings": findings, "metadata": metadata}

    parts = content.split("---", 2)
    if len(parts) < 3:
        findings.append({
            "severity": "error",
            "check": "frontmatter_closed",
            "message": "YAML frontmatter is not properly closed with ---"
        })
        return {"findings": findings, "metadata": metadata}

    frontmatter = parts[1].strip()

    # Parse name
    name_match = re.search(r"^name:\s*(.+)$", frontmatter, re.MULTILINE)
    if name_match:
        metadata["name"] = name_match.group(1).strip()
    else:
        findings.append({
            "severity": "error",
            "check": "name_present",
            "message": "Frontmatter missing required 'name' field"
        })

    # Parse description
    desc_match = re.search(r"description:\s*>?\s*\n((?:\s+.+\n?)+)", frontmatter)
    if desc_match:
        desc = desc_match.group(1).strip()
        metadata["description"] = desc
        metadata["description_words"] = len(desc.split())
    elif re.search(r"description:\s*(.+)$", frontmatter, re.MULTILINE):
        desc = re.search(r"description:\s*(.+)$", frontmatter, re.MULTILINE).group(1).strip()
        metadata["description"] = desc
        metadata["description_words"] = len(desc.split())
    else:
        findings.append({
            "severity": "error",
            "check": "description_present",
            "message": "Frontmatter missing required 'description' field"
        })

    # Description quality checks
    if "description_words" in metadata:
        wc = metadata["description_words"]
        if wc < 20:
            findings.append({
                "severity": "warning",
                "check": "description_length",
                "message": f"Description is only {wc} words — likely too short for effective triggering. Aim for 50-120 words."
            })
        elif wc > 150:
            findings.append({
                "severity": "warning",
                "check": "description_length",
                "message": f"Description is {wc} words — may be too long for metadata that's always in context. Aim for 50-120 words."
            })

        desc_lower = metadata.get("description", "").lower()
        if "todo" in desc_lower or "[todo" in desc_lower:
            findings.append({
                "severity": "error",
                "check": "description_todo",
                "message": "Description contains TODO placeholder — not filled in"
            })

    return {"findings": findings, "metadata": metadata}


def analyze_structure(skill_dir: str) -> dict:
    """Check directory structure and file sizes."""
    findings = []
    stats = {}

    skill_md = os.path.join(skill_dir, "SKILL.md")
    if not os.path.exists(skill_md):
        findings.append({
            "severity": "error",
            "check": "skill_md_exists",
            "message": "SKILL.md not found — required for all skills"
        })
        return {"findings": findings, "stats": stats}

    # Line count
    with open(skill_md) as f:
        lines = f.readlines()
    stats["skill_md_lines"] = len(lines)

    if len(lines) > 500:
        findings.append({
            "severity": "warning",
            "check": "skill_md_length",
            "message": f"SKILL.md is {len(lines)} lines — exceeds 500-line guideline. Consider moving detail to references/."
        })

    # Check for unwanted files
    unwanted = ["README.md", "INSTALLATION_GUIDE.md", "CHANGELOG.md", "LICENSE"]
    for uw in unwanted:
        if os.path.exists(os.path.join(skill_dir, uw)):
            findings.append({
                "severity": "warning",
                "check": "unwanted_files",
                "message": f"Found {uw} — skills are for AI agents, not human onboarding. Consider removing."
            })

    # Count scripts
    scripts_dir = os.path.join(skill_dir, "scripts")
    if os.path.isdir(scripts_dir):
        scripts = [f for f in os.listdir(scripts_dir) if not f.startswith(".")]
        stats["script_count"] = len(scripts)
        stats["scripts"] = scripts
    else:
        stats["script_count"] = 0
        stats["scripts"] = []

    # Count references
    refs_dir = os.path.join(skill_dir, "references")
    if os.path.isdir(refs_dir):
        refs = [f for f in os.listdir(refs_dir) if not f.startswith(".")]
        stats["reference_count"] = len(refs)
        stats["references"] = refs
    else:
        stats["reference_count"] = 0
        stats["references"] = []

    # Count assets
    assets_dir = os.path.join(skill_dir, "assets")
    if os.path.isdir(assets_dir):
        assets = [f for f in os.listdir(assets_dir) if not f.startswith(".")]
        stats["asset_count"] = len(assets)
        stats["assets"] = assets
    else:
        stats["asset_count"] = 0
        stats["assets"] = []

    # Check for misplaced top-level files/directories that should be in subfolders.
    allowed_top_level = {"SKILL.md", "scripts", "references", "assets", "agents"}
    top_level_entries = [
        entry for entry in os.listdir(skill_dir)
        if not entry.startswith(".")
    ]
    unexpected = sorted(
        entry for entry in top_level_entries
        if entry not in allowed_top_level
    )
    stats["unexpected_top_level"] = unexpected

    if unexpected:
        by_target = {"scripts": [], "references": [], "assets": [], "unknown": []}
        for entry in unexpected:
            by_target[suggest_resource_folder(skill_dir, entry)].append(entry)

        actions = []
        for target in ("scripts", "references", "assets"):
            entries = by_target[target]
            if not entries:
                continue
            move_list = ", ".join(entries)
            target_dir = os.path.join(skill_dir, target)
            if os.path.isdir(target_dir):
                actions.append(f"move to {target}/: {move_list}")
            else:
                actions.append(f"create {target}/ and move: {move_list}")

        if by_target["unknown"]:
            actions.append(
                "manually classify and move: " + ", ".join(by_target["unknown"])
            )

        findings.append({
            "severity": "warning",
            "check": "top_level_layout",
            "message": (
                "Found top-level entries outside the canonical skill layout "
                f"(SKILL.md, scripts/, references/, assets/, agents/): "
                + ", ".join(unexpected)
                + ". Reorganize by "
                + "; ".join(actions)
                + "."
            ),
        })

    return {"findings": findings, "stats": stats}


def analyze_python_file(filepath: str) -> dict:
    """Static analysis of a single Python file."""
    findings = []
    stats = {}

    with open(filepath) as f:
        source = f.read()

    stats["lines"] = source.count("\n") + 1
    stats["path"] = filepath

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        findings.append({
            "severity": "error",
            "check": "syntax",
            "message": f"Syntax error: {e}"
        })
        return {"findings": findings, "stats": stats}

    # Collect all imports
    imports = {}
    third_party = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                imports[alias.name] = node.lineno
                if root not in STDLIB_MODULES:
                    third_party.append({"module": alias.name, "line": node.lineno})
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                root = node.module.split(".")[0]
                imports[node.module] = node.lineno
                if root not in STDLIB_MODULES:
                    third_party.append({"module": node.module, "line": node.lineno})

    stats["imports"] = list(imports.keys())
    stats["third_party"] = third_party

    if third_party:
        mods = ", ".join(tp["module"] for tp in third_party)
        findings.append({
            "severity": "info",
            "check": "third_party_imports",
            "message": f"Third-party dependencies found: {mods}. Ensure these are documented and installed."
        })

    # Check for unused imports by scanning source for references
    for mod_name, lineno in imports.items():
        short = mod_name.split(".")[-1]
        # Remove the import line itself before checking usage
        lines = source.split("\n")
        other_lines = "\n".join(l for i, l in enumerate(lines, 1) if i != lineno)
        if short not in other_lines:
            findings.append({
                "severity": "warning",
                "check": "unused_import",
                "message": f"Import '{mod_name}' (line {lineno}) appears unused"
            })

    # Check for defined-but-unused module-level variables (simple heuristic)
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name = target.id
                    # Count occurrences in source (excluding the definition line)
                    lines = source.split("\n")
                    other_lines = "\n".join(
                        l for i, l in enumerate(lines, 1) if i != node.lineno
                    )
                    # Use word boundary matching to avoid false positives
                    pattern = r"\b" + re.escape(name) + r"\b"
                    if not re.search(pattern, other_lines):
                        findings.append({
                            "severity": "warning",
                            "check": "unused_variable",
                            "message": f"Module-level variable '{name}' (line {node.lineno}) appears unused"
                        })

    # Check for functions with no docstring
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not (node.body and isinstance(node.body[0], ast.Expr) and
                    isinstance(node.body[0].value, (ast.Constant, ast.Str))):
                if not node.name.startswith("_"):
                    findings.append({
                        "severity": "info",
                        "check": "missing_docstring",
                        "message": f"Public function '{node.name}' (line {node.lineno}) has no docstring"
                    })

    # Check for error handling
    has_try = any(isinstance(n, ast.Try) for n in ast.walk(tree))
    stats["has_error_handling"] = has_try
    if not has_try:
        findings.append({
            "severity": "info",
            "check": "error_handling",
            "message": "No try/except blocks found — consider adding error handling for robustness"
        })

    return {"findings": findings, "stats": stats}


def analyze_skill(skill_dir: str) -> dict:
    """Run all analyses on a skill directory."""
    results = {
        "skill_dir": os.path.abspath(skill_dir),
        "sections": {},
        "summary": {"error": 0, "warning": 0, "info": 0}
    }

    # Frontmatter analysis
    skill_md = os.path.join(skill_dir, "SKILL.md")
    if os.path.exists(skill_md):
        fm = analyze_frontmatter(skill_md)
        results["sections"]["frontmatter"] = fm

    # Structure analysis
    struct = analyze_structure(skill_dir)
    results["sections"]["structure"] = struct

    # Python file analysis
    scripts_dir = os.path.join(skill_dir, "scripts")
    if os.path.isdir(scripts_dir):
        py_results = []
        for fname in sorted(os.listdir(scripts_dir)):
            if fname.endswith(".py"):
                py_results.append(
                    analyze_python_file(os.path.join(scripts_dir, fname))
                )
        if py_results:
            results["sections"]["python"] = py_results

    # Tally findings
    for section in results["sections"].values():
        items = section if isinstance(section, list) else [section]
        for item in items:
            for f in item.get("findings", []):
                results["summary"][f["severity"]] = (
                    results["summary"].get(f["severity"], 0) + 1
                )

    return results


def main():
    parser = argparse.ArgumentParser(description="Static analysis for skill quality")
    parser.add_argument("skill_dir", help="Path to skill directory")
    parser.add_argument("--format", choices=["json", "text"], default="text",
                        help="Output format")
    args = parser.parse_args()

    if not os.path.isdir(args.skill_dir):
        print(f"Error: '{args.skill_dir}' is not a directory", file=sys.stderr)
        sys.exit(1)

    results = analyze_skill(args.skill_dir)

    if args.format == "json":
        print(json.dumps(results, indent=2))
    else:
        # Human-readable text output
        print(f"=== Skill Analysis: {results['skill_dir']} ===\n")

        for section_name, section_data in results["sections"].items():
            items = section_data if isinstance(section_data, list) else [section_data]
            for item in items:
                # Print stats
                for key, val in item.get("stats", {}).items():
                    print(f"  [{section_name}] {key}: {val}")
                for key, val in item.get("metadata", {}).items():
                    if key != "description":  # Don't dump the full description
                        print(f"  [{section_name}] {key}: {val}")

                # Print findings
                for f in item.get("findings", []):
                    icon = {"error": "X", "warning": "!", "info": "-"}[f["severity"]]
                    print(f"  [{icon}] {f['check']}: {f['message']}")
            print()

        s = results["summary"]
        print(f"Summary: {s['error']} error(s), {s['warning']} warning(s), {s['info']} info")


if __name__ == "__main__":
    main()
