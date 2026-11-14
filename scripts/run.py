#!/usr/bin/env python3
"""DSH Plugin Scanner - static security analysis for DeepSeek Harness plugins."""
import argparse, json, re, sys
from pathlib import Path

RISKY_IMPORTS = [
    ("child_process", "spawns child processes"),
    ("eval(", "evaluates arbitrary code"),
    ("new Function(", "evaluates arbitrary code"),
    ("process.exit(", "can terminate the harness"),
]

INSTALL_SCRIPTS = ["preinstall", "postinstall", "prepare", "install"]

SUSPICIOUS_DEPS = ["node-gyp", "prebuild-install", "node-pre-gyp", "install"]

def scan_package_json(plugin):
    issues = []
    pkg = plugin / "package.json"
    if not pkg.exists():
        issues.append(("RED", f"package.json not found in {plugin}"))
        return issues, None
    try:
        data = json.loads(pkg.read_text(encoding="utf-8-sig"))
    except Exception as e:
        issues.append(("RED", f"package.json is invalid JSON: {e}"))
        return issues, None
    scripts = data.get("scripts", {})
    for s in INSTALL_SCRIPTS:
        if s in scripts:
            issues.append(("RED", f"package.json has {s} script: {scripts[s]}"))
    if "dsh" not in data:
        issues.append(("YELLOW", "package.json has no dsh.plugin field"))
    elif "plugin" not in data.get("dsh", {}):
        issues.append(("YELLOW", "package.json has dsh but no dsh.plugin entry"))
    if "repository" not in data:
        issues.append(("YELLOW", "package.json has no repository field"))
    if "license" not in data:
        issues.append(("YELLOW", "package.json has no license field"))
    deps = list(data.get("dependencies", {}).keys())
    for d in deps:
        if any(s in d for s in SUSPICIOUS_DEPS):
            issues.append(("YELLOW", f"suspicious dependency: {d}"))
    return issues, data


def check_obfuscation(plugin):
    """Detects minified/compiled files where static analysis is blind."""
    issues = []
    for ext in ["*.js", "*.ts"]:
        for f in plugin.rglob(ext):
            if "node_modules" in f.parts or "dist" in f.parts:
                continue
            try:
                text = f.read_text(errors="ignore")
                lines = text.splitlines()
                if not lines:
                    continue
                
                # Heuristic: Check if the file has very long lines (minified)
                long_lines = sum(1 for line in lines if len(line) > 500)
                avg_line_len = sum(len(line) for line in lines) / len(lines)
                
                if long_lines > 0 or (avg_line_len > 200 and len(lines) > 5):
                    issues.append(("UNCLEAR", f"{f.name} appears minified/compiled. Static analysis cannot read it safely."))
            except Exception:
                pass
    return issues

def scan_source(plugin):

    issues = []
    for ext in ["*.ts", "*.js", "*.tsx", "*.jsx"]:
        for f in plugin.rglob(ext):
            if "node_modules" in f.parts:
                continue
            try:
                text = f.read_text(errors="ignore")
            except Exception:
                continue
            for line_no, line in enumerate(text.splitlines(), 1):
                for pattern, why in RISKY_IMPORTS:
                    if pattern in line:
                        issues.append(("YELLOW", f"{f.name}:{line_no} uses {pattern} ({why})"))
    return issues

def render(plugin, issues):
    red = [i for i in issues if i[0] == "RED"]
    yellow = [i for i in issues if i[0] == "YELLOW"]
    print(f"Plugin: {plugin}")
    print(f"Red flags: {len(red)}  Warnings: {len(yellow)}")
    print()
    for level, msg in issues:
        print(f"  [{level}] {msg}")
    print()
    if red:
        print("Verdict: DO NOT INSTALL until red flags are resolved.")
        return 2
    if yellow:
        print("Verdict: review warnings before installing.")
        return 1
    print("Verdict: clean. No red flags or warnings found.")
    return 0

def main():
    ap = argparse.ArgumentParser(description="Scan a DSH plugin for security issues.")
    ap.add_argument("--plugin", required=True, help="Path to plugin directory")
    ap.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = ap.parse_args()
    plugin = Path(args.plugin).resolve()
    if not plugin.exists():
        print(f"ERROR: plugin not found: {plugin}")
        return 2
    issues, _ = scan_package_json(plugin)
    issues += scan_source(plugin)
    issues += check_obfuscation(plugin)
    if args.json:
        print(json.dumps({"plugin": str(plugin), "issues": issues}, indent=2))
        if any(i[0] == "RED" for i in issues): return 2
        if any(i[0] == "YELLOW" for i in issues): return 1
        if any(i[0] == "UNCLEAR" for i in issues): return 3
        return 0
    return render(plugin, issues)

if __name__ == "__main__":
    sys.exit(main())
