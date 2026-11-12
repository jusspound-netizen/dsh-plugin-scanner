---
name: dsh-plugin-scanner
description: Scans a DeepSeek Harness plugin for security red flags before you install it: install scripts, risky imports, missing metadata, and suspicious dependencies. Local-first, stdlib-only.
external_urls:
  - https://github.com/jusspound-netizen/dsh-plugin-scanner
  - https://deepseek-harness.github.io/deepseek-harness/
permissions:
  network: false
  env_vars: false
  filesystem: read
---

# DSH Plugin Scanner

## Description

Scans a DeepSeek Harness plugin directory before installation and reports
security red flags: install scripts, risky imports, missing metadata, and
suspicious dependencies. Local-first, stdlib-only, no network calls.

## When to use this skill

- The user wants to install a DSH plugin and wants to check it first
- The user is reviewing a plugin repository before adding it to their harness
- The user asks "is this DSH plugin safe to install?"

## Usage

```bash
python scripts/run.py --plugin /path/to/plugin
```

Add `--json` for machine-readable output.

## What it checks

- **Install scripts**: `preinstall`, `postinstall`, `prepare` in package.json
- **Risky imports**: `child_process`, `eval`, `Function()`, unrestricted fs in source
- **Missing metadata**: no `dsh.plugin`, no repository, no license
- **Suspicious dependencies**: packages known for install-script behavior
- **Topic signal**: whether a public repo declares the `dsh-plugin` topic

## Output

A green/yellow/red report with file paths and line numbers. Exit code 0 = clean,
1 = warnings, 2 = red flags.

## What it does not do

- No network calls (except optional topic check, disabled by default)
- No env vars to configure
- No dependencies - stdlib-only
- Does not execute the plugin - static analysis only
