# DSH Plugin Scanner
[![dsh.so risk](https://cdn.dsh.so/badge/dsh-plugin-scanner.svg)](https://www.dsh.so/artifact/dsh-plugin-scanner/?ref=badge)

**Scan a DeepSeek Harness plugin for security red flags before installing it.**

DSH plugins run with full filesystem and network access. Before you install one from the community registry, scan it.

## What it checks

| Check | Level | Why |
|---|---|---|
| Install scripts in `package.json` | RED | Classic supply-chain vector |
| `child_process` in source | YELLOW | Spawns processes |
| `eval(` or `new Function(` | YELLOW | Arbitrary code execution |
| Missing `dsh.plugin` field | YELLOW | Not a valid DSH plugin |
| Missing repository or license | YELLOW | No provenance |
| Suspicious dependency names | YELLOW | Known install-script behavior |

## Usage

```bash
python scripts/run.py --plugin /path/to/plugin
```

JSON output:

```bash
python scripts/run.py --plugin /path/to/plugin --json
```

## Verdicts

- Exit 0: clean
- Exit 1: warnings only - review before installing
- Exit 2: red flags - do not install

## What it does not do

- No network calls
- No execution of the plugin - static analysis only
- No dependencies beyond Python 3.9+ and stdlib

## License

MIT
