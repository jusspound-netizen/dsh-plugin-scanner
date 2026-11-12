# DSH Plugin Scanner - Setup

## Usage

```bash
python scripts/run.py --plugin /path/to/plugin
```

JSON output:

```bash
python scripts/run.py --plugin /path/to/plugin --json
```

## What it checks

| Check | Level | Why |
|---|---|---|
| install scripts in package.json | RED | classic supply-chain vector |
| `child_process` in source | YELLOW | spawns processes |
| `eval(` or `new Function(` | YELLOW | arbitrary code execution |
| missing `dsh.plugin` field | YELLOW | not a valid DSH plugin |
| missing repository/license | YELLOW | no provenance |
| suspicious dependency names | YELLOW | known install-script behavior |

## Verdicts

- Exit 0: clean
- Exit 1: warnings only - review before installing
- Exit 2: red flags - do not install

## What it does not do

- No network calls
- No execution of the plugin
- No env vars to configure
- Static analysis only - it reads files, it does not run them
