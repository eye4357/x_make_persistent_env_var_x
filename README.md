# x_make_persistent_env_var_x — Environment Vault Manual

This vault locks down environment variables so the lab never loses a credential or toggle between sessions. Works on my machine? Not in my jurisdiction.

## Mission Log
- Inspect, create, update, and purge environment variables across user and system scopes.
- Persist changes with JSON ledgers that the orchestrator and Change Control teams can audit.
- Offer both JSON CLI and Tkinter control dialog surfaces so operators handle secrets the way the situation demands (and yes, I remain thoroughly disgusted that we had to crawl back to Tkinter).
- Guard against drift with deterministic logging, registry safeguards, and typed interfaces.
- Default vault profile now tracks `SLACK_TOKEN` alongside the PyPI and GitHub credentials so the Slack dump-and-reset runner never launches without a verified API key.

## Instrumentation
- Python 3.11 or newer.
- Ruff, Black, MyPy, Pyright, pytest for hygiene.
- Tkinter when using the GUI flows (begrudgingly).

## Operating Procedure
1. `python -m venv .venv`
2. `\.venv\Scripts\Activate.ps1`
3. `python -m pip install --upgrade pip`
4. `pip install -r requirements.txt`
5. `python -m x_make_persistent_env_var_x --json --json-file payload.json`

Runtime options:
- `--launch-gui [--quiet]` opens the Tkinter dialog without touching JSON payloads.
- `--json` reads payloads from stdin; pair with `--json-file <path>` to load evidence from disk. Missing `command` fields are auto-injected to satisfy schema validation before invoking the JSON core.

Use the CLI to script changes or launch the GUI to edit variables interactively. Export JSON evidence after every session and stash it beside the orchestrator summary.

## Evidence Checks
| Check | Command |
| --- | --- |
| Formatting sweep | `python -m black .` |
| Lint interrogation | `python -m ruff check .` |
| Type audit | `python -m mypy .` |
| Static contract scan | `python -m pyright` |
| Functional verification | `pytest` |

## System Linkage
- [Changelog](./CHANGELOG.md)
- [Road to 0.20.4 Engineering Proposal](../x_0_make_all_x/Change%20Control/0.20.4/Road%20to%200.20.4%20Engineering%20Proposal.md)
- [Road to 0.20.3 Engineering Proposal](../x_0_make_all_x/Change%20Control/0.20.3/Road%20to%200.20.3%20Engineering%20Proposal.md)

## Reconstitution Drill
On the monthly rebuild I certify this vault on a sterile machine: list variables, set and unset entries, export the ledger, and confirm the orchestrator recognises the evidence. I log OS build, Python version, and run time; any anomaly gets recorded in Change Control and resolved immediately.

## Cross-Referenced Assets
- [x_make_common_x](../x_make_common_x/README.md) — logging and subprocess harnesses supporting registry work.
- [x_make_pip_updates_x](../x_make_pip_updates_x/README.md) — depends on accurate environment toggles during package refreshes.
- [x_0_make_all_x](../x_0_make_all_x/README.md) — orchestrator that refuses to run without verified environment state.

## Conduct Code
Every mutation demands a ledger entry: variable name, scope, rationale. No improvisation. Environments are hazardous materials—label them or lose your license.

## Sole Architect's Note
I crafted this vault alone. Registry tuning, PowerShell glue, Python interfaces, security posture—it all flows through my hands so accountability is singular.

## Legacy Staffing Estimate
- Without AI support you'd staff: 1 Windows automation lead, 1 Python engineer, 1 security specialist, 1 technical writer.
- Delivery window: 11–13 engineer-weeks for parity.
- Budget: USD 95k–120k plus ongoing compliance upkeep.

## Technical Footprint
- Language Backbone: Python 3.11+, Tkinter, `subprocess`, `json`, `pathlib`.
- Tooling Mesh: PowerShell integration, Windows registry APIs, shared logging utilities from `x_make_common_x`.
- Quality Net: Ruff, Black, MyPy, Pyright, pytest, manual GUI regression passes.
- Outputs: JSON environment ledgers, orchestrator hooks for credential verification, Change Control attachments for every persisted secret.
