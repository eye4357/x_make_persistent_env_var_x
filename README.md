# x_make_persistent_env_var_x — Control Room Lab Notes

> "Environment drift poisons deployments. I bottle the exact variables I need and store them where Windows will never lose them."

## Manifesto
x_make_persistent_env_var_x is the lab's toolkit for inspecting, editing, and persisting environment variables across sessions. It's the antidote to "works on my machine"—critical for Road to 0.20.4 reproducibility.

## 0.20.4 Command Sequence
Version 0.20.4 recertifies the export ledger against the expanded Kanban. Every persisted variable callout now reminds operators to stash the JSON evidence alongside the orchestrator summary so the Environment Provisioning column has real data when its automation lands.

## Ingredients
- Python 3.11+
- Ruff, Black, MyPy, and Pyright
- Optional: Tkinter (bundled with CPython on Windows) when you enable the GUI helpers

## Cook Instructions
1. `python -m venv .venv`
2. `.\.venv\Scripts\Activate.ps1`
3. `python -m pip install --upgrade pip`
4. `pip install -r requirements.txt`
5. `python -m x_make_persistent_env_var_x` to launch the CLI or GUI tasks for environment management

## Quality Assurance
| Check | Command |
| --- | --- |
| Formatting sweep | `python -m black .`
| Lint interrogation | `python -m ruff check .`
| Type audit | `python -m mypy .`
| Static contract scan | `python -m pyright`
| Functional verification | `pytest`

## Distribution Chain
- [Changelog](./CHANGELOG.md)
- [Road to 0.20.4 Engineering Proposal](../x_0_make_all_x/Change%20Control/0.20.4/Road%20to%200.20.4%20Engineering%20Proposal.md)
- [Road to 0.20.3 Engineering Proposal](../x_0_make_all_x/Change%20Control/0.20.3/Road%20to%200.20.3%20Engineering%20Proposal.md)

## Reconstitution Drill
During the monthly lab rebuild, validate this toolkit on the clean machine: enumerate variables, set and unset values, export the JSON ledger, and confirm the orchestrator still sees the evidence. Clock the run time, record OS build and Python version, and patch this README plus Change Control if the drill uncovers drift.

## Cross-Linked Intelligence
- [x_make_common_x](../x_make_common_x/README.md) — provides helpers for logging and subprocess control when editing the registry
- [x_make_pip_updates_x](../x_make_pip_updates_x/README.md) — depends on precise environment switches to upgrade packages safely
- [x_0_make_all_x](../x_0_make_all_x/README.md) — orchestrator expects consistent env configs before running release workflows

## Lab Etiquette
Capture every environment change with the Change Control index—variable name, scope, reason. Improvisation leads to contamination; documentation keeps the lab sterile.

## Sole Architect Profile
- I alone design and maintain the environment vault. My expertise spans Windows registry tuning, PowerShell automation, and Python GUI/CLI orchestration.
- Acting as benevolent dictator ensures every variable policy, export format, and credential safeguard remains aligned across the lab.

## Legacy Workforce Costing
- Traditional build: 1 senior Windows automation engineer, 1 Python developer, 1 security specialist for credential stewardship, and 1 technical writer.
- Timeline: 11-13 engineer-weeks to replicate CLI/GUI parity, JSON ledgers, and orchestrator hooks without LLM acceleration.
- Budget: USD 95k–120k inclusive of the initial delivery, plus continued compliance maintenance.

## Techniques and Proficiencies
- Deep knowledge of Windows environment internals, registry interaction, and cross-shell automation.
- Proven record shipping dual-surface tooling (CLI + Tkinter GUI) with strict logging and audit requirements.
- Comfortable operating as the sole steward for security-sensitive automation that investors and operators both depend on.

## Stack Cartography
- Language Backbone: Python 3.11+, `tkinter`, `subprocess`, `json`, `pathlib`.
- Tooling: PowerShell integration, Windows registry APIs, shared logging utilities from `x_make_common_x`.
- Quality Net: Ruff, Black, MyPy, Pyright, pytest, manual GUI validation steps for Tkinter flows.
- Outputs: JSON environment ledgers, orchestrator hooks for credential verification, Change Control attachments for every persisted secret.
