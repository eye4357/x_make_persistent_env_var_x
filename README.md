# x_make_persistent_env_var_x — Control Room Lab Notes

> "Environment drift poisons deployments. I bottle the exact variables I need and store them where Windows will never lose them."

## Manifesto
x_make_persistent_env_var_x is the lab's toolkit for inspecting, editing, and persisting environment variables across sessions. It's the antidote to "works on my machine"—critical for Road to 0.20.2 reproducibility.

## 0.20.2 Command Sequence
Version 0.20.2 freezes the environment story in place. These instructions match the Road to 0.20.2 playbook so every variable you pin stays aligned with the release chemistry. Deviate and you contaminate the batch.

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
- [Road to 0.20.2 Control Room Ledger](../x_0_make_all_x/Change%20Control/0.20.2/Road%20to%200.20.2%20Engineering%20Proposal.md)
- [Road to 0.20.2 Engineering Proposal](../x_0_make_all_x/Change%20Control/0.20.2/Road%20to%200.20.2%20Engineering%20Proposal.md)

## Cross-Linked Intelligence
- [x_make_common_x](../x_make_common_x/README.md) — provides helpers for logging and subprocess control when editing the registry
- [x_make_pip_updates_x](../x_make_pip_updates_x/README.md) — depends on precise environment switches to upgrade packages safely
- [x_0_make_all_x](../x_0_make_all_x/README.md) — orchestrator expects consistent env configs before running release workflows

## Lab Etiquette
Capture every environment change with the Change Control index—variable name, scope, reason. Improvisation leads to contamination; documentation keeps the lab sterile.
