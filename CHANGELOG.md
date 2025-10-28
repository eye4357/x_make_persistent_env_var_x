# x_make_persistent_env_var_x — Production Ledger

I catalogue every substantive adjustment to this environment vault here. Entries obey [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and Semantic Versioning so compliance teams can tie configuration evidence to specific releases.

## [Unreleased]
### Changed
- Retired the legacy Tkinter interface so the package operates strictly as a JSON-in/JSON-out service.
- Added a PySide6-driven credential dialog (`x_cls_make_persistent_env_var_gui_x`) that shells the JSON workflow for orchestrator launches.
- Hardened the CLI dispatcher: new `--launch-gui` flag, explicit JSON exit codes, and automatic injection of the `command` field for schema compliance.
- Expanded test coverage with a CLI dispatch harness that mocks the PySide6 surface to keep GUI verification in CI.

## [0.20.4] - 2025-10-15
### Changed
- README aligned with the Road to 0.20.4 release, outlining how environment exports back the upcoming Kanban Environment Provisioning column.
- Reinforced documentation for parking JSON evidence alongside orchestrator summaries so the provisioning automation has data when it lands.

## [0.20.3] - 2025-10-14
### Changed
- Documentation refreshed for the Road to 0.20.3 release, noting the JSON metadata requirements for persistent environment exports.

## [0.20.2] - 2025-10-14
### Changed
- Hardened the README and control notes for the Road to 0.20.2 checkpoint, spelling out the tightened environment management protocol.

## [0.20.1] - 2025-10-13
### Changed
- Updated README guidance to reference the Road to 0.20.1 control-room ledger so environment tooling tracks the live milestone.

## [0.20.0-prep] - 2025-10-12
### Added
- Crafted a control-room aligned README and changelog to cement the repository's mission in the Road to 0.20.0 program.
- Linked environment tooling to the Change Control index and critical orchestration repos.

### Changed
- Reinforced expectations for declaring environment mutations—no stealth updates, no excuses.
