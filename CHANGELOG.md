# Changelog

All notable changes to binrev are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-10-18

### Fixed

- A corrupt `~/.binrev/config.json` no longer crashes every command with a
  raw traceback. The unreadable file is preserved as a
  `config.json.corrupt-<nanoseconds>` sibling (a broken API key may still be
  recoverable) and configuration restarts from defaults, so
  `binrev config set` can repair in place instead of dead-ending. Unknown or
  non-string keys inside an otherwise valid file are dropped to the existing
  clean "no LLM key configured" path.
- `binrev inspect --func` rejects a non-address value with a one-line usage
  error (exit 2), matching the `--isa` flag's behavior, instead of leaking a
  raw ValueError traceback.
- A truncated or corrupt ELF whose section-header table points past end of
  file falls back to raw-blob disassembly instead of raising `struct.error`
  from the header unpacks.

### Added

- CLI test coverage for `binrev config set` / `binrev config show`
  (including the corrupt-config repair contract) and `binrev run -q` agent
  sessions, driven in-process via `CliRunner`.

### Changed

- `Config.load` / `Config.save` resolve the config path at call time, so
  embedders and tests can redirect `~/.binrev/config.json` hermetically.

## [0.2.0] - 2026-09-14

### Fixed

- `binrev inspect` now honors a configured Ghidra backend
  (`binrev config set --ghidra <path>`), matching `binrev <binary>` behavior;
  capstone remains the automatic fallback when Ghidra is not configured or
  reachable. Previously inspect always used capstone, silently downgrading
  decompilation quality.
- String extraction for ELF inputs now reports addresses in the `.text`
  virtual-address space shared with functions and cross-references. Previously
  every string address was offset by the ELF header size, so
  `search_strings` hits could not be cross-referenced against `decompile` /
  `xrefs` output.

### Added

- This `CHANGELOG.md` with per-release sections and compare/tag links.
- Version-consistency test (`tests/test_version.py`): the `VERSION` file,
  `pyproject.toml` `[project]` version, `binrev.__version__`, the
  `binrev --version` output and `web/site.json` `meta.content_version` must
  all agree.
- CLI tests (`tests/test_cli.py`) covering inspect backend routing (Ghidra
  preferred, capstone fallback), driven in-process via click's `CliRunner`.
- Regression test for the ELF string-address fix.

### Changed

- `binrev --version` now prints `binrev.__version__` directly instead of
  auto-detecting from installed package metadata, which silently diverged
  from the source tree whenever the package was not reinstalled.

### Removed

- Dead no-op `pytest_collection_modifyitems` hook in `tests/conftest.py`;
  capstone absence is already guarded by module-level `pytest.importorskip`.

## [0.1.0] - 2026-08-24

### Added

- `BinState` primitive: the decompiled function graph, cross-references, ISA
  state, string table and cross-step notes held as first-class, queryable
  objects rather than a CLI stdout log.
- Capstone backend (no external tools) plus a Ghidra headless bridge that
  dumps real decompiled C, rich xrefs and strings to JSON.
- Binary action-space tools: `decompile`, `xrefs`, `list_funcs`,
  `search_strings`, `set_note`, `done`.
- Agent loop over any OpenAI-compatible endpoint (Qwen / DeepSeek) with
  mocked-client tests.
- `binrev inspect`, `binrev config` and the default `binrev <binary>` agent
  session CLI.

[Unreleased]: https://github.com/SuperMarioYL/binrev/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/SuperMarioYL/binrev/releases/tag/v0.3.0
[0.2.0]: https://github.com/SuperMarioYL/binrev/releases/tag/v0.2.0
[0.1.0]: https://github.com/SuperMarioYL/binrev/releases/tag/v0.1.0
