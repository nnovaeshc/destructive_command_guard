# Changelog

All notable changes to **dcg** (Destructive Command Guard) are documented here.

Versions marked with **[Release]** have published GitHub Releases with pre-built binaries.
Versions marked with **[Tag]** are git tags only (no GitHub Release / no binaries).

Repository: <https://github.com/Dicklesworthstone/destructive_command_guard>

---

## [Unreleased] (after v0.4.3)

Post-v0.4.3 work on `main` that has not yet been tagged.

### Added
- **Strict git pack**: expanded dangerous-command detection for additional destructive git patterns ([6d950f3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6d950f3), [031e84a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/031e84a))
- Hook system expansion with additional interception patterns and strict git pack hardening ([031e84a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/031e84a))

### Fixed
- Disambiguate Claude Code from Gemini in `detect_protocol()` — closes [#77](https://github.com/Dicklesworthstone/destructive_command_guard/issues/77) ([8815b54](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8815b54))
- Podman `rm`/`rmi` combined-flag bypass (e.g. `podman rm -af`) ([d9d23b5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d9d23b5))
- Removed safe patterns in strict git pack that created a compound-command bypass ([d6ce202](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d6ce202))

### Maintenance
- Clippy and rustfmt cleanup across CLI, hook, and pack modules ([c26f22d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c26f22d))

---

## [v0.4.3](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.3) — 2026-03-14 [Tag]

A large release adding new agent detections, new protection packs, self-healing settings monitoring, and a session-scoped interactive allowlist system.

### Added
- **Real-time `settings.json` overwrite detection and self-healing** — DCG now watches for external processes silently removing its hook registration and restores it automatically ([708d202](https://github.com/Dicklesworthstone/destructive_command_guard/commit/708d202))
- **Supabase database protection pack** — full CLI coverage including `db push`, `db reset`, `migration repair`, and others; `--dry-run` whitelisted as safe ([003a429](https://github.com/Dicklesworthstone/destructive_command_guard/commit/003a429), [3e3ed19](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3e3ed19))
- **Augment Code** and **GitHub Copilot CLI** agent detection in the installer ([5917125](https://github.com/Dicklesworthstone/destructive_command_guard/commit/5917125), [84bb1a0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/84bb1a0))
- **Gemini CLI hook protocol support** with improved detection for minimal payloads ([ac6e6ad](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ac6e6ad), [0629a5d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0629a5d))
- `dcg setup` command with shell startup hook-removal detection — closes [#56](https://github.com/Dicklesworthstone/destructive_command_guard/issues/56) ([45db4b7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/45db4b7))
- Shell startup check to detect silently removed DCG hook ([eb06112](https://github.com/Dicklesworthstone/destructive_command_guard/commit/eb06112))
- **Session-scoped allowlist** binding with `session_id` and testable interactive checks ([3533533](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3533533))
- **Interactive allowlist audit system** with collision-resistant backup naming and SQLite schema v6 migration ([c948240](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c948240))
- **TOON output format** support, hardened history storage, and improved test infrastructure ([69f60c8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/69f60c8))
- Project-level hook install and `--no-configure` update flag ([1397a8b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1397a8b))

### Fixed
- Emit JSON `"ask"` decision for warn-severity matches in hook mode — closes [#70](https://github.com/Dicklesworthstone/destructive_command_guard/issues/70) ([91f09db](https://github.com/Dicklesworthstone/destructive_command_guard/commit/91f09db))
- Display `custom_paths` packs in `dcg packs` listing — closes [#57](https://github.com/Dicklesworthstone/destructive_command_guard/issues/57) ([045cfc0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/045cfc0))
- Redis `maxmemory` regex no longer matches `maxmemory-policy` ([1c3c94a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1c3c94a))
- Missing Redis CONFIG SET rules for persistence and rewrite ([4f0a21a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4f0a21a))
- Prevent duplicate shell check injection on re-runs ([8b70cab](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8b70cab))
- ARM64 compilation fix for `uring-fs` (`*const i8` to `*const libc::c_char`) ([7b9bf96](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7b9bf96))
- Installer and CI aligned on `gnu` targets to match existing release binaries ([5e81603](https://github.com/Dicklesworthstone/destructive_command_guard/commit/5e81603))

---

## [v0.4.2](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.2) — 2026-02-23 [Tag]

Stabilization release that resolved 91+ pre-existing test failures.

### Fixed
- Resolved 91+ pre-existing test failures across the entire test suite ([faf7e0e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/faf7e0e))

### Changed
- License updated to MIT with OpenAI/Anthropic Rider ([c1200c7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c1200c7))

---

## [v0.4.1](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.1) — 2026-02-22 [Tag]

First `musl`-based statically linked Linux binary release, plus dependency modernization and publish to crates.io.

### Added
- `dcg pack-info` shows patterns by default; new `--json` and `--no-patterns` flags ([48e303e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/48e303e))
- Comprehensive unit tests for output modules ([b97f50a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b97f50a))

### Fixed
- Switch Linux x86_64 distribution to **musl** for portable, statically linked binaries ([e066687](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e066687))
- Binary content detection for Unicode; FTS rowid sync; regex engine fallback ([acc2f2c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/acc2f2c))
- macOS `CursorUIViewService` filtered from Cursor IDE detection ([970f62f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/970f62f))
- Migrate all branch references from `master` to `main`; fix quote-stripping in normalizer ([920d785](https://github.com/Dicklesworthstone/destructive_command_guard/commit/920d785))
- History writer migrated to thread-local DB; updated `rand` API ([4d1b3c7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4d1b3c7))
- Static linking verification for musl builds in CI ([6cdbfc1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6cdbfc1), [0a6850c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0a6850c))
- crates.io keyword limit compliance (max 5) ([0a46ef7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0a46ef7))

### Changed
- `fsqlite` dependencies switched from local paths to crates.io v0.1.0 ([9dc695b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9dc695b))
- `rich_rust` dependency updated from pre-release/git ref to crates.io v0.2.0 ([83d4abf](https://github.com/Dicklesworthstone/destructive_command_guard/commit/83d4abf))

---

## [v0.4.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.0) — 2026-02-10 [Release]

Major release adding GitHub Copilot CLI hook support and installer improvements.

### Added
- **GitHub Copilot CLI hook support** and installer integration ([7385931](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7385931))
- `repository_dispatch` triggers for homebrew-tap and scoop-bucket automated packaging ([b5482b4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b5482b4))
- Timeout protection and user feedback for agent scanning during install ([37c9123](https://github.com/Dicklesworthstone/destructive_command_guard/commit/37c9123))

### Fixed
- Build ordered pack list and keyword index after external packs are loaded ([314e591](https://github.com/Dicklesworthstone/destructive_command_guard/commit/314e591))
- All available subcommands now appear in `dcg --help` output ([23f3301](https://github.com/Dicklesworthstone/destructive_command_guard/commit/23f3301))

### Changed
- Evaluator refactored to consolidate external pack checking into core evaluation ([fea7d6a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fea7d6a))

---

## [v0.3.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.3.0) — 2026-02-02 [Release]

Large feature release introducing robot mode, rich terminal output, golden testing, and the `rich_rust` visual layer.

### Added
- **Robot mode** with structured JSON output and machine-readable exit codes (`dcg test --robot`) ([e576883](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e576883))
- Robot mode API documentation ([34506dd](https://github.com/Dicklesworthstone/destructive_command_guard/commit/34506dd))
- **Golden JSON tests** framework for deterministic output validation ([0b0ca97](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0b0ca97))
- `rich_rust` integration — DcgConsole wrapper, rich theme bridge, colored metrics tables, tree visualizations ([ae39947](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ae39947), [c881a75](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c881a75), [328107a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/328107a))
- Enhanced `doctor`, `packs`, `explain`, and `stats` commands with rich terminal output ([02b5086](https://github.com/Dicklesworthstone/destructive_command_guard/commit/02b5086), [ea39323](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ea39323), [2b8780d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2b8780d))
- Tree output visualization for `dcg explain` ([e538399](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e538399))
- Schema versioning and metadata in `TestOutput` JSON ([b7a6d6d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b7a6d6d))
- Configurable verification methods for interactive prompts ([23618ac](https://github.com/Dicklesworthstone/destructive_command_guard/commit/23618ac))
- Detailed explanations added to all destructive patterns ([e775c2b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e775c2b))
- Expanded allowlist rules for safe command patterns ([db272dc](https://github.com/Dicklesworthstone/destructive_command_guard/commit/db272dc))
- External pack loading from `custom_paths` wired into the evaluator ([bea17d0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bea17d0), [a2cabc5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a2cabc5))
- Expanded `system.disk` pack with mdadm, btrfs, LVM, and dmsetup patterns ([56df75a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/56df75a))
- Agent-specific profiles and trust levels (Epic 9) ([77571ba](https://github.com/Dicklesworthstone/destructive_command_guard/commit/77571ba))
- CLI output control flags for legacy and color modes ([fdda44f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fdda44f))
- OpenCode added to supported tools list ([4473419](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4473419))

### Fixed
- macOS config path: check XDG-style `~/.config/dcg` first ([ceffdf5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ceffdf5))
- External packs marked as always-enabled in listing ([7821773](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7821773))
- Iteration limit added to prevent unbounded wrapper stripping in normalizer ([d342171](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d342171))
- CI/TERM=dumb detection for plain text fallback output ([47b4ddd](https://github.com/Dicklesworthstone/destructive_command_guard/commit/47b4ddd))

---

## [v0.2.15](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.15) — 2026-01-20 [Release]

CI fix release.

### Fixed
- Run only lib tests in dist workflow to avoid missing binary errors ([6489d2b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6489d2b))

---

## [v0.2.14](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.14) — 2026-01-20 [Tag]

Version bump and formatting for release pipeline.

### Maintenance
- Bump version to 0.2.14 and apply `cargo fmt` ([6d67502](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6d67502))

---

## [v0.2.13](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.13) — 2026-01-20 [Tag]

Massive feature batch covering the MCP server, CI scan extractors, self-update mechanism, SARIF output, rich TUI, and dozens of new security packs.

### Added
- **MCP server mode** (`dcg mcp`) for direct agent integration via the Model Context Protocol ([b372d99](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b372d99))
- **SARIF 2.1.0 output format** for security tool / CI integration ([4a4c09e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4a4c09e), [17f2040](https://github.com/Dicklesworthstone/destructive_command_guard/commit/17f2040))
- **Rich terminal rendering** — denial boxes, progress bars, tables, and TUI denial integration ([a0aaf42](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a0aaf42), [f9986e0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f9986e0))
- **Native Rust self-update mechanism** with version rollback and background notification ([f8a8a15](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f8a8a15), [d1f886d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d1f886d))
- **Custom pack system** with external YAML loading (`custom_paths` in config) ([0e4bc64](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0e4bc64), [f87aade](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f87aade))
- **Scan extractors**: CircleCI, Azure Pipelines, Dockerfile, docker-compose ([1a3b232](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1a3b232), [80d4cda](https://github.com/Dicklesworthstone/destructive_command_guard/commit/80d4cda), [302e35f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/302e35f))
- **Sigstore cosign signing** added to release workflow ([45c8109](https://github.com/Dicklesworthstone/destructive_command_guard/commit/45c8109))
- Installer: sigstore verification, Cursor detection, preflight checks, version-check idempotency ([2a597b6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2a597b6), [1ab0b5b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1ab0b5b))
- Installer: checksum verification with `--no-verify` flag ([616db4a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/616db4a))
- Installer: `uninstall.sh` script with agent hook removal ([c3d3eff](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c3d3eff))
- Installer: Aider auto-configuration, Continue detection, Codex CLI detection ([0a06a82](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0a06a82), [8d07940](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8d07940), [067b28a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/067b28a))
- **MySQL pack** with comprehensive destructive patterns ([81b0ca8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/81b0ca8))
- Git branch detection module ([6bb91f9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6bb91f9))
- `DetailedEvaluationResult` and `evaluate_detailed()` API ([bb93259](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bb93259))
- Config parser for new allowlist schema ([876beff](https://github.com/Dicklesworthstone/destructive_command_guard/commit/876beff))
- Suggestions added for Docker, Kubernetes, MySQL, and system permissions packs ([26dcc3b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/26dcc3b), [1b16ef0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1b16ef0), [5f76ba0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/5f76ba0), [876beff](https://github.com/Dicklesworthstone/destructive_command_guard/commit/876beff))
- Verbosity controls, shell completions, and `DCG_FORMAT` env var ([f545d4d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f545d4d))
- Hook output enriched with `ruleId`, `severity`, and `remediation` fields ([b439cd4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b439cd4))
- Standardized error code system (DCG-XXXX) ([4f87561](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4f87561))
- JSON Schema (Draft 2020-12) for all DCG output formats ([8c7601c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8c7601c))
- `--format json` support for `test` and `packs` commands ([f9db962](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f9db962))
- Comprehensive severity levels and extended explanations across all packs ([86b6b9a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/86b6b9a))

### Fixed
- Docker-compose extractor quote handling for embedded commands ([90c01a0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/90c01a0))
- UTF-8 safe string handling in update and denial modules ([c62ec3e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c62ec3e))
- CI blockers resolved for release builds ([999b9b1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/999b9b1))

---

## [v0.2.12](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.12) — 2026-01-15 [Tag]

Rename of the internal `telemetry` module to `history`.

### Changed
- Complete `telemetry` to `history` module rename across the codebase ([ddfc15d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ddfc15d))

---

## [v0.2.11](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.11) — 2026-01-15 [Tag]

Introduces the full command history system and auto-configuration of agent hooks.

### Added
- **Command history system** with stats, export, and per-pack analysis (`dcg history stats`, `dcg history export`) ([59a33b1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/59a33b1))
- Installer auto-configures Claude Code and Gemini CLI hooks with detailed feedback ([512c2d3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/512c2d3))
- Aho-Corasick quick-reject in `sanitize_for_pattern_matching` for performance ([6c8afc6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6c8afc6))
- Comprehensive history module integration tests and security regression tests ([c7802cc](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c7802cc), [f4726e2](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f4726e2))

---

## [v0.2.10](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.10) — 2026-01-15 [Release]

Security hardening, performance improvements, and the telemetry pruning command.

### Added
- **Telemetry pruning** command ([06c6ea7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/06c6ea7))
- ACFS checksum update notification workflow ([46a6c5e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/46a6c5e))

### Fixed
- Tier 1 bypass for inline scripts with attached quotes (e.g. `bash -c"..."`) ([2890891](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2890891))
- `xargs` regex robustness, simulated limits, and OOM protection ([77fa5fb](https://github.com/Dicklesworthstone/destructive_command_guard/commit/77fa5fb))
- Inline interpreter detection improved to avoid false positives on echoed commands ([3b426b0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3b426b0))
- Quoted secrets with spaces now handled in redaction ([a04f570](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a04f570))
- Potential stack overflow in recursive heredoc scanning limited to depth 50 ([a8f24b0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a8f24b0))
- `DCG_TELEMETRY_*` env vars renamed to `DCG_HISTORY_*` ([d44bde6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d44bde6))

---

## [v0.2.9](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.9) — 2026-01-14 [Release]

Codebase-wide rename from `telemetry` to `history` and Redis secret redaction.

### Changed
- Complete `telemetry` to `history` rename throughout codebase ([d0b2976](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d0b2976))

### Fixed
- Redis `user:password` URL pattern added to secret redaction ([0d61117](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0d61117))

---

## [v0.2.8](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.8) — 2026-01-14 [Tag]

Introduces the telemetry/history subsystem with persistent SQLite storage, CLI subcommands, and secret redaction.

### Added
- **Telemetry CLI** subcommands for querying persistent command history ([fc2a7a8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fc2a7a8), [2e4ea76](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2e4ea76))
- **Secret redaction patterns** for telemetry storage ([dbe7159](https://github.com/Dicklesworthstone/destructive_command_guard/commit/dbe7159))
- Comprehensive E2E test framework for telemetry ([13d1701](https://github.com/Dicklesworthstone/destructive_command_guard/commit/13d1701))
- Telemetry database migrations and config options ([15e3587](https://github.com/Dicklesworthstone/destructive_command_guard/commit/15e3587), [bb95341](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bb95341))
- Claude Code `SKILL.md` for automatic capability discovery ([6f44dc7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6f44dc7))
- Installer auto-configures Claude Code and Gemini CLI idempotently ([3b8fc5f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3b8fc5f))

### Fixed
- TMPDIR shell default value syntax in safe path detection ([4a970b8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4a970b8))
- `is_expired` made fail-closed on invalid timestamps ([84e607c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/84e607c))
- CI failures in E2E, scan-regression, and coverage jobs ([f7a4d53](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f7a4d53), [dc82f6a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/dc82f6a))

### Security
- Numerous normalizer and context hardening fixes: sanitize `git grep`/`ag`/`ack` search patterns, harden allowlist exception parsing, avoid panics in production paths, apply scan globs after directory expansion, honor project pack overrides ([cf0565a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/cf0565a), [299df4b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/299df4b), [49fda98](https://github.com/Dicklesworthstone/destructive_command_guard/commit/49fda98), [3e678b5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3e678b5), [bcc9a20](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bcc9a20))

---

## [v0.2.7](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.7) — 2026-01-12 [Release]

Memory leak fix and version alignment.

### Fixed
- Full pipeline memory test constrained to core packs to prevent leaks ([d8b1376](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d8b1376))

---

## [v0.2.6](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.6) — 2026-01-12 [Release]

CI fix for macOS Intel builds.

### Fixed
- macOS Intel builds moved to `macos-15-intel` runner (deprecation of `macos-13`) ([46c20d7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/46c20d7))

---

## [v0.2.5](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.5) — 2026-01-12 [Release]

Memory test stabilization.

### Fixed
- Warm up pipeline before leak check to avoid false positives ([02c0169](https://github.com/Dicklesworthstone/destructive_command_guard/commit/02c0169))

---

## [v0.2.4](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.4) — 2026-01-12 [Release]

Lockfile pin for CI stability.

### Fixed
- Pin `ciborium` to 0.2.2 in lockfile ([9f454c6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9f454c6))

---

## [v0.2.3](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.3) — 2026-01-12 [Release]

Default config fix.

### Fixed
- Enable common packs on default config load ([23fd149](https://github.com/Dicklesworthstone/destructive_command_guard/commit/23fd149))

---

## [v0.2.2](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.2) — 2026-01-12 [Release]

Formatting fix.

### Fixed
- Align confidence tests with rustfmt ([534d1ef](https://github.com/Dicklesworthstone/destructive_command_guard/commit/534d1ef))

---

## [v0.2.1](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.1) — 2026-01-12 [Release]

Installer improvements with Gemini CLI support and binary size reduction.

### Added
- Gemini CLI support in installer with proper tool name and error handling ([3769dab](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3769dab))
- Auto-configure Claude Code/Codex and detect predecessor tools ([9929f7d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9929f7d))

### Fixed
- Installer portability improvements for BSD/macOS systems ([9f89544](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9f89544))
- Binary size reduced 69% by trimming tree-sitter parsers ([d11670e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d11670e))
- UTF-8 boundary panic prevented in confidence/operator detection ([44389a3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/44389a3))

---

## [v0.2.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.0) — 2026-01-09 [Tag]

Foundational release representing the first tagged version of DCG with a mature feature set. Built over 300+ commits in two days of intensive multi-agent development.

### Core Capabilities
- **Modular pack system** with 49+ security packs covering: core git/filesystem, databases (PostgreSQL, MySQL, Redis, MongoDB), Kubernetes, Docker/Podman, cloud providers (AWS, GCP, Azure), Terraform, CI/CD (GitHub Actions, Jenkins, CircleCI), CDN (CloudFront, Cloudflare, Fastly), DNS, backup tools (restic, rclone, Velero), load balancers, container registries, secrets management, monitoring, email services, API gateways, and more ([f04ae36](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f04ae36aaecc027b7666504cd5aa7e0c2d922dda))
- **Claude Code hook protocol** — native JSON-based intercept for commands before execution
- **Heredoc / inline script scanning** — detects destructive commands inside `bash -c`, `python -c`, heredoc blocks, and embedded scripts across Bash, Python, Ruby, Perl, Node, PHP, Go, and Lua
- **Smart context detection** — distinguishes data contexts (strings, comments, variables) from execution contexts; avoids false positives on `grep "rm -rf"` while still blocking `rm -rf /`
- **Aho-Corasick keyword prefilter** + per-pack `RegexSet` fast path for O(n) matching
- **Lazy regex compilation** with `LazyFancyRegex` — patterns compiled on first use only
- **Fail-open deadline enforcement** — configurable timeout budget prevents DCG from blocking workflows
- **Scan mode** for CI/CD — extract and evaluate commands from GitHub Actions, Dockerfiles, Makefiles, Terraform, shell scripts, docker-compose, and package.json
- **Explain mode** — `dcg explain "command"` shows matching rules, packs, and severity
- **Simulate mode** — `dcg simulate` with output formats and redaction/truncation
- **Allowlist system** — global, project-scoped, and heredoc-content allowlists with `allow-once` audit logging
- **Suggestions engine** — safer alternative recommendations for blocked commands
- **Confidence tiering** — warn-by-default patterns for ambiguous commands
- **E2E test framework** with comprehensive coverage of CLI flows, hook mode, scan mode, and security regressions
- **Fuzz testing** targets for heredoc scanning and scan extractors
- **Reusable GitHub Action** for `dcg scan` in CI pipelines ([2145f1d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2145f1d))
- **Corpus-based regression testing** with canonical command corpus and behavior invariants ([ac551c9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ac551c9))
- **Release automation** and self-updater foundation ([cb9f6b4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/cb9f6b4))

### Infrastructure
- Cross-platform CI: Linux (x86_64, aarch64), macOS (Intel, Apple Silicon), Windows
- Codecov integration for coverage tracking
- Dependabot configuration for automated dependency updates
- `install.sh` with `--easy-mode` flag, platform auto-detection, and predecessor tool migration

---

## Initial Development — 2026-01-07

The project began as `git_safety_guard`, a focused tool for blocking destructive git commands. It was renamed to **destructive_command_guard** (`dcg`) and expanded into a general-purpose destructive-command interceptor with the modular pack system.

- Initial commit ([1640612](https://github.com/Dicklesworthstone/destructive_command_guard/commit/16406128fc967a305b97f4cd8da1b537a4be7b6f))
- Rename to `destructive_command_guard` with modular pack system ([f04ae36](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f04ae36aaecc027b7666504cd5aa7e0c2d922dda))

---

## Release Matrix

| Version | Date | Type | Binaries |
|---------|------|------|----------|
| v0.4.3 | 2026-03-14 | Tag only | No |
| v0.4.2 | 2026-02-23 | Tag only | No |
| v0.4.1 | 2026-02-22 | Tag only | No |
| v0.4.0 | 2026-02-10 | **GitHub Release** | Yes |
| v0.3.0 | 2026-02-02 | **GitHub Release** | Yes |
| v0.2.15 | 2026-01-20 | **GitHub Release** | Yes |
| v0.2.14 | 2026-01-20 | Tag only | No |
| v0.2.13 | 2026-01-20 | Tag only | No |
| v0.2.12 | 2026-01-15 | Tag only | No |
| v0.2.11 | 2026-01-15 | Tag only | No |
| v0.2.10 | 2026-01-15 | **GitHub Release** | Yes |
| v0.2.9 | 2026-01-14 | **GitHub Release** | Yes |
| v0.2.8 | 2026-01-14 | Tag only | No |
| v0.2.7 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.6 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.5 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.4 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.3 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.2 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.1 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.0 | 2026-01-09 | Tag only | No |
