<!-- Compact Copilot instructions for pml-to-selinux -->
# Quick AI coding guide — pml-to-selinux

This file gives focused, actionable guidance for an AI coding agent to be productive in this repository.

1) Big picture
- Purpose: a compiler that converts Casbin PML (model .conf + policy .csv) into SELinux policy files (.te, .fc).
- High-level pipeline: CLI (`cli/main.go`) → Parser (`compiler/parser.go`) → Analyzer (`compiler/analyzer.go`) → Mapping (`mapping/*`) → SELinux generators (`selinux/te_generator.go`, `selinux/fc_generator.go`) → Optimizer (`compiler/optimizer.go`).

2) Where to start (local navigation)
- Read `README.md` at project root for an overview and `compiler/README.md` for parser/analyzer details.
- Entry point for CLI: `cli/main.go` (uses Cobra). For unit tests look under `compiler/`, `mapping/`, `selinux/`.

3) Build & test commands (run in repository root)
- Build the CLI binary: `go build ./cli`.
- Run unit tests: `go test ./...` or target package: `go test ./compiler -v`.
- Run examples/demos: `go run tests/demo_parser.go examples/httpd/httpd_model.conf examples/httpd/httpd_policy.csv`.

4) Project-specific patterns & conventions
- Error handling: parsing errors often return `*compiler.ParseError` with file and line — preserve structured errors when changing parser code (see `compiler/README.md` examples).
- Path mapping: mapping logic is centralized in `mapping/type_mapping.go` and `mapping/context_mapping.go`; prefer changes here when modifying Path→Type inference.
- Generators emit SELinux artifacts in `selinux/` and expect normalized model structures from `models/`.
- CLI uses Cobra flags (see `cli/main.go`) — keep flags stable to avoid breaking user scripts.

5) Integration points and external deps
- Cobra for CLI (`github.com/spf13/cobra`) — changes to CLI should update `go.mod` and keep compatibility with Cobra v1.x API.
- No network calls or external services; tests rely on local example files under `examples/`.

6) Helpful file examples to reference in PRs
- Parser: `compiler/parser.go`, `compiler/parser_test.go` (or tests under `compiler/`).
- Analyzer & optimizer: `compiler/analyzer.go`, `compiler/optimizer.go`.
- Mapping: `mapping/type_mapping.go`, `mapping/context_mapping.go`.
- Generators: `selinux/te_generator.go`, `selinux/fc_generator.go`.

7) Common edits and cautions
- When changing AST/data models in `models/`, update all consumers: parser → analyzer → mapping → generators → tests.
- Keep CLI flags and output messages stable; tests and examples parse CLI outputs.
- Unit tests in `tests/` and package tests expect deterministic ordering; maintain stable map/list ordering when possible.

8) Quick examples for the agent
- To add a new mapping rule: edit `mapping/type_mapping.go` and add a unit test under `mapping/` verifying `Path→Type` inference.
- To add a CLI flag: edit `cli/main.go`, add flag using Cobra, wire into command handler in `cli/` and add an integration test under `tests/`.

If anything above is unclear or you want more detail on specific components (parser, mapping rules, or the generator), tell me which area and I will expand with code pointers and small TODOs.
