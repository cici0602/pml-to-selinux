# PML-to-SELinux Compiler - AI Agent Instructions

## Project Overview

This is a compiler that translates **Casbin PML (Policy Modeling Language)** into **SELinux policy files** (.te, .fc). It bridges high-level access control policies with Linux kernel security modules.

**Core Value Proposition**: Write security policies in Casbin's human-readable format and automatically generate production-ready SELinux policies.

## Architecture & Pipeline

The compilation happens in 6 stages:

```
PML Files → Parser → Analyzer → Generator → Optimizer → SELinux Files
 (.conf/.csv)  ↓       ↓          ↓           ↓         (.te/.fc)
            models/  compiler/  selinux/  compiler/
           ParsedPML  validation mapping  optimizer
```

### Package Responsibilities

- **`models/`**: Core data structures
  - `pml_model.go`: Casbin PML structures (Policy, RoleRelation, ParsedPML)
  - `selinux_model.go`: SELinux structures (AllowRule, DenyRule, FileContext, TypeDeclaration)
  
- **`compiler/`**: Parsing and analysis
  - `parser.go`: Reads `.conf` (model) and `.csv` (policy) files
  - `analyzer.go`: Validates model completeness, policy rules, detects conflicts
  - `optimizer.go`: Merges rules, deduplicates types/contexts

- **`mapping/`**: Translation logic (the "magic")
  - `context_mapping.go`: Converts Casbin wildcards to SELinux regex
    - `/var/www/*` → `/var/www(/.*)?`
    - `/etc/*.conf` → `/etc/[^/]+\.conf`
  - `type_mapping.go`: Generates SELinux type names from paths
    - `/var/log/httpd/*` → `httpd_var_log_httpd_t`
    - Infers attributes: logfile, configfile, exec_type

- **`selinux/`**: Output generation
  - `te_generator.go`: Creates Type Enforcement files with policy_module, type declarations, allow/deny rules
  - `fc_generator.go`: Creates File Context files with gen_context() macros

- **`cli/`**: Command-line interface (work in progress)
  - Uses Cobra framework
  - Main command: `pml2selinux compile -m model.conf -p policy.csv`

## Critical Patterns & Conventions

### 1. PML Policy Format
```csv
p, subject, object, action, class, effect
p, httpd_t, /var/www/html/*, read, file, allow
```
- **subject**: SELinux type (e.g., `httpd_t`)
- **object**: File path with wildcards
- **action**: Permission name (read, write, execute)
- **class**: Object class (file, dir, tcp_socket)
- **effect**: allow or deny

### 2. Path Pattern Translation Rules
When converting paths in `mapping/context_mapping.go`:
- Trailing wildcards: `/*` → `(/.*)?` (matches directory contents)
- Mid-path wildcards: `*` → `[^/]+` (matches single path component)
- Always escape regex special chars: `.`, `+`, `(`, `)`, etc.
- File type inference: paths ending `/` are directories

### 3. Type Naming Convention
Generated types follow: `{module}_{normalized_path}_t`
- Replace `/` with `_`
- Replace `-` and `.` with `_`
- Remove leading `/`
- Example: `/var/log/httpd/*` with module "httpd" → `httpd_var_log_httpd_t`

### 4. Rule Optimization Strategy
The optimizer merges rules with same source/target/class:
```selinux
# Before
allow httpd_t file_t:file read;
allow httpd_t file_t:file write;

# After  
allow httpd_t file_t:file { read write };
```

## Development Workflows

### Running Tests
```bash
# All tests (50+ test cases)
go test ./... -v

# Specific package
go test ./mapping -v          # Path/type mapping tests
go test ./compiler -v         # Parser/analyzer tests
```

### Demo/Integration Testing
```bash
cd tests
go run demo_phase2.go         # Full pipeline demo using httpd example
```

### Building CLI (when implemented)
```bash
cd cli
go build -o pml2selinux
./pml2selinux compile -m ../examples/httpd/httpd_model.conf -p ../examples/httpd/httpd_policy.csv -o output/
```

## Example Data Locations

- **Example policies**: `examples/httpd/` and `examples/basic/`
- **Test fixtures**: Embedded in `*_test.go` files
- **Demo program**: `tests/demo_phase2.go` shows complete workflow

## Key Files to Reference

When working on:
- **Path conversion**: See `mapping/context_mapping_test.go` for 16 test cases covering edge cases
- **Type generation**: See `mapping/type_mapping_test.go` for system path detection patterns
- **SELinux output format**: See `selinux/te_generator.go` lines 50-150 for formatting rules
- **PML parsing**: See `compiler/parser.go` parseModel() and parsePolicy() methods

## Common Pitfalls

1. **Path escaping**: Always escape regex chars BEFORE converting wildcards, not after
2. **Type attributes**: Different paths imply different attributes:
   - `/bin`, `/sbin` → exec_type
   - `/var/log`, `*.log` → logfile
   - `/etc`, `*.conf` → configfile
3. **Rule merging**: Must preserve original object path in `OriginalObject` field for traceability
4. **File contexts**: Always set defaults: `system_u:object_r:{type}:s0`

## Project Status

- ✅ **Phase 1 Complete**: Parser, analyzer (17 + 7 test suites)
- ✅ **Phase 2 Complete**: Mappers, generators, optimizer (30+ tests)
- 🚧 **Phase 3 In Progress**: Full CLI implementation

See `PHASE2_COMPLETED.md` for detailed feature list.

## Testing Philosophy

- Unit tests for each mapper function with edge cases
- Integration tests via demo programs
- No mocking - tests use real file I/O with example data
- Test output consistency: always sort types/rules for deterministic output

## Notes on SELinux Specifics

This compiler targets **SELinux reference policy** format:
- Uses `policy_module()` macro (not raw policy)
- Type declarations include attributes for policy inference
- File contexts use `gen_context()` macro for MLS/MCS support
- Deny rules use `neverallow` (compile-time enforcement)
