# PML to SELinux

[![Go Report Card](https://goreportcard.com/badge/github.com/cici0602/pml-to-selinux)](https://goreportcard.com/report/github.com/cici0602/pml-to-selinux)
[![Build](https://github.com/cici0602/pml-to-selinux/actions/workflows/ci.yml/badge.svg)](https://github.com/cici0602/pml-to-selinux/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/cici0602/pml-to-selinux)](https://github.com/cici0602/pml-to-selinux/releases)
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/S5UjpzGZjN)

Lightweight compiler that translates Casbin PML (Policy Modeling Language) into SELinux policy modules.

## Features

Supported:

- Basic Type Enforcement (TE)
- File and directory access control
- TCP/UDP port bind/connect
- Unix domain sockets
- Process capabilities
- Domain transitions
- Generate standard SELinux files (.te, .fc, .if)

Not supported:

- MLS/MCS (multi-level security)
- Conditional policies and booleans
- Complex constraint statements
- Role transitions


## Installation

Install the CLI using go:

```bash
go install github.com/cici0602/pml-to-selinux/cli@latest
```

Or build from source:

```bash
git clone https://github.com/cici0602/pml-to-selinux.git
cd pml-to-selinux
make build
```

## Quick start

1. Initialize a project:

```bash
pml2selinux init myapp
cd myapp
```

2. Edit `policy.csv` (example):

```csv
# Allow executing the application binary
p, myapp_t, /usr/bin/myapp, execute, allow

# Allow reading the configuration file
p, myapp_t, /etc/myapp/config.json, read, allow

# Allow appending to logs
p, myapp_t, /var/log/myapp(/.*)?, append, allow

# Allow binding TCP port 8080
p, myapp_t, tcp:8080, name_bind, allow
```

3. Compile the policy:

```bash
pml2selinux compile -m model.conf -p policy.csv -o output/
```

## Commands

```bash
pml2selinux compile    # Compile PML to SELinux policy
pml2selinux validate   # Validate PML files
pml2selinux init       # Initialize a new project
pml2selinux version    # Show version
```

## Examples

See the `examples/` directory for sample projects:

- `webapp/` - web application example
- `database/` - database service example
- `worker/` - background worker example

## License

Apache License 2.0
