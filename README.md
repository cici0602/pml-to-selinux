# PML-to-SELinux Compiler

**PML-to-SELinux** is a tool that simplifies SELinux policy creation by compiling high-level Casbin Policy Markup Language (PML) into standard SELinux policy modules.

## 🎯 Design Philosophy

This tool follows the **80/20 principle** (Pareto Principle) for SELinux policy generation:

- **Target Users**: Application developers and system administrators who need to secure their applications
- **Core Focus**: Cover 80% of common use cases with minimal complexity
- **Not a Goal**: 100% feature parity with native SELinux (which would add unnecessary complexity)

## ✅ Supported Features (MVP)

The tool supports the most common SELinux use cases:

### 1. Domain & Type Management ✅
- Create isolated security domains (`myapp_t`)
- Automatic type declarations for files, dirs, sockets, etc.
- Domain transition rules (`exec_type` → domain transition)

### 2. File/Directory Access Control ✅
- Read, write, execute permissions on files
- Directory operations (search, add_name, remove_name)
- Automatic file context (`.fc`) generation
- Support for recursive patterns (`/var/lib/myapp(/.*)  ?`)

### 3. Network & Port Binding ✅
- TCP/UDP port binding (`tcp:8080`)
- Unix domain socket support
- Network connection permissions

### 4. Basic Capabilities ✅
- Essential capabilities like `net_bind_service`
- `setuid`, `setgid` for privileged operations

### 5. Type Transitions ✅
- Automatic labeling for newly created files
- Ensures runtime-created files get correct types

### 6. Common Object Classes ✅
Supports these object classes:
- `file`, `dir`, `lnk_file`, `sock_file`
- `tcp_socket`, `udp_socket`, `unix_stream_socket`, `unix_dgram_socket`
- `process`, `capability`

## ❌ Not Supported (By Design)

These advanced SELinux features are intentionally NOT supported in the MVP:

### 1. MLS/MCS (Multi-Level/Category Security) ❌
- **Why**: Too complex for 80% of use cases
- **Alternative**: Use native SELinux tools if you need mandatory access control

### 2. Deny Rules / Neverallow ❌
- **Why**: Simplified to allow-only model for clarity
- **Alternative**: Manually add `neverallow` statements to generated `.te` files

### 3. Conditional Policies & Booleans ❌
- **Why**: Adds significant complexity
- **Alternative**: Generate static policies, use `semanage boolean` for runtime changes

### 4. Complex Role Transitions ❌
- **Why**: Most applications don't need `newrole` or complex RBAC
- **Alternative**: Use native SELinux role management for complex scenarios

### 5. Constraints & Assertions ❌
- **Why**: Advanced feature rarely needed
- **Alternative**: Manually add `constrain` statements to `.te` files

### 6. Full Macro/Interface System ❌
- **Why**: We generate basic interfaces only
- **Alternative**: Extend generated `.if` files manually for complex interfaces

## 🚀 Quick Start

### Installation

```bash
cd pml-to-selinux
go build -o bin/pml-to-selinux ./cli
```

### Basic Usage

```bash
# Compile a PML policy to SELinux
./bin/pml-to-selinux compile \
  -m examples/webapp/model.conf \
  -p examples/webapp/policy.csv \
  -o output/webapp \
  -n myweb \
  -v

# Install the generated policy
checkmodule -M -m -o myweb.mod output/webapp/myweb.te
semodule_package -o myweb.pp -m myweb.mod -fc output/webapp/myweb.fc
sudo semodule -i myweb.pp

# Relabel files
sudo restorecon -R /opt/myweb /var/lib/myweb /var/log/myweb
```

## 📝 PML Policy Example

### Simple Web Application

**model.conf:**
```ini
[request_definition]
r = sub, obj, act, class

[policy_definition]
p = sub, obj, act, class, eft

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && matchPath(r.obj, p.obj) && r.act == p.act && r.class == p.class
```

**policy.csv:**
```csv
# Web app domain
p, myweb_t, /opt/myweb/bin/myweb, execute, file, allow

# Read config
p, myweb_t, /opt/myweb/config(/.*)?, read, file, allow

# Write data
p, myweb_t, /var/lib/myweb(/.*)?, write, file, allow
p, myweb_t, /var/lib/myweb(/.*)?, create, file, allow

# Append logs
p, myweb_t, /var/log/myweb(/.*)?, append, file, allow

# Bind to port 8080
p, myweb_t, tcp:8080, name_bind, tcp_socket, allow

# Capability to bind ports
p, myweb_t, self, net_bind_service, capability, allow
```

This generates:
- `myweb.te` - Type Enforcement policy
- `myweb.fc` - File Contexts
- `myweb.if` - Interface definitions

## 📚 Examples

See the `examples/` directory for complete examples:

- **`examples/webapp/`** - Web application (port binding, file access, logging)
- **`examples/database/`** - Database service (data files, socket, logs)
- **`examples/worker/`** - Background worker (IPC, caching, network)

## 🔧 Generated Files

### .te (Type Enforcement)
Contains:
- Type declarations
- Allow rules
- Domain transitions
- Capabilities

### .fc (File Contexts)
Contains:
- Path-to-type mappings
- Regex patterns for recursive directories
- Proper SELinux context format

### .if (Interface)
Contains:
- Basic access interfaces for other modules
- Automatically generated from your policy

## 🎓 When to Use Native SELinux

Use `pml-to-selinux` when:
- ✅ Creating policy for a new application
- ✅ Need basic file/network/process isolation
- ✅ Want rapid prototyping of SELinux policies
- ✅ Learning SELinux concepts

Use native SELinux tools when:
- ❌ Need MLS/MCS security levels
- ❌ Require complex conditional policies
- ❌ Need fine-grained role-based access control
- ❌ Want to modify system core policies

## 🤝 Contributing

This is a focused MVP tool. When contributing:

1. **Keep it simple** - Don't add features that serve <20% of users
2. **Document limitations** - Be clear about what's not supported
3. **Provide examples** - Show real-world use cases
4. **Test thoroughly** - Ensure generated policies actually work

See [REFACTOR_PROGRESS.md](REFACTOR_PROGRESS.md) for current development status.

## 📖 Documentation

- [Implementation Guide](docs/实现指南.md) - MVP feature specifications (Chinese)
- [Refactoring Guide](docs/重构指南.md) - Design principles (Chinese)
- [Refactor Status](REFACTOR_PROGRESS.md) - Current progress

## ⚖️ License

Apache License 2.0

## 🙏 Acknowledgments

Built on top of [Casbin](https://github.com/casbin/casbin) for policy parsing.

---

**Remember**: This tool aims to make SELinux accessible, not to replace it entirely. For production deployments, always review and test generated policies thoroughly!
