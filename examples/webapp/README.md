# Web Application Example

This example demonstrates a simple web application that:

## Use Cases

1. **Binds to port 8080** - Web service listening
2. **Reads configuration** from `/opt/myweb/config/`
3. **Writes data files** to `/var/lib/myweb/`
4. **Appends to logs** in `/var/log/myweb/`

## Expected SELinux Policy

### Types
- `myweb_t` - Main application domain
- `myweb_exec_t` - Executable file type
- `myweb_config_t` - Configuration files
- `myweb_var_lib_t` - Data files
- `myweb_log_t` or reuse `var_log_t` - Log files

### File Contexts
```
/opt/myweb/bin/myweb      --  myweb_exec_t
/opt/myweb/config(/.*)?   --  myweb_config_t
/var/lib/myweb(/.*)?      --  myweb_var_lib_t
/var/log/myweb(/.*)?      --  var_log_t
```

### Key Rules
- Allow execute on `myweb_exec_t`
- Allow read on `myweb_config_t`
- Allow read/write/create on `myweb_var_lib_t`
- Allow append/write on log files
- Allow `name_bind` on `tcp_socket` for port 8080
- Allow `net_bind_service` capability

## Compile

```bash
pml2selinux compile -m model.conf -p policy.csv -o output/
```
