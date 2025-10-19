# Database Example

This example demonstrates a database service that:

## Use Cases

1. **Binds to port 5432** - TCP connections
2. **Manages database files** in `/var/lib/mydb/`
3. **Writes logs** to `/var/log/mydb/`
4. **Provides Unix socket** at `/var/run/mydb.sock`

## Expected SELinux Policy

### Types
- `mydb_t` - Main database domain
- `mydb_exec_t` - Executable file type
- `mydb_db_var_t` - Database data files
- `mydb_sock_t` - Unix socket file

### File Contexts
```
/usr/lib/mydb/bin/mydb    --  mydb_exec_t
/var/lib/mydb(/.*)?       --  mydb_db_var_t
/var/log/mydb(/.*)?       --  var_log_t
/var/run/mydb.sock        -s  mydb_sock_t
```

### Key Rules
- Full access to database files (read/write/create/unlink)
- TCP socket binding to port 5432
- Unix socket creation and binding
- Log append permissions

## Compile

```bash
pml2selinux compile -m model.conf -p policy.csv -o output/
```
