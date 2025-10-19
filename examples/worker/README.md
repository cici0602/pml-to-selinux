# Background Worker Example

This example demonstrates a background worker process that:

## Use Cases

1. **Connects to remote services** - Outbound TCP connections
2. **Writes local cache** in `/var/cache/worker/`
3. **Connects to unix socket** - IPC with other services
4. **Provides its own socket** at `/var/run/worker.sock`

## Expected SELinux Policy

### Types
- `worker_t` - Main worker domain
- `worker_exec_t` - Executable file type
- `worker_cache_t` - Cache files
- `worker_sock_t` - Unix socket file

### File Contexts
```
/opt/worker/bin/worker    --  worker_exec_t
/var/cache/worker(/.*)?   --  worker_cache_t
/var/run/worker.sock      -s  worker_sock_t
```

### Key Rules
- Full access to cache files
- Connect to external unix sockets
- Make outbound TCP connections (`name_connect`)
- Create and bind to its own unix socket

## Compile

```bash
pml2selinux compile -m model.conf -p policy.csv -o output/
```

## Notes

This example showcases:
- Network client operations (TCP connect)
- IPC via unix sockets
- Cache file management
- No special capabilities needed
