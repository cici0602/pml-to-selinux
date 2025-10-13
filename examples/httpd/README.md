# Apache httpd SELinux Policy Example

This example demonstrates how to use Casbin PML to define SELinux policies for Apache httpd.

## Files

- `httpd_model.conf` - PML model definition
- `httpd_policy.csv` - Policy rules
- `expected_output/` - Expected generated SELinux files

## Policy Description

This policy allows httpd to:
- Read and write web content in `/var/www/html/`
- Write logs to `/var/log/httpd/`
- Read configuration from `/etc/httpd/`
- Bind to network sockets
- Read system libraries

And denies:
- Writing to system binaries

## Compile

```bash
cd /home/chris/opensource/casbin/pml-to-selinux
go run cli/main.go compile \
  -m examples/httpd/httpd_model.conf \
  -p examples/httpd/httpd_policy.csv \
  -o examples/httpd/output/ \
  -n httpd
```

## Expected Output

### httpd.te (Type Enforcement)

```selinux
policy_module(httpd, 1.0.0)

type httpd_t;
type httpd_var_www_t;
type httpd_log_t;
type httpd_etc_t;

# Allow rules
allow httpd_t httpd_var_www_t:file { read write getattr };
allow httpd_t httpd_log_t:file { write append create };
allow httpd_t httpd_etc_t:file { read getattr };
allow httpd_t self:tcp_socket { bind listen accept };

# Deny rules
neverallow httpd_t bin_t:file write;
```

### httpd.fc (File Context)

```selinux
/var/www/html(/.*)?       gen_context(system_u:object_r:httpd_var_www_t,s0)
/var/log/httpd(/.*)?      gen_context(system_u:object_r:httpd_log_t,s0)
/etc/httpd(/.*)?          gen_context(system_u:object_r:httpd_etc_t,s0)
```

## Install and Test

After generation, you can compile and install the policy:

```bash
# Compile the policy
checkmodule -M -m -o httpd.mod httpd.te
semodule_package -o httpd.pp -m httpd.mod -fc httpd.fc

# Install the policy
sudo semodule -i httpd.pp

# Test
sudo semanage fcontext -l | grep httpd
```
