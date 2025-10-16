# Phase 2 功能演示示例

本示例演示了 PML to SELinux 编译器第二阶段的所有新功能：

## 功能展示

### 1. 目录与递归支持
- **递归路径匹配**: `/var/www/webapp/*` 会生成 SELinux 的 `/var/www/webapp(/.*)?` 模式
- **目录识别**: 自动识别目录并应用适当的权限
- **子目录支持**: 策略自动应用到所有子目录

示例：
```csv
p, webapp_t, /var/www/webapp/*, read, file, allow
```
生成的 SELinux 规则：
```
allow webapp_t webapp_var_www_webapp_t:file { read open getattr };
allow webapp_t webapp_var_www_webapp_t:dir { search getattr };
```

生成的文件上下文：
```
/var/www/webapp(/.*)?    gen_context(system_u:object_r:webapp_var_www_webapp_t,s0)
```

### 2. 角色（Role）映射
- **用户-角色映射**: `g, webapp_user, webapp_staff` 定义角色关系
- **角色继承**: 支持多级角色继承
- **自动生成角色允许规则**

示例角色层次：
```
webapp_user → webapp_staff → webapp_admin → sysadm
```

生成的 SELinux 规则：
```
allow webapp_user_r webapp_staff_r;
allow webapp_staff_r webapp_admin_r;
allow webapp_admin_r sysadm_r;
```

### 3. Domain Transitions
- **进程域转换**: 支持主域到子域的自动转换
- **入口点定义**: 自动生成必要的入口点和转换权限
- **转换辅助规则**: 自动添加 execute、transition、entrypoint 权限

示例：
```csv
t, webapp_t, webapp_worker_exec_t, process, webapp_worker_t
```

生成的 SELinux 规则：
```
type_transition webapp_t webapp_worker_exec_t:process webapp_worker_t;
allow webapp_t webapp_worker_exec_t:file { execute read open getattr };
allow webapp_t webapp_worker_t:process transition;
allow webapp_worker_t webapp_worker_exec_t:file entrypoint;
```

### 4. 动作映射表
- **预定义映射**: 常见动作（read、write、execute）自动映射到多个 SELinux 权限
- **复合动作**: 支持 `rwx`、`rw` 等简写
- **可扩展**: 支持自定义动作映射

动作映射示例：
- `read` → `{ read open getattr }`
- `write` → `{ write open append }`
- `execute` → `{ execute read open getattr execute_no_trans }`
- `rwx` → `{ read write execute ... }`

### 5. 增强的类支持
- **文件类**: file, dir, lnk_file
- **进程类**: process
- **网络类**: tcp_socket, udp_socket
- **IPC类**: shm, sem, msgq

## 编译示例

```bash
# 编译此示例
pml2selinux compile -m phase2_model.conf -p phase2_policy.csv -o output/

# 生成的文件：
# - output/webapp.te (类型强制策略)
# - output/webapp.fc (文件上下文)
# - output/webapp.if (接口定义)
```

## 预期输出

### webapp.te (部分)
```selinux
policy_module(webapp, 1.0.0)

# 类型声明
type webapp_t;
type webapp_var_www_webapp_t;
type webapp_var_log_webapp_t;
type webapp_etc_webapp_t;
type webapp_worker_t;
type webapp_worker_exec_t;
type webapp_dbclient_t;
type webapp_dbclient_exec_t;

# 文件访问规则（递归目录支持）
allow webapp_t webapp_var_www_webapp_t:file { read write execute open getattr };
allow webapp_t webapp_var_www_webapp_t:dir { search getattr read };

# 日志写入
allow webapp_t webapp_var_log_webapp_t:file { write append create open };
allow webapp_t webapp_var_log_webapp_t:dir { add_name write search };

# 域转换规则
type_transition webapp_t webapp_worker_exec_t:process webapp_worker_t;
allow webapp_t webapp_worker_exec_t:file { execute read open getattr };
allow webapp_t webapp_worker_t:process transition;
allow webapp_worker_t webapp_worker_exec_t:file entrypoint;

# 角色允许规则
allow webapp_user_r webapp_staff_r;
allow webapp_staff_r webapp_admin_r;

# 网络权限
allow webapp_t self:tcp_socket { bind listen accept };
```

### webapp.fc (部分)
```selinux
# 递归目录模式
/var/www/webapp(/.*)?              gen_context(system_u:object_r:webapp_var_www_webapp_t,s0)
/var/log/webapp(/.*)?              gen_context(system_u:object_r:webapp_var_log_webapp_t,s0)
/etc/webapp(/.*)?                  gen_context(system_u:object_r:webapp_etc_webapp_t,s0)
/var/tmp/webapp(/.*)?              gen_context(system_u:object_r:webapp_var_tmp_webapp_t,s0)
/var/lib/webapp/db(/.*)?           gen_context(system_u:object_r:webapp_var_lib_webapp_db_t,s0)

# 可执行文件
/usr/local/bin/webapp-helper   --  gen_context(system_u:object_r:webapp_exec_t,s0)
/usr/local/bin/webapp-cron     --  gen_context(system_u:object_r:webapp_exec_t,s0)
```

## 测试

运行单元测试：
```bash
cd /path/to/pml-to-selinux
go test ./mapping/... -v
go test ./compiler/... -v
```

## 新增功能清单

✅ 目录递归支持 (`/path/*` → `/path(/.*)?`)
✅ 角色映射和继承 (`g, member, role`)
✅ 域转换规则 (`t, source, target, class, new_type`)
✅ 动作映射表（可配置和扩展）
✅ 增强的文件上下文生成
✅ 完整的单元测试覆盖

## 下一步（第三阶段）

- [ ] Booleans 支持
- [ ] semanage 集成
- [ ] 复杂宏生成
- [ ] 策略最小化优化
- [ ] 冲突检测增强
