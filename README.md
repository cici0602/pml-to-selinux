# PML to SELinux Policy Compiler

将 Casbin PML (Policy Modeling Language) 转换为 SELinux 策略文件的编译器工具。

[![Build](https://github.com/cici0602/pml-to-selinux/actions/workflows/ci.yml/badge.svg)](https://github.com/cici0602/pml-to-selinux/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/cici0602/pml-to-selinux)](https://goreportcard.com/report/github.com/cici0602/pml-to-selinux)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## 特性

- ✅ 完整的 PML 解析器 (model.conf + policy.csv)
- ✅ 智能映射到 SELinux 类型和权限
- ✅ 生成 .te (类型强制)、.fc (文件上下文)、.if (接口) 文件
- ✅ 策略优化和冲突检测
- ✅ 支持角色关系和类型转换
- ✅ 命令行工具和多种操作模式
- ✅ Docker 容器化支持
- ✅ **新增**: 目录递归支持 (`/path/*` → `/path(/.*)?`)
- ✅ **新增**: 角色映射和继承 (`g, member, role`)
- ✅ **新增**: 域转换规则自动生成 (`t, source, target, class, new_type`)
- ✅ **新增**: 可配置的动作映射表 (支持自定义动作映射)

## 快速开始

### 安装

```bash
# 源码安装
git clone https://github.com/cici0602/pml-to-selinux
cd pml-to-selinux
make build
make install

# Docker 运行
docker pull cici0602/pml2selinux:latest

# 或下载预编译二进制
# 见 GitHub Releases
```

### 基本使用

```bash
# 编译 PML 到 SELinux 策略
pml2selinux compile -m model.conf -p policy.csv -o output/

# 验证 PML 文件
pml2selinux validate -m model.conf -p policy.csv

# 分析策略
pml2selinux analyze -m model.conf -p policy.csv

# 比较两个策略
pml2selinux diff -m1 model1.conf -p1 policy1.csv -m2 model2.conf -p2 policy2.csv

# 初始化项目模板
pml2selinux init myproject
```

## 示例

### 输入：PML 策略

**model.conf**:
```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
```

**policy.csv**:
```csv
httpd_t,/var/www/html/*,read,allow
httpd_t,/var/log/httpd/*,write,allow
```

### 输出：SELinux 策略

**httpd.te**:
```
policy_module(httpd, 1.0.0)

type httpd_var_www_html_t;
type httpd_var_log_httpd_t;

allow httpd_t httpd_var_www_html_t:file { read getattr };
allow httpd_t httpd_var_log_httpd_t:file { write create };
```

**httpd.fc**:
```
/var/www/html(/.*)?    gen_context(system_u:object_r:httpd_var_www_html_t,s0)
/var/log/httpd(/.*)?   gen_context(system_u:object_r:httpd_var_log_httpd_t,s0)
```

More examples at [examples/](examples/) directory.

## 第二阶段新功能

### 目录递归支持

PML 策略中的 `/path/*` 模式会自动转换为 SELinux 的递归模式 `/path(/.*)?`：

**PML 输入**:
```csv
p, httpd_t, /var/www/*, read, file, allow
```

**SELinux 输出**:
```selinux
# .te 文件
allow httpd_t httpd_var_www_t:file { read open getattr };

# .fc 文件  
/var/www(/.*)?    gen_context(system_u:object_r:httpd_var_www_t,s0)
```

### 角色映射

支持 PML 角色关系映射到 SELinux 角色：

**PML 输入**:
```csv
g, webapp_user, webapp_staff
g, webapp_staff, webapp_admin
```

**SELinux 输出**:
```selinux
allow webapp_user_r webapp_staff_r;
allow webapp_staff_r webapp_admin_r;
```

### 域转换（Domain Transitions）

自动生成进程域转换所需的所有规则：

**PML 输入**:
```csv
t, webapp_t, webapp_worker_exec_t, process, webapp_worker_t
```

**SELinux 输出**:
```selinux
type_transition webapp_t webapp_worker_exec_t:process webapp_worker_t;
allow webapp_t webapp_worker_exec_t:file { execute read open getattr };
allow webapp_t webapp_worker_t:process transition;
allow webapp_worker_t webapp_worker_exec_t:file entrypoint;
```

### 动作映射表

支持自定义和扩展动作映射：

```go
// 默认映射
read    → { read, open, getattr }
write   → { write, open, append }
execute → { execute, read, open, getattr, execute_no_trans }

// 复合动作
rw      → { read, write }
rwx     → { read, write, execute }
```

查看完整示例: [examples/phase2/](examples/phase2/)

## Architecture


## 开发

### 构建

```bash
make build      # 构建二进制
make test       # 运行测试
make bench      # 性能测试
make coverage   # 覆盖率报告
make lint       # 代码检查
```

### 测试

```bash
# 运行所有测试
go test ./...

# 运行特定测试
go test ./compiler -v

# 性能测试
go test -bench=. ./...
```

### Docker

```bash
# 构建镜像
make docker-build

# 运行
docker run --rm -v $(pwd):/workspace cici0602/pml2selinux compile -m model.conf -p policy.csv
```

## 项目结构

```
.
├── cli/             # 命令行工具
├── compiler/        # 核心编译器
│   ├── parser.go       # PML 解析器
│   ├── analyzer.go     # 策略分析器
│   ├── generator.go    # SELinux 生成器
│   └── optimizer.go    # 策略优化器
├── mapping/         # 映射逻辑
├── selinux/         # SELinux 文件生成
├── models/          # 数据模型
├── examples/        # 示例策略
└── docs/            # 文档
```

## 文档

- [快速开始](docs/QUICKSTART.md)
- [实施指南](docs/IMPLEMENTATION_GUIDE.md)
- [项目状态](docs/PROJECT_STATUS.md)
- [Phase 3 报告](docs/PHASE3_COMPLETION.md)
- [Phase 4 报告](docs/PHASE4_COMPLETION.md)
- [Phase 5 报告](docs/PHASE5_COMPLETION.md)

## 路线图

- ✅ Phase 1: 核心解析器
- ✅ Phase 2: SELinux 生成器
- ✅ Phase 3: CLI 工具
- ✅ Phase 4: 高级特性 (接口、diff、模板)
- ✅ Phase 5: 生产就绪 (CI/CD、Docker、Benchmark)

## 贡献

欢迎贡献！请查看 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可

Apache License 2.0 - 详见 [LICENSE](LICENSE)

## 致谢

基于 [Casbin](https://casbin.org) 项目构建。
