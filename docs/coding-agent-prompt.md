# Coding Agent 提示词: Casbin PML to SELinux 编译器

## 项目背景

你正在为 Casbin 开源项目开发一个新功能：**PML to SELinux 编译器**。该功能允许用户使用 Casbin 的 PML (Policy Modeling Language) 作为更高层次的抽象语言编写安全策略，然后编译生成 SELinux 策略文件。

### 核心目标
- 让 Casbin PML 成为比 SELinux 策略更高层、更易用的抽象层
- 用户只需编写 Casbin PML，无需直接接触复杂的 SELinux 语法
- 在 PML 层面进行策略分析、验证和优化
- 自动生成标准的 SELinux 策略包 (.te, .fc, .if 文件)

## 技术栈
- **语言**: Go (项目已有代码库是 Go)
- **输入**: Casbin PML 模型文件 (.conf) 和策略文件 (.csv)
- **输出**: SELinux 策略文件 (.te, .fc, .if)

## 代码结构要求

请按照以下模块化结构组织代码：

```
pml-to-selinux/
├── compiler/
│   ├── parser.go          # 解析 PML 模型和策略
│   ├── analyzer.go        # 语义分析、类型检查
│   ├── generator.go       # SELinux 代码生成协调器
│   └── optimizer.go       # 策略优化（去重、合并）
├── mapping/
│   ├── type_mapping.go    # Casbin type ↔ SELinux type
│   ├── context_mapping.go # 路径模式 ↔ file context
│   └── permission_mapping.go # Casbin action ↔ SELinux permission
├── selinux/
│   ├── te_generator.go    # 生成 .te 文件 (type enforcement)
│   ├── fc_generator.go    # 生成 .fc 文件 (file context)
│   └── if_generator.go    # 生成 .if 文件 (interface)
├── validator/
│   ├── pml_validator.go   # 验证 PML 语法和语义
│   └── selinux_validator.go # 验证生成的 SELinux 策略
├── models/
│   ├── pml_model.go       # PML 数据结构
│   └── selinux_model.go   # SELinux 策略数据结构
├── cli/
│   └── main.go            # 命令行工具入口
├── examples/
│   ├── httpd/             # Apache httpd 示例
│   ├── nginx/             # Nginx 示例
│   └── basic/             # 基础示例
├── tests/
│   └── ...                # 单元测试和集成测试
└── docs/
    ├── 设计文档.md
    └── coding-agent-prompt.md
```

## 核心数据结构

### 1. PML Model 结构
```go
type PMLModel struct {
    RequestDefinition map[string][]string  // r = sub, obj, act, class
    PolicyDefinition  map[string][]string  // p = sub, obj, act, class, eft
    RoleDefinition    map[string][]string  // g = _, _
    Matchers          string               // 匹配规则
    Effect            string               // 策略效果
}

type Policy struct {
    Subject    string  // e.g., "httpd_t"
    Object     string  // e.g., "/var/www/*"
    Action     string  // e.g., "read"
    Class      string  // e.g., "file"
    Effect     string  // "allow" or "deny"
}
```

### 2. SELinux Policy 结构
```go
type SELinuxPolicy struct {
    ModuleName string
    Version    string
    Types      []TypeDeclaration
    Rules      []AllowRule
    Transitions []TypeTransition
}

type AllowRule struct {
    SourceType string
    TargetType string
    Class      string
    Permissions []string
}

type FileContext struct {
    PathPattern string
    Context     string  // e.g., "system_u:object_r:httpd_var_www_t:s0"
}
```

## 关键实现要点

### 1. 路径模式映射
```go
// 将 Casbin 路径模式转换为 SELinux file context
// Input: /var/www/*
// Output: /var/www(/.*)?    gen_context(system_u:object_r:httpd_var_www_t,s0)

func ConvertPathPattern(casbinPath string) (selinuxPattern string, typeLabel string) {
    // 实现路径通配符转换
    // * -> (/.*)?
    // ** -> (/.*)? (递归匹配)
    // 生成唯一的 type 标签
}
```

### 2. 权限聚合
```go
// 将多条相同 source/target 的规则合并
// Input:
//   allow httpd_t httpd_var_www_t:file read
//   allow httpd_t httpd_var_www_t:file write
// Output:
//   allow httpd_t httpd_var_www_t:file { read write };

func AggregatePermissions(rules []AllowRule) []AllowRule {
    // 按 source, target, class 分组
    // 合并 permissions
}
```

### 3. 类型推断
```go
// 从路径推断 SELinux type
// /var/www/* -> httpd_var_www_t
// /var/log/httpd/* -> httpd_log_t
// /etc/httpd/* -> httpd_etc_t

func InferTypeFromPath(path string, subject string) string {
    // 使用命名约定生成 type 名称
}
```

## CLI 接口设计

```bash
# 基本用法
pml2selinux compile -m model.conf -p policy.csv -o output_dir/

# 参数说明
-m, --model    PML 模型文件路径
-p, --policy   PML 策略文件路径
-o, --output   输出目录
-n, --name     生成的模块名称（默认从策略推断）
-v, --validate 生成后验证策略
--optimize     启用策略优化

# 示例
pml2selinux compile \
  -m examples/httpd/httpd_model.conf \
  -p examples/httpd/httpd_policy.csv \
  -o output/httpd/ \
  -n httpd \
  --validate
```

## 测试要求

### 单元测试
```go
func TestPathPatternConversion(t *testing.T) {
    tests := []struct {
        input    string
        expected string
    }{
        {"/var/www/*", "/var/www(/.*)?"},
        {"/etc/*.conf", "/etc/[^/]+\\.conf"},
    }
    // ...
}

func TestPolicyAggregation(t *testing.T) {
    // 测试权限合并
}

func TestTypeInference(t *testing.T) {
    // 测试类型推断
}
```

### 集成测试
- 测试完整的编译流程
- 验证生成的 SELinux 策略可以被 checkmodule 编译
- 测试常见场景（httpd, nginx, ssh）

## 示例场景

### 示例 1: Apache httpd

**输入 PML:**
```ini
# httpd_model.conf
[request_definition]
r = sub, obj, act, class

[policy_definition]
p = sub, obj, act, class, eft

[matchers]
m = r.sub == p.sub && matchPath(r.obj, p.obj) && r.act == p.act && r.class == p.class
```

```csv
# httpd_policy.csv
p, httpd_t, /var/www/html/*, read, file, allow
p, httpd_t, /var/www/html/*, write, file, allow
p, httpd_t, /var/log/httpd/*, write, file, allow
p, httpd_t, /etc/httpd/*, read, file, allow
p, httpd_t, :80, bind, tcp_socket, allow
```

**预期输出:**
```selinux
# httpd.te
policy_module(httpd, 1.0.0)

require {
    type httpd_t;
}

type httpd_var_www_t;
type httpd_log_t;
type httpd_etc_t;

allow httpd_t httpd_var_www_t:file { read write };
allow httpd_t httpd_log_t:file write;
allow httpd_t httpd_etc_t:file read;
allow httpd_t self:tcp_socket bind;
```

```selinux
# httpd.fc
/var/www/html(/.*)?       gen_context(system_u:object_r:httpd_var_www_t,s0)
/var/log/httpd(/.*)?      gen_context(system_u:object_r:httpd_log_t,s0)
/etc/httpd(/.*)?          gen_context(system_u:object_r:httpd_etc_t,s0)
```

## 错误处理

### 必须检测的错误
1. **语法错误**: PML 文件格式不正确
2. **语义错误**: 引用了未定义的类型或角色
3. **冲突检测**: allow 和 deny 规则冲突
4. **路径错误**: 无效的路径模式
5. **权限错误**: 无效的权限或对象类别

### 错误信息格式
```
Error: Invalid path pattern in policy
  File: httpd_policy.csv, Line: 5
  Pattern: /var/www/[invalid
  Reason: Unclosed bracket in path pattern
  Suggestion: Use /var/www/* for wildcard matching
```


## 代码风格
- 遵循 Go 官方代码规范
- 使用有意义的变量和函数名
- 添加详细的注释（特别是映射逻辑）
- 每个公共函数都要有文档注释


## 额外说明

1. **保持简单**: 先实现核心功能，不要过度设计
2. **迭代开发**: 从最简单的用例开始，逐步增加复杂度
3. **测试驱动**: 先写测试，再写实现
4. **文档优先**: 每个模块都要有清晰的文档说明
5. **参考现有代码**: 学习 Casbin 项目中现有的代码风格和模式

## 参考资源
- Casbin 代码库: `/home/chris/opensource/casbin/`
- SELinux 策略示例: `/usr/share/selinux/` (系统中)
- 设计文档: `docs/设计文档.md`

祝开发顺利！如有问题，可以参考设计文档或查看 Casbin 现有代码。
