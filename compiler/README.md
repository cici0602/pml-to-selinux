# Compiler Package - PML Parser & Analyzer

PML (Policy Modeling Language) 编译器包，提供 Casbin PML 文件的解析和语义分析功能。

## 功能特性

### 1. PML 解析器 (Parser)

- ✅ 解析 `.conf` 模型文件（request_definition, policy_definition, role_definition, matchers, policy_effect）
- ✅ 解析 `.csv` 策略文件（policy 规则和 role 关系）
- ✅ 支持注释（# 开头）和空行
- ✅ 详细的错误报告（包含文件名和行号）
- ✅ 灵活的 CSV 解析（支持引号、逗号转义）

### 2. 语义分析器 (Analyzer)

- ✅ 模型完整性验证
- ✅ 策略规则合法性检查
- ✅ Allow/Deny 规则冲突检测
- ✅ 策略统计信息生成
- ✅ 路径模式重叠检测

## 快速开始

### 安装

```bash
go get github.com/cici0602/pml-to-selinux/compiler
```

### 基本使用

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/cici0602/pml-to-selinux/compiler"
)

func main() {
    // 1. 创建解析器
    parser := compiler.NewParser("model.conf", "policy.csv")
    
    // 2. 解析 PML 文件
    pml, err := parser.Parse()
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Parsed %d policies\n", len(pml.Policies))
    
    // 3. 创建分析器
    analyzer := compiler.NewAnalyzer(pml)
    
    // 4. 执行语义分析
    err = analyzer.Analyze()
    if err != nil {
        log.Fatal(err)
    }
    
    // 5. 获取统计信息
    stats := analyzer.GetStats()
    fmt.Printf("Total Policies: %d\n", stats.TotalPolicies)
    fmt.Printf("Allow Rules: %d\n", stats.AllowRules)
    fmt.Printf("Deny Rules: %d\n", stats.DenyRules)
    fmt.Printf("Conflicts: %d\n", stats.Conflicts)
}
```

## API 文档

### Parser

#### NewParser

```go
func NewParser(modelPath, policyPath string) *Parser
```

创建一个新的解析器实例。

**参数：**
- `modelPath`: PML 模型文件路径（.conf）
- `policyPath`: 策略文件路径（.csv）

**返回：**
- `*Parser`: 解析器实例

#### Parse

```go
func (p *Parser) Parse() (*models.ParsedPML, error)
```

解析模型和策略文件。

**返回：**
- `*models.ParsedPML`: 解析后的 PML 数据
- `error`: 解析错误（如果有）

### Analyzer

#### NewAnalyzer

```go
func NewAnalyzer(pml *models.ParsedPML) *Analyzer
```

创建一个新的分析器实例。

**参数：**
- `pml`: 已解析的 PML 数据

**返回：**
- `*Analyzer`: 分析器实例

#### Analyze

```go
func (a *Analyzer) Analyze() error
```

执行完整的语义分析。

**返回：**
- `error`: 分析错误（如果有）

#### GetStats

```go
func (a *Analyzer) GetStats() *AnalysisStats
```

获取分析统计信息。

**返回：**
- `*AnalysisStats`: 统计信息结构

### AnalysisStats 结构

```go
type AnalysisStats struct {
    TotalPolicies    int            // 总策略数
    AllowRules       int            // Allow 规则数
    DenyRules        int            // Deny 规则数
    UniqueSubjects   int            // 唯一主体数
    UniqueObjects    int            // 唯一对象数
    UniqueActions    int            // 唯一动作数
    Conflicts        int            // 冲突数
    RoleRelations    int            // 角色关系数
    SubjectTypes     map[string]int // 按主体统计
    ObjectPatterns   map[string]int // 按对象统计
    ActionTypes      map[string]int // 按动作统计
}
```

## 示例

### 运行演示程序

```bash
# 解析 httpd 示例
go run tests/demo_parser.go examples/httpd/httpd_model.conf examples/httpd/httpd_policy.csv
```

**输出示例：**
```
=== PML Parser and Analyzer Demo ===
Model file: examples/httpd/httpd_model.conf
Policy file: examples/httpd/httpd_policy.csv

1. Parsing PML files...
✓ Successfully parsed model and policies

2. Model Information:
   Request Definition: map[r:[sub obj act class]]
   Policy Definition: map[p:[sub obj act class eft]]
   Matchers: r.sub == p.sub && matchPath(r.obj, p.obj) && r.act == p.act && r.class == p.class
   Effect: some(where (p.eft == allow)) && !some(where (p.eft == deny))

3. Analyzing policies...
✓ Analysis completed

4. Policy Statistics:
   Total Policies: 15
   Allow Rules: 13
   Deny Rules: 2
   Unique Subjects: 1
   Unique Objects: 8
   Unique Actions: 8
   Conflicts Detected: 0

5. Rules by Subject:
   httpd_t: 15 rules

6. Rules by Action:
   read: 4 rules
   write: 4 rules
   getattr: 2 rules
   ...

7. Sample Policies (first 5):
   httpd_t -> /var/www/html/* : read on file [allow]
   httpd_t -> /var/www/html/* : write on file [allow]
   httpd_t -> /var/www/html/* : getattr on file [allow]
   httpd_t -> /var/log/httpd/* : write on file [allow]
   httpd_t -> /var/log/httpd/* : append on file [allow]
   ... and 10 more policies

✓ Demo completed successfully!
```

### 错误处理示例

```go
parser := compiler.NewParser("model.conf", "policy.csv")
pml, err := parser.Parse()
if err != nil {
    if parseErr, ok := err.(*compiler.ParseError); ok {
        // 获取详细的错误信息
        fmt.Printf("Parse error in %s at line %d: %s\n", 
            parseErr.File, parseErr.Line, parseErr.Message)
    } else {
        fmt.Printf("Error: %v\n", err)
    }
    return
}
```

### 冲突检测示例

```go
analyzer := compiler.NewAnalyzer(pml)
err := analyzer.Analyze()
if err != nil {
    log.Fatal(err)
}

stats := analyzer.GetStats()
if stats.Conflicts > 0 {
    fmt.Printf("Warning: Found %d policy conflicts\n", stats.Conflicts)
    // 冲突会作为警告输出到 stdout
}
```

## 测试

### 运行所有测试

```bash
go test ./compiler/... -v
```

### 运行特定测试

```bash
# 测试解析器
go test ./compiler -run TestParseModel -v

# 测试分析器
go test ./compiler -run TestValidateModel -v

# 测试冲突检测
go test ./compiler -run TestDetectConflicts -v
```

### 测试覆盖率

```bash
go test ./compiler/... -cover
```

## PML 文件格式

### 模型文件 (.conf)

```ini
[request_definition]
r = sub, obj, act, class

[policy_definition]
p = sub, obj, act, class, eft

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = r.sub == p.sub && matchPath(r.obj, p.obj) && r.act == p.act && r.class == p.class
```

### 策略文件 (.csv)

```csv
# 策略规则
p, httpd_t, /var/www/*, read, file, allow
p, httpd_t, /var/www/*, write, file, allow
p, httpd_t, /usr/bin/*, write, file, deny

# 角色关系
g, user_u, user_r
g2, httpd_t, web_domain
```

## 支持的功能

### 解析器
- ✅ Section 解析（request_definition, policy_definition, role_definition, matchers, policy_effect）
- ✅ 注释支持（# 开头的行）
- ✅ 空行处理
- ✅ CSV 格式支持（包括引号和逗号转义）
- ✅ 错误定位（文件名 + 行号）

### 分析器
- ✅ 模型验证（检查必需的 sections）
- ✅ 策略验证（字段完整性、值合法性）
- ✅ 路径模式验证
- ✅ Effect 值验证（allow/deny）
- ✅ 冲突检测（allow vs deny）
- ✅ 路径重叠检测
- ✅ 统计信息生成

## 已知限制

1. 暂不支持复杂的正则表达式路径模式
2. 冲突检测基于简单的路径重叠逻辑
3. 暂不支持动态策略加载

