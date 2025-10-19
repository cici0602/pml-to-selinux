# Mapping 模块测试说明

## 📁 文件结构

```
mapping/
├── action_mapping.go              # 动作映射实现
├── action_mapping_test.go         # 动作映射测试
├── context_mapping.go             # 上下文映射实现
├── context_mapping_test.go        # 上下文映射测试
├── filesystem_mapping.go          # 文件系统映射实现
├── filesystem_mapping_test.go     # 文件系统映射测试
├── type_mapping.go                # 类型映射实现
├── type_mapping_test.go           # 类型映射测试
└── TEST_REFACTOR_SUMMARY.md       # 重构总结文档
```

## 🧪 运行测试

### 运行所有测试
```bash
cd mapping
go test -v
```

### 查看测试覆盖率
```bash
go test -cover
```

### 生成详细的覆盖率报告
```bash
go test -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### 运行特定测试
```bash
# 测试 action_mapping
go test -v -run TestActionMapper

# 测试 type_mapping
go test -v -run TestTypeMapper

# 测试 context_mapping
go test -v -run TestPathMapper

# 测试 filesystem_mapping
go test -v -run TestFilesystemMapper
```

## 📊 测试统计

- **测试文件:** 4个
- **测试函数:** 46个
- **测试用例:** 290+个
- **代码覆盖率:** 81.3%
- **通过率:** 100%

## 🎯 测试内容

### action_mapping_test.go
测试 PML 动作到 SELinux 权限的映射功能：
- 文件操作 (read, write, execute, etc.)
- 目录操作 (search, list, add_name, etc.)
- 网络操作 (bind, connect, listen, etc.)
- 进程操作 (transition, signal, etc.)
- 自定义映射和配置管理

### type_mapping_test.go
测试路径到 SELinux 类型名的转换：
- 路径规范化和类型名生成
- 边界条件处理
- 类型属性推断
- 系统路径识别
- 类型名称清理

### context_mapping_test.go
测试路径模式到 SELinux 文件上下文模式的转换：
- 通配符模式转换
- 文件类型推断
- 设备文件处理
- 模式匹配验证

### filesystem_mapping_test.go
测试文件系统相关的 SELinux 规则生成：
- genfscon 规则生成
- fsuse 规则生成
- portcon 规则生成
- 文件系统安全属性
- 策略验证

## 📝 测试规范

### 命名约定
- 测试文件: `<source_file>_test.go`
- 测试函数: `Test<StructName>_<FunctionName>`
- 子测试: 使用描述性名称，如 "Read file", "empty path"

### 测试结构
```go
func TestMapper_Function(t *testing.T) {
    // 使用表驱动测试
    tests := []struct {
        name     string
        input    string
        expected string
    }{
        {"case 1", "input1", "expected1"},
        {"case 2", "input2", "expected2"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // 测试逻辑
        })
    }
}
```

## 🔧 开发指南

### 添加新测试
1. 确定测试所属的文件
2. 使用表驱动测试模式
3. 提供清晰的测试用例描述
4. 包含边界条件测试

### 维护测试
1. 保持测试的独立性
2. 避免测试之间的依赖
3. 及时更新测试文档
4. 确保测试通过后再提交

## 📚 相关文档
- [TEST_REFACTOR_SUMMARY.md](./TEST_REFACTOR_SUMMARY.md) - 详细的重构总结
- [重构指南.md](../docs/重构指南.md) - 项目整体重构指南
