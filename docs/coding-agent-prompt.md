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

可以参考以下模块化结构组织代码：

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

## 代码风格
- 遵循 Go 官方代码规范
- 使用有意义的变量和函数名
- 添加详细的注释（特别是映射逻辑）
- 每个公共函数都要有文档注释

## 额外说明

1. **保持简单**: 先实现核心功能，不要过度设计
2. **迭代开发**: 从最简单的用例开始，逐步增加复杂度
3. **测试驱动**: 先写测试，再写实现，冗余测试需要合并
4. **文档优先**: 每个模块都要有清晰的文档说明
5. **参考现有代码**: 学习 Casbin 项目中现有的代码风格和模式
6. 完全兼容 Casbin 官方 PML

## 参考资源
- Casbin 代码库: `/home/chris/opensource/casbin/`