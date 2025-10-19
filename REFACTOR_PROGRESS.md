# PML-to-SELinux 重构进度报告

**日期**: 2025-10-19  
**状态**: 🚧 进行中

## ✅ 已完成的工作

### 1. 数据模型简化 ✅
- 重构 `models/selinux_model.go`
  - 移除 `DenyRule`、`MacroDefinition`
  - 移除MLS字段 (User, Role, Level, Context)
  - 添加 `CapabilityRule`、`PortBinding`
  - 简化 `FileContext` 结构

### 2. 新增真实场景示例 ✅
创建了三个面向应用开发者的示例:

#### `examples/webapp/` - Web应用
- 绑定端口 8080
- 读取配置文件
- 写入数据文件和日志
- 包含完整的 model.conf 和 policy.csv

#### `examples/database/` - 数据库服务
- 绑定端口 5432
- 管理数据库文件
- 创建Unix socket
- 写入日志

#### `examples/worker/` - 后台Worker
- 连接外部TCP服务
- Unix socket IPC
- 写入本地缓存

### 3. 生成器简化 ✅
- 简化 `selinux/macro_generator.go`
  - 移除复杂宏生成
  - 只保留require块生成
- 简化 `selinux/fc_generator.go`
  - 使用简化的FileContext结构
- 简化 `selinux/te_generator.go`
  - 移除deny规则生成

### 4. 编译器调整 ✅
- 更新 `compiler/generator.go`
  - 添加Capability和PortBinding支持
  - 移除DenyRule支持
  - 简化FileContext生成

## 🚧 进行中的工作

### compiler包中的遗留错误
还需要修复:
- `compiler/differ.go` - FileContext.Context引用
- `compiler/optimizer.go` - DenyRules引用

**建议**: 这两个模块(differ/optimizer)不是MVP必需功能,可以:
1. 暂时注释掉
2. 或者创建简化版本

## ❌ 尚未开始

1. **测试重构** - 更新测试用例适配新模型
2. **文档更新** - 更新README和CLI帮助
3. **端到端测试** - 验证三个示例能否生成有效的SELinux策略

## 核心设计决策

### 支持的特性 (80%场景)
✅ Domain和类型声明  
✅ 文件/目录访问控制 (read/write/execute)  
✅ TCP/UDP端口绑定  
✅ Unix socket通信  
✅ 基本capabilities (net_bind_service等)  
✅ Type transitions  
✅ File contexts  

### 不支持的特性 (20%高级场景)
❌ MLS/MCS  
❌ Deny/Neverallow规则  
❌ 复杂的宏和接口  
❌ 角色转换 (newrole)  
❌ 条件布尔值  
❌ Constraints  

## 下一步行动

### 优先级 P0 (核心功能)
1. 修复compiler/differ.go和optimizer.go
2. 确保三个新示例能编译通过
3. 手动验证生成的.te/.fc文件语法正确

### 优先级 P1 (可用性)
4. 添加基本的集成测试
5. 更新README文档
6. 添加CLI使用示例

### 优先级 P2 (完善)
7. 优化错误信息
8. 添加更多示例
9. 性能优化

## 技术债务

1. **测试覆盖率低** - 大量旧测试失效
2. **文档过时** - 需要重写README和教程
3. **代码重复** - mapping模块有冗余代码
4. **未使用的代码** - role_mapping等模块可能不再需要

## 成功标准

MVP版本的成功标准:
- [ ] 三个新示例能成功编译
- [ ] 生成的.te文件语法正确
- [ ] 生成的.fc文件格式正确
- [ ] 文档清晰说明支持和不支持的特性
- [ ] CLI能正常运行compile命令

## 估计工作量

- 修复编译错误: 2-4小时
- 测试和验证: 2-3小时  
- 文档更新: 1-2小时
- **总计**: 约1个工作日

## 参考文档

- [实现指南](docs/实现指南.md) - MVP特性清单
- [重构指南](docs/重构指南.md) - 设计原则
- [Coding Prompt](docs/coding-agent-prompt.md) - 开发原则
