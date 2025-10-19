# PML-to-SELinux 重构状态

## 当前状态 (2025-10-19)

本项目正在进行重大重构,目标是简化为面向**应用开发者和系统管理员**的实用工具。

### 重构目标

遵循"二八原则" - 用最小复杂度覆盖 80% 常见场景:
- ✅ 文件/目录读写
- ✅ 网络端口绑定
- ✅ Unix socket 通信  
- ✅ 基本 capability
- ✅ Domain 和 type transition
- ❌ MLS/MCS (已删除)
- ❌ 复杂角色转换 (已删除)
- ❌ Deny rules (暂时移除)
- ❌ 复杂宏 (暂时移除)

### 新示例

已创建三个真实场景示例:
1. **webapp** - Web 应用 (端口 8080, 读配置, 写数据, 写日志)
2. **database** - 数据库服务 (端口 5432, 管理数据文件, Unix socket)
3. **worker** - 后台任务 (连接外部服务, 写缓存, IPC)

### 编译状态

⚠️ 当前编译未通过 - 正在修复以下模块:
- `selinux/macro_generator.go` - 需要移除 MacroDefinition 引用
- `selinux/te_generator.go` - 需要移除 DenyRules 引用
- `compiler/differ.go` - 需要适配新的 FileContext 结构
- `compiler/optimizer.go` - 需要移除 DenyRules 引用

### 下一步

1. 修复编译错误
2. 简化生成器 (te/fc/if)
3. 更新测试用例
4. 更新主 README

### 使用新示例

```bash
# 编译 web 应用示例
pml2selinux compile -m examples/webapp/model.conf -p examples/webapp/policy.csv -o output/webapp

# 编译数据库示例  
pml2selinux compile -m examples/database/model.conf -p examples/database/policy.csv -o output/database

# 编译 worker 示例
pml2selinux compile -m examples/worker/model.conf -p examples/worker/policy.csv -o output/worker
```

## 参考文档

- `docs/实现指南.md` - 详细的实现指南
- `docs/重构指南.md` - 重构分析报告
- `docs/coding-agent-prompt.md` - 开发原则
