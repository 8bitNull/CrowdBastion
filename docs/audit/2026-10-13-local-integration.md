# 本地整合与仓库整理（2026-10-13）

功能与文档提交 `03968d4` 已快进合并到本地 `main`；合并双方树均为 `588db360df567df274f1fe67b1476740d2151ee3`。本轮没有推送远端或部署生产服务。

README 从 149 行收敛为 70 行；菜单、目录结构与详细验收分别归入命令参考、文档索引及验收索引。实验补丁、历史失败及日志证据保持原始字节，补齐被日志忽略规则遗漏的归档文件。

## 验证

- 合并前完整回归：689 项，669 通过、20 按环境条件跳过、0 失败，170.845 秒，见[原始输出](local-integration-2026-10-13/premerge-unittest.txt)。
- 相同源码树合并后 V2bX 专项：68 项全部通过，3.556 秒，见[原始输出](local-integration-2026-10-13/postmerge-v2bx-tests.txt)。
- Bash/Python 语法、ShellCheck（既有排除项）及 diff 空白检查通过；索引内本地 Markdown 目标及 134 个归档文件哈希核验通过。

命令使用临时依赖环境：

```bash
PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=/tmp/v2bx-test-python-deps python3 -m unittest discover -s tests -q
PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=/tmp/v2bx-test-python-deps python3 -m unittest discover -s tests -p 'test_v2bx*.py' -q
```

## 旧工作区保全

旧 detached 工作区的 313 个文件／符号链接已完整归档到仓库外私有目录 `/data/project/script/crowdsec-1key-archives/2026-10-13-vps-repair/`，含清单、文件哈希、原始补丁与完整 Git bundle。归档 SHA256 为 `be60ffb1b730c0166e0be6431e4e7765551280a43c52619073e98181e610af38`；删除前逐项核对归档与旧工作区一致，并验证 bundle 有效。此备份仅在当前宿主机保存，不随仓库发布。

旧工作区改动中 171 个文件与现目录一致，7 个差异文件均有当前版本；比较后保留当前后续实现和文档，旧字节由私有备份保全。本轮源码测试不追加协议覆盖、生产防护、长期稳定性或 ARM64 原生验收保证。
