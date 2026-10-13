# CrowdBastion 更名与升级

[返回 README](../readme.md) · [使用说明](usage-guide.md)

项目于 2026-10-13 从 `crowdsec-1key` 更名为 **CrowdBastion**。新仓库地址为 [8bitNull/CrowdBastion](https://github.com/8bitNull/CrowdBastion)，主入口为 `crowdbastion.sh`。CrowdSec 仍是底层检测与防护引擎，相关官方命令和组件名称沿用。

## 首次下载

```bash
git clone --branch main https://github.com/8bitNull/CrowdBastion.git
cd CrowdBastion
bash crowdbastion.sh --help
sudo bash crowdbastion.sh
```

始终保留主脚本和完整 `lib/` 目录。

## 更新已有检出

进入现有项目目录，先用 `git status --short` 核对本地改动；有改动时先保存并处理，再更新：

```bash
git remote set-url origin https://github.com/8bitNull/CrowdBastion.git
git pull --ff-only
bash crowdbastion.sh --help
```

本地目录可以继续叫 `crowdsec-1key`，不需要移动目录或重新安装。旧命令 `bash install-crowdsec-1panel.sh` 仍可使用：该文件是指向 `crowdbastion.sh` 的兼容链接，两者必须一起保留。

## 已有安装的兼容性

本次更名更新项目名称、仓库地址、使用入口和显示文本。以下运行标识沿用旧版名称，以继续识别配置、复用凭据、维护互斥锁和执行回滚：

| 类型 | 沿用的名称或路径示例 |
| --- | --- |
| 配置与安装记录 | `/etc/crowdsec/crowdsec-1key-*.json`、`crowdsec-1key-*.yaml` |
| Telegram 交互机器人 | `crowdsec-1key-bot.service`、`/usr/local/lib/crowdsec-1key-bot`、`/var/lib/crowdsec-1key-bot` |
| 官方 Telegram 通知 | `crowdsec_1key_telegram`、`crowdsec-1key-telegram.yaml` |
| 维护副本与备份 | `/usr/local/lib/crowdsec-1key/current`、`/var/backups/crowdsec-1key` |
| 锁、日志及资源归属 | `crowdsec-1key*.lock`、`crowdsec-1key*.log` 及已有托管标记 |
| V2bX 仅观察规则 | `crowdsec-1key/v2bx-observation`、`crowdsec-1key/v2bx-failure-observation` 及专用 guard |

这些名称仍由当前程序使用，不应手工批量重命名。各组件的具体路径见 [管理与维护](management-guide.md)、[自定义机器人](2026-10-13-custom-telegram-bot.md)和 [V2bX 指南](v2bx-guide.md)。

更新仓库不会自动替换 cron 维护副本或已安装的机器人程序。已启用定时更新时，按 [使用说明](usage-guide.md#日常维护与更新)重新运行 `--enable-cron` 同步副本；已安装交互机器人时，按其指南执行“配置/更新并启用”。

## 历史记录

验收报告、证据文件、设计与实施计划保留当时的项目名称、脚本路径和校验值。旧名称出现在这些归档中，不代表当前仓库地址或主入口仍使用旧名称。
