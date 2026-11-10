# KeyGuard

> 本地优先的 SSH 密钥与设备指纹管理器，使用 Python + PySide6 构建。

[![Tests](https://github.com/Almost-Noob/KeyGuard/actions/workflows/tests.yml/badge.svg)](https://github.com/Almost-Noob/KeyGuard/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)

KeyGuard 将本机 SSH 身份、信任关系、设备标识和安全风险集中到一个现代桌面界面中。所有扫描、指纹计算和密钥生成都在本地完成，不上传任何数据。

![KeyGuard 概览](docs/screenshots/overview.png)

## 功能

- 扫描 `~/.ssh`：私钥、公钥、证书、`known_hosts`、`authorized_keys`、SSH 配置
- 识别 OpenSSH 版本、`ssh-agent` 和本机 `sshd` 状态
- 解析 SHA256/MD5 指纹、算法、位数、口令保护、公私钥匹配和私钥权限
- 生成 Ed25519 / RSA / ECDSA 密钥，支持口令、注释、`.pub`、ACL 限制和 `ssh-add`
- 计算设备指纹：Machine ID、Windows 硬件 ID、系统盘序列号，支持遮罩和 JSON 导出
- 安全审计：弱算法、权限过宽、重复密钥、过期证书、撤销主机密钥和危险配置
- 深色/浅色主题、搜索、筛选、复制和快捷键

## 界面

| 密钥库 | 设备指纹 |
| --- | --- |
| ![密钥库](docs/screenshots/keys.png) | ![设备指纹](docs/screenshots/device.png) |

| 生成密钥 | 浅色主题 |
| --- | --- |
| ![生成密钥](docs/screenshots/generate-dialog.png) | ![浅色主题](docs/screenshots/light-overview.png) |

> 截图由 `tools/demo_screenshots.py` 使用合成数据生成，不包含真实密钥或设备标识。

## 环境

项目直接使用仓库内的 **Conda 环境 `.conda`**，不使用 venv，也不需要启动脚本或激活环境。

- Python 3.11+（开发环境使用 3.15）
- Windows 10/11 为完整功能的主要目标平台
- OpenSSH 客户端可选，用于读取版本、`ssh-agent` 和 `sshd` 状态

## 快速开始

已有 `.conda` 环境时：

```powershell
git clone https://github.com/Almost-Noob/KeyGuard.git
cd KeyGuard
.\.conda\python.exe -m pip install -r requirements.txt
.\.conda\python.exe main.py
```

没有 `.conda` 时，先用 Conda 创建：

```powershell
conda create --prefix .conda python=3.12 -y
.\.conda\python.exe -m pip install -r requirements.txt
.\.conda\python.exe main.py
```

Linux / macOS：

```bash
conda create --prefix .conda python=3.12 -y
.conda/bin/python -m pip install -r requirements.txt
.conda/bin/python main.py
```

### 命令参数

```text
--ssh-dir PATH     指定要扫描的 SSH 目录（默认 ~/.ssh）
--theme dark|light 指定主题
```

```powershell
.\.conda\python.exe main.py --ssh-dir C:\Users\demo\.ssh --theme light
```

## 文档

- [开发文档](docs/DEVELOPMENT.md)：架构、模块、SSH 解析、设备指纹算法、UI 约定、测试和发布流程
- [安全策略](SECURITY.md)：数据边界、密钥处理、威胁模型和漏洞报告
- [贡献指南](CONTRIBUTING.md)：开发环境、代码约定和 PR 流程
- [变更记录](CHANGELOG.md)

## 项目结构

```text
.
├── main.py
├── app/
│   ├── core/          # SSH 扫描、解析、审计、密钥生成、设备指纹
│   └── ui/            # 主窗口、主题、组件、页面、对话框
├── assets/            # Logo 和图标
├── docs/              # 开发文档与合成截图
├── tests/             # 单元测试和 UI smoke tests
├── tools/             # 文档截图生成器
├── requirements.txt
└── pyproject.toml     # Ruff 配置
```

## 开发与测试

```powershell
.\.conda\python.exe -m pip install -r requirements-dev.txt
.\.conda\python.exe -m unittest discover -s tests -q
.\.conda\python.exe -m ruff check main.py app tests tools
```

UI 测试建议使用 offscreen：

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
.\.conda\python.exe -m unittest discover -s tests -v
```

## 安全与隐私

- 所有扫描、指纹计算和密钥生成均在本地完成，无遥测或云端同步
- 私钥内容不会显示在 UI 中；只解析结构以计算指纹
- 设备指纹默认遮罩敏感字段；导出 JSON 包含原始硬件标识，请按敏感数据处理
- 生成密钥后尝试用 Windows ACL 将私钥限制为当前用户、SYSTEM 和 Administrators
- 不要提交真实私钥、设备指纹或 `.ssh` 目录

详见 [SECURITY.md](SECURITY.md)。

## 常见问题

### Git 报 `Permission denied (publickey)`

确认公钥已添加到 GitHub，并在 `~/.ssh/config` 中显式指定 `github.com` 使用的 `IdentityFile`。Git for Windows 自带的 `ssh.exe` 可能看不到 Windows `ssh-agent` 中的密钥。

### `ssh-agent` 未运行

Windows 管理员 PowerShell：

```powershell
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent
ssh-add $env:USERPROFILE\.ssh\id_ed25519
ssh-add -l
```

## License

[MIT](LICENSE) © 2026 Almost-Noob
