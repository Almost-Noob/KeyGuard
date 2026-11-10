# KeyGuard 开发文档

本文档面向维护者和贡献者，说明 KeyGuard 的模块边界、数据流、SSH 解析细节、设备指纹算法和 UI 约定。

## 1. 技术栈

| 层 | 技术 |
| --- | --- |
| 语言 | Python 3.11+ |
| GUI | PySide6（Qt 6 Widgets） |
| 图标 | QtAwesome / Material Design Icons |
| 密钥生成 | `cryptography`（OpenSSH 序列化，bcrypt 加密） |
| 系统信息 | `psutil`、Windows Registry、CIM/WMI（带注册表兜底） |
| 测试 | Python `unittest` + PySide6 offscreen |

### 环境

项目直接使用仓库内的 **Conda 环境 `.conda`**，不使用 venv：

```powershell
conda create --prefix .conda python=3.12 -y
.\.conda\python.exe -m pip install -r requirements.txt
.\.conda\python.exe main.py
```

已有 `.conda` 时跳过创建步骤。直接调用 `.conda\python.exe`，不需要激活环境。

目标平台是 Windows 10/11；SSH 扫描和密钥生成逻辑尽量保持跨平台。Windows 专属能力包括：

- 读取 Machine GUID、ComputerHardwareId
- 读取卷序列号
- `icacls` 检查/修复私钥权限
- `sc.exe` 查询 `sshd` 服务
- DWM 深色标题栏

## 2. 目录结构

```text
main.py
app/
  core/
    ssh.py        # SSH 领域模型、扫描、解析、审计、密钥生成
    device.py     # 设备指纹采集和稳定 ID 计算
  ui/
    main_window.py
    theme.py
    widgets.py
    dialogs.py
    helpers.py
    pages/
      overview.py
      keys.py
      hosts.py
      config.py
      device.py
      audit.py
tests/
  test_core.py
  test_ui.py
tools/
  demo_screenshots.py
```

`app/core` 不导入 PySide6，可以独立在终端或测试中调用。`app/ui` 只负责展示和交互。

## 3. 启动与数据流

```text
main.py
  └── QApplication + theme
        └── MainWindow
              ├── scan_system(~/.ssh)         # 同步扫描
              ├── collect_device_fingerprint() # 首次构建页面时采集
              └── QStackedWidget
                    ├── OverviewPage
                    ├── KeysPage
                    ├── HostsPage
                    ├── ConfigPage
                    ├── DevicePage
                    └── AuditPage
```

扫描结果是一个不可变快照式的 `ScanResult`。刷新时重新扫描并重建所有页面，避免页面状态和文件系统状态不一致。密钥选择会通过 `MainWindow._selected_key` 保留；主题切换只重建 UI，不重新扫描。

生成密钥后：

```text
GenerateKeyDialog
  └── generate_ssh_key()
        ├── cryptography 生成私钥
        ├── 写 OpenSSH 私钥（600 / ACL）
        ├── 写 .pub
        └── 可选 ssh-add
  └── MainWindow.refresh_scan()
```

## 4. SSH 扫描

入口：

```python
from app.core.ssh import scan_system

result = scan_system("C:/Users/demo/.ssh")
```

`scan_system()` 依次执行：

1. 定位 `ssh.exe`、`ssh-keygen.exe`、`ssh-add.exe`
2. 读取 OpenSSH 版本
3. 扫描 SSH 目录中的私钥、公钥和证书
4. 解析 `known_hosts`、`known_hosts.old`
5. 解析用户和系统 `ssh_config`
6. 查询 `ssh-agent`
7. 查询 `sshd` 服务、`sshd_config`、主机密钥
8. 解析 `authorized_keys` / `administrators_authorized_keys`
9. 运行审计规则，计算评分

扫描过程对单个文件/服务的错误采取降级策略：记录到 `ScanResult.errors`，继续扫描其他部分。

### 4.1 OpenSSH 公钥格式

公钥行结构：

```text
[options] key-type base64-blob [comment]
```

解析逻辑在 `parse_public_key_line()`：

- 逐 token 尝试 base64 解码
- 从 blob 的第一个 SSH string 读取 key type
- 计算 `SHA256(base64(blob))`，生成 `SHA256:...`
- 同时生成 MD5 指纹
- RSA 读取 modulus 的 bit length
- ECDSA 从曲线名读取 256/384/521
- Ed25519 固定 256
- 支持 `sk-*` 安全密钥和 `*-cert-v01@openssh.com` 证书
- 支持 authorized_keys 前置 options

`options` 仅用于展示和审计，不会执行。

### 4.2 OpenSSH 私钥

私钥格式有两种：

1. **OpenSSH 新格式**

```text
-----BEGIN OPENSSH PRIVATE KEY-----
base64(
  "openssh-key-v1\0"
  ciphername
  kdfname
  kdfoptions
  nkeys
  public-key-blob
  encrypted-private-section
)
```

KeyGuard 只解析明文的头部和公钥部分，不尝试解密私钥内容；这样可以判断算法、位数、是否加密，并得到公钥指纹。

2. **传统 PEM**

- `RSA PRIVATE KEY`
- `DSA PRIVATE KEY`
- `EC PRIVATE KEY`
- `PRIVATE KEY` / `ENCRYPTED PRIVATE KEY`

未加密 PEM 通过 `cryptography` 读取公钥；加密 PEM 只根据头部标记为加密。

私钥文件永远不会把私钥内容传给 UI。

### 4.3 known_hosts

支持格式：

```text
[host,]... key-type base64 [comment]
@cert-authority host key-type base64
@revoked host key-type base64
|1|base64-sha1|base64-hash key-type base64
```

- 逗号分隔的多个 host 会拆开
- 哈希主机名保留原样，不尝试反解
- `@revoked` 计为严重审计项
- `@cert-authority` 显示为 CA 记录

### 4.4 SSH config

解析 `~/.ssh/config` 和系统 `ssh_config`：

- `Host`：支持多个别名和通配符
- `Include`：相对路径、绝对路径、`~`、glob，递归深度限制 4
- `Match`：进入后跳过后续选项，直到下一个 `Host`
- 重复的 `IdentityFile` 会保留为列表
- 用户配置优先于系统配置

`Host *` 会作为通配规则保留，参与安全审计（例如通配的 `StrictHostKeyChecking no`）。

### 4.5 authorized_keys

- 复用 `parse_public_key_line()`，支持前置 options
- 记录来源文件和行号
- `options` 非空时标记为“带限制”
- 弱算法公钥会进入审计

## 5. 审计与评分

审计规则集中在 `_build_findings()`，返回 `Finding`：

```python
@dataclass
class Finding:
    severity: str  # critical | warning | info
    title: str
    detail: str
    remediation: str
    category: str
```

评分：

```text
score = max(8, 100 - critical * 24 - warning * 8)
```

等级：

| 分数 | 等级 |
| --- | --- |
| >= 90 | 优秀 |
| >= 75 | 良好 |
| >= 60 | 需关注 |
| < 60 | 有风险 |

增加规则时：

1. 在 `_build_findings()` 中构造 `Finding`
2. 给出可操作的中文 remediation
3. 避免一个文件产生大量重复项；同一类问题可以聚合
4. 在 `tests/test_core.py` 添加覆盖

## 6. 设备指纹

入口：

```python
from app.core.device import collect_device_fingerprint

fp = collect_device_fingerprint()
print(fp.device_id, fp.short_id)
```

采集顺序：

1. Windows CIM/WMI：ComputerSystem、BIOS、BaseBoard、Processor、OperatingSystem、DiskDrive、ComputerSystemProduct
2. 注册表兜底：`HARDWARE\DESCRIPTION\System\BIOS`、`CentralProcessor\0`、`CurrentVersion`、`Control\SystemInformation`
3. `winreg` 读取 MachineGuid
4. `GetVolumeInformationW` 读取系统盘卷序列号
5. `psutil` 读取内存、CPU、网卡
6. Linux/macOS fallback：`/etc/machine-id`、`/sys/class/dmi/id/*`

### 6.1 主指纹算法

参与计算的稳定字段（按固定顺序）：

```text
machine_guid
computer_hardware_id
smbios_uuid
bios_serial
board_serial
cpu_id
system_volume
```

规范化：

```python
canonical = "\n".join(f"{key}={value.strip().upper()}" for key, value in stable_pairs)
device_id = sha256(canonical.encode("utf-8")).hexdigest()
```

短 ID：

```python
short = base32(bytes.fromhex(device_id))[:16]
short_id = "-".join(short[i:i+4] for i in range(0, 16, 4))
```

如果稳定字段少于 2 个，回退到 hostname + OS + architecture，并在 UI 中显示稳定性警告。

MAC、BIOS 版本、主板型号等只用于展示，不参与主指纹，避免网络/固件变化导致指纹漂移。

### 6.2 隐私

- `FingerprintComponent.sensitive` 控制默认遮罩
- UI 只有勾选“显示敏感信息”后才允许复制原始值
- 导出的 JSON 包含原始值，README/SECURITY 已明确提示

## 7. UI 架构

### 7.1 主题

`app/ui/theme.py` 定义：

- `DARK` / `LIGHT` 设计令牌
- QSS 模板（`string.Template`，`$token` 占位）
- `apply_theme()`：设置 Fusion style、QSS、QPalette
- `base_font()`：Segoe UI Variable / Microsoft YaHei UI 字体栈

新增颜色时同时补齐两套 token，避免 `KeyError`。QSS 中 8 位颜色使用 `#AARRGGBB`。

### 7.2 通用组件

`app/ui/widgets.py`：

- `IconBadge`、`Badge`、`Card`、`SectionCard`、`StatCard`
- `KeyRow`、`HostRow`、`FindingRow`
- `ScoreRing`（QPainter 绘制评分环）
- `Toast`（淡入淡出通知）
- `ScrollPage`（统一滚动页面基类）
- `elide_middle` / `KeyValueRow`（长路径省略 + tooltip + 复制）

### 7.3 页面

每个页面暴露：

```python
TITLE = "密钥库"
SUBTITLE = "管理系统中的 SSH 密钥对与公钥授权"
```

页面通常接收一个 `ScanResult` 快照，构造时一次性渲染。需要交互的页面使用 PySide6 Signal 向外通知，不直接操作 `MainWindow`。

`MainWindow` 负责：

- 侧边栏/页头/导航
- 扫描和刷新
- 页面重建
- 主题切换
- 生成密钥对话框
- 全局 Toast、快捷键、窗口几何持久化

### 7.4 添加页面

1. 在 `app/ui/pages/` 新建 `QWidget` 或 `ScrollPage`
2. 实现 `TITLE`、`SUBTITLE`
3. 在 `MainWindow.PAGE_SPECS` 增加标题、副标题、图标
4. 在 `_build_pages()` 实例化并加入 `self.stack`
5. 更新快捷键数量（目前 Ctrl+1..6）
6. 更新截图脚本的页面列表

## 8. 测试

```powershell
.\.conda\python.exe -m unittest discover -s tests -q
```

测试分层：

- `tests/test_core.py`：公钥/私钥解析、密钥生成、扫描、config、known_hosts、authorized_keys、设备指纹
- `tests/test_ui.py`：offscreen 创建主窗口、六个页面、主题切换、生成对话框校验

测试数据写到 `.tmp/unit-*`，测试结束清理。不要使用真实用户密钥或真实设备标识。

## 9. 文档截图

截图由合成数据生成，不读取真实 SSH 目录或硬件：

```powershell
.\.conda\python.exe tools\demo_screenshots.py
```

输出到 `docs/screenshots/`。脚本使用 `MainWindow(scan=..., device=...)` 注入演示数据。

修改 UI 后请重新生成截图，并确认没有真实用户名、主机名、路径或指纹。

## 10. 打包（可选）

当前没有强制打包流程。临时构建可以使用 PyInstaller：

```powershell
.\.conda\python.exe -m pip install pyinstaller
.\.conda\python.exe -m PyInstaller --noconfirm --windowed --name KeyGuard --add-data "assets;assets" main.py
```

注意：

- `assets` 路径通过 `Path(__file__)` 推导；打包后需要确认资源路径
- PyInstaller 产物未纳入 CI
- 分发前请验证 Qt 插件、SVG 图标和 `cryptography` 的 OpenSSL DLL

## 11. 编码约定

- Python 3.11+ 类型标注
- 4 空格缩进，行宽尽量 120
- core 层不导入 PySide6
- 不把异常直接抛到 Qt 事件循环；UI 层捕获并显示可读错误
- 文件路径使用 `pathlib.Path`
- 不在日志/异常中输出口令
- 新增敏感字段时同时处理遮罩、复制和导出策略

## 12. 常见问题

### 低完整性进程无法写 `~/.ssh`

如果工作区文件被 Windows 标记为 Low Mandatory Level，Python 进程会以低完整性运行，无法写入普通用户目录。表现为 PowerShell 可以写 `.ssh`，但 Python 报 `Permission denied`。

处理：从普通桌面/终端启动 KeyGuard，或由管理员将 `.conda\python.exe` 的完整性级别设为 Medium。这个限制来自运行环境，不是 KeyGuard 的文件权限逻辑。

### Git for Windows 看不到 Windows ssh-agent

Git for Windows 可能使用自带的 `ssh.exe`，与 Windows OpenSSH 的 agent 管道不共享。推荐在 `~/.ssh/config` 中显式指定：

```sshconfig
Host github.com
  HostName github.com
  User git
  IdentityFile ~/.ssh/github
  IdentitiesOnly yes
```

这样 Windows OpenSSH 和 Git 自带 SSH 都能直接使用密钥文件。

### 启动方式与 PowerShell 执行策略

直接运行 `.\.conda\python.exe main.py`，不需要激活 conda 环境，因此不受 PowerShell 的 `Activate.ps1` 执行策略影响。工作区 `.vscode/settings.json` 已关闭自动激活，并直接指向 `.conda\python.exe`。

## 13. 发布流程

1. 更新 `README.md` / `CHANGELOG.md`
2. 运行完整测试
3. 重新生成合成截图
4. 确认 `git status` 不包含 `.conda`、`.tmp`、真实密钥
5. 创建 tag（例如 `v1.0.0`）
6. 推送 `main` 和 tag
7. 在 GitHub Release 中附上变更说明

发布前检查：

```powershell
git status --short
.\.conda\python.exe -m unittest discover -s tests -q
```
