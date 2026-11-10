# Security Policy

## 支持范围

KeyGuard 是一个本地桌面应用，不提供网络服务，也不收集遥测数据。

| 版本 | 支持 |
| --- | --- |
| 1.x | ✅ 安全修复 |

## 报告安全问题

请通过 GitHub 的私密漏洞报告功能联系维护者：

<https://github.com/Almost-Noob/KeyGuard/security/advisories/new>

请勿在公开 issue 中披露以下内容：

- 真实私钥、口令或 `authorized_keys` 内容
- 未脱敏的设备指纹或硬件序列号
- 可用于定位具体机器的路径、主机名或网络信息
- 尚未修复的利用细节

报告时请提供：受影响版本、操作系统、复现步骤、影响范围和（如适用）最小化 PoC。

## 数据与隐私

- 扫描、密钥生成、设备指纹计算均在本地完成
- 不上传密钥、指纹、配置或扫描结果
- 私钥内容不会显示在 UI 中，也不会写入日志
- 设备指纹页面默认遮罩 Machine ID、硬件 ID、序列号和 MAC
- 导出的设备指纹 JSON 包含原始硬件标识，应由用户自行按敏感数据保管

## 密钥处理

- 私钥通过 `cryptography` 在内存中生成，以 OpenSSH 格式写入
- Windows 上尝试用 `icacls` 将私钥权限限制为当前用户、SYSTEM 和 Administrators
- 非 Windows 平台使用 `chmod 600`
- 有口令的私钥使用 bcrypt KDF；无口令私钥以明文私钥文件形式保存
- KeyGuard 不会自动删除或覆盖已有密钥

## 威胁模型

KeyGuard 不能防御：

- 已取得当前用户权限的恶意软件读取私钥文件
- 内存取证或键盘记录
- 被篡改的操作系统、OpenSSH 或 Python 运行时
- 用户把私钥/导出指纹提交到公开仓库
- 远端主机被攻陷后滥用 `ForwardAgent yes`

建议：

- 为私钥设置口令，并使用 `ssh-agent`
- 不要对不可信主机启用 agent forwarding
- 定期轮换密钥并清理旧的 `authorized_keys`
- 在分享截图或导出文件前移除敏感标识

## 依赖安全

项目固定主要依赖版本（见 `requirements.txt`）。建议用户在受控环境中安装，并定期检查依赖更新。CI 会在 Windows 上运行测试；依赖漏洞报告同样欢迎通过私密渠道提交。

## 低完整性/沙箱环境

如果 KeyGuard 在受限沙箱或低完整性进程中运行，Windows 可能阻止写入 `~/.ssh`。这是运行环境的限制，不是权限检查漏洞。请从普通桌面或终端启动应用。
