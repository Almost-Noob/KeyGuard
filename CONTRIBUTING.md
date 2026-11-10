# Contributing to KeyGuard

感谢你愿意改进 KeyGuard。请保持改动聚焦、可测试，并且不引入真实用户数据。

## 开发环境

项目使用仓库内的 Conda 环境 `.conda`，不使用 venv。

```powershell
git clone https://github.com/Almost-Noob/KeyGuard.git
cd KeyGuard

# 如果仓库中已经有可用的 .conda 环境，跳过下一行
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

不需要激活环境；直接调用 `.conda` 中的解释器即可。

## 提交前检查

```powershell
.\.conda\python.exe -m unittest discover -s tests -q
```

如果改动了 UI，请重新生成合成截图：

```powershell
.\.conda\python.exe tools\demo_screenshots.py
```

并检查截图没有包含真实用户名、主机名、路径、指纹或密钥。

## 代码约定

- Python 3.11+，使用类型标注
- `app/core` 不允许导入 PySide6
- UI 文案使用中文，标识符和注释使用英文
- 不把口令、私钥内容或原始设备标识写入日志
- 文件路径使用 `pathlib.Path`
- 新增审计规则时给出可操作的 remediation
- 修改扫描器时考虑权限不足、文件损坏和服务不存在的降级路径

## Pull Request

1. Fork 仓库并从 `main` 创建分支
2. 保持提交信息清晰（例如 `feat: add certificate expiry audit`）
3. 在 PR 描述中说明动机、行为和测试方式
4. UI 改动请附截图（合成数据）
5. 不要提交 `.conda`、`.tmp`、真实 `.ssh` 内容或任何密钥

## 安全问题

请勿通过公开 issue 报告安全问题，使用 [SECURITY.md](SECURITY.md) 中的私密渠道。
