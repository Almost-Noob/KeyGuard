"""Generate documentation screenshots from synthetic, non-personal data.

Run from the repository root with the workspace conda interpreter:

    .\\.conda\\python.exe tools\\demo_screenshots.py
"""

from __future__ import annotations

import base64
import hashlib
import sys
from datetime import datetime
from pathlib import Path

from PySide6.QtWidgets import QApplication

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.device import DeviceFingerprint, FingerprintComponent  # noqa: E402
from app.core.ssh import (  # noqa: E402
    AgentKey,
    AgentStatus,
    AuthorizedKeyEntry,
    Finding,
    HostConfig,
    KeyRecord,
    KnownHostEntry,
    ScanResult,
    ServerInfo,
)
from app.ui.dialogs import GenerateKeyDialog  # noqa: E402
from app.ui.main_window import MainWindow  # noqa: E402
from app.ui.theme import apply_theme, base_font  # noqa: E402

OUT = ROOT / "docs" / "screenshots"
SSH_DIR = r"C:\Users\demo\.ssh"
WHEN = datetime(2026, 11, 10, 20, 30)


def fingerprint(label: str) -> str:
    digest = hashlib.sha256(label.encode("utf-8")).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def public_key(label: str, comment: str = "demo@workstation") -> str:
    body = base64.b64encode(hashlib.sha256(label.encode("utf-8")).digest()).decode("ascii").rstrip("=")
    return f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{body} {comment}"


def demo_scan() -> ScanResult:
    ed = KeyRecord(
        name="id_ed25519_work",
        private_path=rf"{SSH_DIR}\id_ed25519_work",
        public_path=rf"{SSH_DIR}\id_ed25519_work.pub",
        key_type="ssh-ed25519",
        bits=256,
        fingerprint=fingerprint("demo-ed25519"),
        fingerprint_md5="MD5:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
        comment="demo@workstation",
        public_key=public_key("demo-ed25519"),
        encrypted=True,
        has_private=True,
        has_public=True,
        modified=datetime(2026, 11, 10, 20, 12),
        size=411,
        source="私钥文件",
    )
    rsa = KeyRecord(
        name="id_rsa_legacy",
        private_path=rf"{SSH_DIR}\id_rsa_legacy",
        public_path=rf"{SSH_DIR}\id_rsa_legacy.pub",
        key_type="ssh-rsa",
        bits=2048,
        fingerprint=fingerprint("demo-rsa"),
        fingerprint_md5="MD5:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00",
        comment="legacy-build",
        public_key=public_key("demo-rsa", "legacy-build"),
        encrypted=False,
        has_private=True,
        has_public=True,
        modified=datetime(2026, 11, 9, 18, 8),
        size=1679,
        source="私钥文件",
    )
    ecdsa = KeyRecord(
        name="id_ecdsa_cloud",
        private_path=rf"{SSH_DIR}\id_ecdsa_cloud",
        public_path=rf"{SSH_DIR}\id_ecdsa_cloud.pub",
        key_type="ecdsa-sha2-nistp384",
        bits=384,
        fingerprint=fingerprint("demo-ecdsa"),
        fingerprint_md5="MD5:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11",
        comment="cloud-prod",
        public_key=public_key("demo-ecdsa", "cloud-prod"),
        encrypted=True,
        has_private=True,
        has_public=True,
        modified=datetime(2026, 11, 8, 9, 21),
        size=622,
        source="私钥文件",
    )
    deploy = KeyRecord(
        name="deploy_key",
        public_path=rf"{SSH_DIR}\deploy_key.pub",
        key_type="ssh-ed25519",
        bits=256,
        fingerprint=fingerprint("demo-deploy"),
        fingerprint_md5="MD5:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22",
        comment="deploy@ci",
        public_key=public_key("demo-deploy", "deploy@ci"),
        has_public=True,
        modified=datetime(2026, 11, 7, 12, 0),
        size=101,
        source="仅公钥",
    )

    known_hosts = [
        KnownHostEntry(["github.com"], "ssh-ed25519", fingerprint("host-github"), 1, source="known_hosts", bits=256),
        KnownHostEntry(["prod.example.com"], "ssh-ed25519", fingerprint("host-prod"), 2, source="known_hosts", bits=256),
        KnownHostEntry(["10.20.0.15"], "ssh-rsa", fingerprint("host-legacy"), 3, marker="@cert-authority", source="known_hosts", bits=3072),
    ]

    hosts = [
        HostConfig(
            alias="github.com",
            hostname="github.com",
            user="git",
            identity_files=[rf"{SSH_DIR}\id_ed25519_work"],
            options={"identitiesonly": "yes"},
            source=rf"{SSH_DIR}\config",
            line=4,
        ),
        HostConfig(
            alias="prod-web",
            hostname="10.20.0.15",
            user="deploy",
            port="2222",
            identity_files=[rf"{SSH_DIR}\id_ecdsa_cloud"],
            proxy_jump="bastion",
            options={"serveraliveinterval": "30"},
            source=rf"{SSH_DIR}\config",
            line=10,
        ),
        HostConfig(
            alias="bastion",
            hostname="bastion.example.com",
            user="ops",
            port="2200",
            identity_files=[rf"{SSH_DIR}\id_ed25519_work"],
            source=rf"{SSH_DIR}\config",
            line=18,
        ),
        HostConfig(
            alias="demo-box",
            hostname="192.168.1.50",
            user="demo",
            source=rf"{SSH_DIR}\config",
            line=24,
        ),
    ]

    findings = [
        Finding(
            "warning",
            "id_rsa_legacy 的 RSA 密钥为 2048 位",
            "2048 位 RSA 仍可用，但 3072 位以上更符合当前建议。",
            "在方便时轮换为 3072 位或 4096 位 RSA，或改用 Ed25519。",
            "密钥",
        ),
        Finding(
            "warning",
            "prod-web 启用了 Agent 转发",
            "将本地 ssh-agent 转发到远端后，拥有远端管理员权限的人可能借用你的密钥。",
            "仅在确实需要跳板认证时启用 ForwardAgent。",
            "配置",
        ),
        Finding(
            "info",
            "deploy_key 只有公钥",
            "发现公钥文件但没有对应的私钥，可能是从其他设备复制的授权记录。",
            "如果需要在当前设备使用该身份，请导入对应私钥。",
            "密钥",
        ),
        Finding(
            "info",
            "known_hosts 中包含 CA 记录",
            "存在 1 条 @cert-authority 记录，用于验证由该 CA 签发的服务器证书。",
            "定期核对该 CA 公钥是否仍由可信团队维护。",
            "已知主机",
        ),
    ]

    agent = AgentStatus(
        available=True,
        running=True,
        keys=[AgentKey(256, fingerprint("agent-key"), "demo@workstation", "ED25519")],
        message="1 把密钥已加载",
    )
    server = ServerInfo(
        installed=True,
        running=True,
        state="RUNNING",
        password_auth=False,
        pubkey_auth=True,
        host_keys=[],
    )
    authorized = [
        AuthorizedKeyEntry(
            "ssh-ed25519",
            fingerprint("authorized-deploy"),
            256,
            "deploy@ci",
            'command="/usr/bin/backup",no-pty',
            1,
            rf"{SSH_DIR}\authorized_keys",
        )
    ]

    raw_config = '\n'.join(
        [
            "Host github.com",
            "  HostName github.com",
            "  User git",
            f"  IdentityFile {SSH_DIR}\\id_ed25519_work",
            "  IdentitiesOnly yes",
            "",
            "Host prod-web",
            "  HostName 10.20.0.15",
            "  User deploy",
            "  Port 2222",
            f"  IdentityFile {SSH_DIR}\\id_ecdsa_cloud",
            "  ProxyJump bastion",
        ]
    )

    return ScanResult(
        ssh_dir=SSH_DIR,
        exists=True,
        keys=[ed, rsa, ecdsa, deploy],
        known_hosts=known_hosts,
        hosts=hosts,
        agent=agent,
        server=server,
        ssh_version="OpenSSH for Windows 9.5p2, LibreSSL 3.8.2",
        ssh_path=r"C:\Windows\System32\OpenSSH\ssh.exe",
        keygen_path=r"C:\Windows\System32\OpenSSH\ssh-keygen.exe",
        ssh_add_path=r"C:\Windows\System32\OpenSSH\ssh-add.exe",
        findings=findings,
        score=84,
        grade="良好",
        raw_configs={rf"{SSH_DIR}\config": raw_config},
        config_files=[rf"{SSH_DIR}\config"],
        authorized_keys=authorized,
        authorized_keys_count=1,
        certificates=0,
        total_files=9,
        scanned_at=WHEN,
    )


def demo_device() -> DeviceFingerprint:
    values = [
        ("machine_guid", "系统 Machine ID", "DEMO-8F2A-4C11-9E70-B4C1", "mdi.identifier", "系统", True, "演示值，非真实设备"),
        ("computer_hardware_id", "Windows 硬件 ID", "{DEMO-54DA-DCE7-95B2-5C32}", "mdi.fingerprint", "系统", True, "演示值，非真实设备"),
        ("system_volume", "系统盘卷序列号 · C:\\", "DEMO2026", "mdi.harddisk", "存储", True),
        ("mac_0", "网卡 · Ethernet", "02:00:00:00:00:01", "mdi.ethernet", "网络", True, "演示值，非真实网卡"),
        ("hostname", "计算机名", "DEMO-WORKSTATION", "mdi.laptop", "系统", False),
        ("os", "操作系统", "Windows 11 Pro", "mdi.microsoft-windows", "系统", False, "24H2 · Build 26100"),
        ("cpu_model", "处理器型号", "Demo CPU 8-Core Processor", "mdi.cpu-64-bit", "硬件", False),
        ("cpu_topology", "CPU 核心 / 线程", "8 核 / 16 线程", "mdi.chip", "硬件", False),
        ("memory", "物理内存", "32.0 GB", "mdi.memory", "硬件", False),
        ("board_model", "主板型号", "DEMO-B850", "mdi.developer-board", "硬件", False),
        ("bios_version", "BIOS 版本", "1.0.0-demo", "mdi.memory", "硬件", False, "2026-01-01"),
    ]
    components = []
    for item in values:
        key, label, value, icon, category, sensitive, *rest = item
        components.append(
            FingerprintComponent(
                key=key,
                label=label,
                value=value,
                icon=icon,
                category=category,
                sensitive=sensitive,
                hint=rest[0] if rest else "",
            )
        )
    digest = hashlib.sha256(b"KeyGuard demo device fingerprint").hexdigest()
    short = base64.b32encode(bytes.fromhex(digest)).decode("ascii")[:16]
    return DeviceFingerprint(
        device_id=digest,
        short_id="-".join(short[i : i + 4] for i in range(0, 16, 4)),
        components=components,
        hostname="DEMO-WORKSTATION",
        username="demo",
        os_name="Windows 11 Pro",
        os_version="24H2 · Build 26100",
        architecture="AMD64",
        manufacturer="Demo Systems",
        model="KeyGuard Demo",
        collected_at=WHEN,
        stable_count=3,
    )


def capture(scan: ScanResult, device: DeviceFingerprint, theme_name: str, prefix: str) -> None:
    apply_theme(QApplication.instance(), theme_name)
    window = MainWindow(scan=scan, device=device)
    window.resize(1400, 900)
    window.show()
    QApplication.processEvents()
    window.grab().save(str(OUT / f"{prefix}overview.png"))
    for index, name in ((1, "keys"), (2, "hosts"), (3, "config"), (4, "device"), (5, "audit")):
        window.navigate(index)
        QApplication.processEvents()
        window.grab().save(str(OUT / f"{prefix}{name}.png"))
    window.close()


def capture_dialog() -> None:
    apply_theme(QApplication.instance(), "dark")
    dialog = GenerateKeyDialog(r"C:\Users\demo\.ssh")
    dialog.comment_edit.setText("demo@workstation")
    dialog.show()
    QApplication.processEvents()
    dialog.grab().save(str(OUT / "generate-dialog.png"))
    dialog.close()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication(sys.argv)
    app.setFont(base_font())
    scan = demo_scan()
    device = demo_device()
    capture(scan, device, "dark", "")
    capture(scan, device, "light", "light-")
    capture_dialog()
    print(f"screenshots written to {OUT}")


if __name__ == "__main__":
    main()
