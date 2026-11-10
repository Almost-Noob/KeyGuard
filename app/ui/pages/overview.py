"""Overview dashboard page."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from app.core.ssh import ScanResult
from app.ui.theme import theme
from app.ui.widgets import (
    IconBadge,
    KeyRow,
    ScoreRing,
    ScrollPage,
    SectionCard,
    StatCard,
    badge,
    icon,
    make_button,
)

SEVERITY_TONE = {"critical": "danger", "warning": "warning", "info": "info"}
SEVERITY_LABEL = {"critical": "严重", "warning": "建议", "info": "提示"}


class OverviewPage(ScrollPage):
    generate_requested = Signal()
    refresh_requested = Signal()
    keys_requested = Signal()
    audit_requested = Signal()
    key_requested = Signal(str)

    TITLE = "概览"
    SUBTITLE = "本机 SSH 身份与安全状态一览"

    def __init__(self, scan: ScanResult, parent: QWidget | None = None):
        super().__init__(parent)
        self.scan = scan
        self._build()

    def _build(self) -> None:
        self.add(self._build_hero())
        self.add(self._build_stats())

        columns = QHBoxLayout()
        columns.setSpacing(16)
        columns.addWidget(self._build_keys_card(), 2)
        columns.addWidget(self._build_audit_card(), 1)
        self.root.addLayout(columns)
        self.add(self._build_system_card())
        self.add(self._build_footer())
        self.finish()

    def _build_hero(self) -> QWidget:
        card = QFrame()
        card.setObjectName("HeroCard")
        layout = QHBoxLayout(card)
        layout.setContentsMargins(26, 24, 26, 24)
        layout.setSpacing(20)

        left = QVBoxLayout()
        left.setSpacing(11)
        eyebrow = QLabel("KEYGUARD  ·  SSH IDENTITY")
        eyebrow.setProperty("role", "eyebrow")
        left.addWidget(eyebrow)

        title = QLabel("本机 SSH 身份，一目了然")
        title.setObjectName("HeroTitle")
        left.addWidget(title)

        if self.scan.keys:
            subtitle_text = (
                f"已发现 {self.scan.private_count} 个私钥、{self.scan.public_count} 个公钥，"
                f"已知 {self.scan.unique_known_hosts} 台主机。"
            )
        else:
            subtitle_text = "尚未发现 SSH 密钥。创建第一对密钥，开始管理你的本机身份。"
        subtitle = QLabel(subtitle_text)
        subtitle.setProperty("role", "muted")
        subtitle.setWordWrap(True)
        left.addWidget(subtitle)

        chips = QHBoxLayout()
        chips.setSpacing(8)
        chips.addWidget(badge(f"{len(self.scan.keys)} 个密钥", "primary"))
        chips.addWidget(badge(f"{self.scan.host_count} 个配置主机", "accent"))
        counts = self.scan.counts_by_severity
        if counts["critical"]:
            chips.addWidget(badge(f"{counts['critical']} 个严重风险", "danger"))
        elif counts["warning"]:
            chips.addWidget(badge(f"{counts['warning']} 条建议", "warning"))
        else:
            chips.addWidget(badge("未发现风险", "success"))
        chips.addStretch(1)
        left.addLayout(chips)

        buttons = QHBoxLayout()
        buttons.setSpacing(9)
        generate = make_button("生成新密钥", "primary", icon_name="mdi.plus", tooltip="创建新的 SSH 密钥对")
        generate.clicked.connect(self.generate_requested)
        buttons.addWidget(generate)
        scan_button = make_button("重新扫描", "secondary", icon_name="mdi.refresh", tooltip="重新读取系统 SSH 状态")
        scan_button.clicked.connect(self.refresh_requested)
        buttons.addWidget(scan_button)
        buttons.addStretch(1)
        left.addLayout(buttons)

        path = QLabel(self.scan.ssh_dir)
        path.setObjectName("PathChip")
        path.setToolTip("当前扫描的 SSH 目录")
        left.addWidget(path, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addLayout(left, 1)

        right = QVBoxLayout()
        right.setSpacing(8)
        right.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.score_ring = ScoreRing(self.scan.score, self.scan.grade)
        right.addWidget(self.score_ring, 0, Qt.AlignmentFlag.AlignHCenter)
        scanned = QLabel(f"上次扫描 · {self.scan.scanned_at.strftime('%H:%M:%S')}")
        scanned.setProperty("role", "dim")
        right.addWidget(scanned, 0, Qt.AlignmentFlag.AlignHCenter)
        layout.addLayout(right, 0)
        return card

    def _build_stats(self) -> QWidget:
        wrapper = QWidget()
        grid = QGridLayout(wrapper)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(14)

        agent_text = str(len(self.scan.agent.keys)) if self.scan.agent.running else "—"
        agent_hint = "agent 运行中" if self.scan.agent.running else "未运行"
        cards = [
            StatCard(
                "私钥",
                str(self.scan.private_count),
                f"{self.scan.encrypted_count} 个受口令保护" if self.scan.private_count else "尚未创建",
                icon_name="mdi.key-outline",
                tone="primary",
            ),
            StatCard(
                "已知主机",
                str(self.scan.unique_known_hosts),
                f"{len(self.scan.known_hosts)} 条信任记录",
                icon_name="mdi.server-network",
                tone="accent",
            ),
            StatCard(
                "SSH 配置主机",
                str(self.scan.host_count),
                f"{len(self.scan.config_files)} 个配置文件",
                icon_name="mdi.file-cog-outline",
                tone="info",
            ),
            StatCard(
                "agent 密钥",
                agent_text,
                agent_hint,
                icon_name="mdi.shield-key-outline",
                tone="success" if self.scan.agent.running else "muted",
            ),
        ]
        for index, card in enumerate(cards):
            grid.addWidget(card, 0, index)
        return wrapper

    def _build_keys_card(self) -> QWidget:
        action = make_button("查看全部", "link")
        action.clicked.connect(self.keys_requested)
        card = SectionCard(
            "密钥一览",
            "最近发现的本地密钥对",
            icon_name="mdi.key-chain",
            action=action,
        )
        if not self.scan.keys:
            box = QVBoxLayout()
            box.setSpacing(10)
            box.setAlignment(Qt.AlignmentFlag.AlignCenter)
            label = QLabel("还没有 SSH 密钥")
            label.setObjectName("EmptyTitle")
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            box.addWidget(label)
            hint = QLabel("生成 Ed25519 密钥只需几秒，推荐设置口令保护。")
            hint.setProperty("role", "muted")
            hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
            box.addWidget(hint)
            create = make_button("生成第一对密钥", "primary", icon_name="mdi.plus")
            create.clicked.connect(self.generate_requested)
            box.addWidget(create, 0, Qt.AlignmentFlag.AlignHCenter)
            card.content.addLayout(box)
            return card

        for key in self.scan.keys[:4]:
            row = KeyRow(key)
            row.clicked.connect(lambda _=False, name=key.name: self.key_requested.emit(name))
            card.add_content(row)
        return card

    def _build_audit_card(self) -> QWidget:
        action = make_button("全部建议", "link")
        action.clicked.connect(self.audit_requested)
        card = SectionCard(
            "安全检查",
            "按风险优先级排序",
            icon_name="mdi.shield-check-outline",
            action=action,
        )
        counts = self.scan.counts_by_severity
        summary = QHBoxLayout()
        summary.setSpacing(7)
        if counts["critical"]:
            summary.addWidget(badge(f"{counts['critical']} 严重", "danger"))
        if counts["warning"]:
            summary.addWidget(badge(f"{counts['warning']} 建议", "warning"))
        if counts["info"]:
            summary.addWidget(badge(f"{counts['info']} 提示", "info"))
        if not any(counts.values()):
            summary.addWidget(badge("状态良好", "success"))
        summary.addStretch(1)
        card.content.addLayout(summary)

        if self.scan.findings:
            for index, finding in enumerate(self.scan.findings[:4]):
                card.add_content(self._mini_finding(finding))
                if index < min(3, len(self.scan.findings[:4]) - 1):
                    line = QFrame()
                    line.setFrameShape(QFrame.Shape.HLine)
                    line.setStyleSheet(f"color: {theme()['border']};")
                    card.add_content(line)
        else:
            good = QLabel("未发现需要处理的安全问题。保持密钥轮换和口令保护即可。")
            good.setProperty("role", "muted")
            good.setWordWrap(True)
            card.add_content(good)
        return card

    @staticmethod
    def _mini_finding(finding) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(9)
        tone = SEVERITY_TONE.get(finding.severity, "info")
        dot = QLabel()
        dot.setFixedSize(8, 8)
        dot.setStyleSheet(f"background: {theme()[tone]}; border-radius: 4px;")
        layout.addWidget(dot, 0, Qt.AlignmentFlag.AlignTop)
        text = QLabel(finding.title)
        text.setWordWrap(True)
        text.setStyleSheet("font-size: 12px;")
        layout.addWidget(text, 1)
        layout.addWidget(badge(SEVERITY_LABEL.get(finding.severity, "提示"), tone), 0, Qt.AlignmentFlag.AlignTop)
        return widget

    def _build_system_card(self) -> QWidget:
        card = SectionCard(
            "系统环境",
            "主动读取的本机 OpenSSH 状态",
            icon_name="mdi.laptop",
        )
        row = QHBoxLayout()
        row.setSpacing(22)
        row.addWidget(self._environment_item("OpenSSH", self.scan.ssh_version, "mdi.console-line", "primary"), 2)
        row.addWidget(self._environment_item("ssh-agent", self.scan.agent.message or "运行中", "mdi.shield-key-outline", "success" if self.scan.agent.running else "muted"), 1)
        sshd_text = f"{self.scan.server.state}" if self.scan.server.installed else "未安装 sshd"
        row.addWidget(self._environment_item("本机 sshd", sshd_text, "mdi.server-security", "success" if self.scan.server.running else "muted"), 1)
        card.content.addLayout(row)

        details = QHBoxLayout()
        details.setSpacing(8)
        details.addWidget(badge(f"known_hosts {len(self.scan.known_hosts)} 条", "muted"))
        details.addWidget(badge(f"authorized_keys {self.scan.authorized_keys_count} 条", "muted"))
        details.addWidget(badge(f"证书 {self.scan.certificates} 个", "muted"))
        if self.scan.server.host_keys:
            details.addWidget(badge(f"sshd 主机密钥 {len(self.scan.server.host_keys)} 个", "muted"))
        details.addStretch(1)
        card.content.addLayout(details)
        return card

    def _environment_item(self, label: str, value: str, icon_name: str, tone: str) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addWidget(IconBadge(icon_name, tone, 34, 17), 0, Qt.AlignmentFlag.AlignTop)
        box = QVBoxLayout()
        box.setSpacing(3)
        name = QLabel(label)
        name.setProperty("role", "dim")
        box.addWidget(name)
        text = QLabel(value)
        text.setWordWrap(True)
        text.setProperty("role", "muted")
        text.setStyleSheet("font-size: 12px;")
        box.addWidget(text)
        layout.addLayout(box, 1)
        return widget

    def _build_footer(self) -> QWidget:
        footer = QWidget()
        layout = QHBoxLayout(footer)
        layout.setContentsMargins(4, 2, 4, 2)
        lock = QLabel()
        lock.setPixmap(icon("mdi.lock-outline", theme()["dim"]).pixmap(14, 14))
        layout.addWidget(lock)
        text = QLabel("所有扫描、指纹计算与密钥生成均在本机完成，不会上传任何数据。")
        text.setProperty("role", "dim")
        layout.addWidget(text)
        layout.addStretch(1)
        version = QLabel("KeyGuard v1.0")
        version.setProperty("role", "dim")
        layout.addWidget(version)
        return footer
