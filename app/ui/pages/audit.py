"""Security audit page."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from app.core.ssh import ScanResult
from app.ui.helpers import clear_layout
from app.ui.widgets import (
    EmptyState,
    FindingRow,
    ScoreRing,
    ScrollPage,
    SectionCard,
    badge,
    make_button,
)

SEVERITY_LABEL = {"critical": "严重", "warning": "建议", "info": "提示"}
SEVERITY_TONE = {"critical": "danger", "warning": "warning", "info": "info"}


class AuditPage(ScrollPage):
    refresh_requested = Signal()

    TITLE = "安全检查"
    SUBTITLE = "针对本机 SSH 密钥、权限与配置的风险建议"

    def __init__(self, scan: ScanResult, parent: QWidget | None = None):
        super().__init__(parent)
        self.scan = scan
        self._filter = "all"
        self._build()

    def _build(self) -> None:
        self.add(self._build_hero())
        self.add(self._build_filter_bar())
        self.list_card = SectionCard(
            "检查结果",
            "按风险等级排序，建议优先处理严重项。",
            icon_name="mdi.shield-search",
        )
        self.list_box = QVBoxLayout()
        self.list_box.setSpacing(9)
        self.list_card.content.addLayout(self.list_box)
        self.add(self.list_card)
        self._render()
        self.add(self._build_rules())
        self.finish()

    def _build_hero(self) -> QWidget:
        card = QFrame()
        card.setObjectName("HeroCard")
        layout = QHBoxLayout(card)
        layout.setContentsMargins(26, 22, 26, 22)
        layout.setSpacing(22)

        left = QVBoxLayout()
        left.setSpacing(9)
        eyebrow = QLabel("SECURITY REVIEW  ·  LOCAL ONLY")
        eyebrow.setProperty("role", "eyebrow")
        left.addWidget(eyebrow)
        title = QLabel("本机 SSH 安全检查")
        title.setObjectName("HeroTitle")
        left.addWidget(title)

        counts = self.scan.counts_by_severity
        if counts["critical"]:
            summary = "存在需要立即处理的严重风险。建议先处理私钥权限、弱算法和已撤销主机密钥。"
        elif counts["warning"]:
            summary = "整体状态可用，但有一些可以改进的安全设置。逐条处理能显著降低风险。"
        else:
            summary = "未发现明显的安全风险。保持密钥口令保护，并在更换设备时及时轮换密钥。"
        subtitle = QLabel(summary)
        subtitle.setProperty("role", "muted")
        subtitle.setWordWrap(True)
        left.addWidget(subtitle)

        chips = QHBoxLayout()
        chips.setSpacing(7)
        chips.addWidget(badge(f"{counts['critical']} 严重", "danger"))
        chips.addWidget(badge(f"{counts['warning']} 建议", "warning"))
        chips.addWidget(badge(f"{counts['info']} 提示", "info"))
        chips.addStretch(1)
        left.addLayout(chips)

        actions = QHBoxLayout()
        rescan = make_button("重新检查", "secondary", icon_name="mdi.refresh")
        rescan.clicked.connect(self.refresh_requested)
        actions.addWidget(rescan)
        actions.addStretch(1)
        left.addLayout(actions)
        layout.addLayout(left, 1)

        right = QVBoxLayout()
        right.setAlignment(Qt.AlignmentFlag.AlignCenter)
        right.addWidget(ScoreRing(self.scan.score, self.scan.grade), 0, Qt.AlignmentFlag.AlignHCenter)
        detail = QLabel(f"{len(self.scan.findings)} 条检查结果")
        detail.setProperty("role", "dim")
        right.addWidget(detail, 0, Qt.AlignmentFlag.AlignHCenter)
        layout.addLayout(right, 0)
        return card

    def _build_filter_bar(self) -> QWidget:
        wrapper = QWidget()
        layout = QHBoxLayout(wrapper)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        segment = QFrame()
        segment.setObjectName("SegmentBar")
        inner = QHBoxLayout(segment)
        inner.setContentsMargins(3, 3, 3, 3)
        inner.setSpacing(2)
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        counts = self.scan.counts_by_severity
        options = [
            ("全部", "all", len(self.scan.findings)),
            ("严重", "critical", counts["critical"]),
            ("建议", "warning", counts["warning"]),
            ("提示", "info", counts["info"]),
        ]
        for index, (label, value, count) in enumerate(options):
            button = make_button(f"{label}  {count}", "segment")
            button.setCheckable(True)
            button.setChecked(index == 0)
            button.setProperty("filterValue", value)
            self.group.addButton(button, index)
            inner.addWidget(button)
        self.group.idClicked.connect(self._on_filter)
        layout.addWidget(segment)
        layout.addStretch(1)
        note = QLabel("评分：100 - 严重×24 - 建议×8")
        note.setProperty("role", "dim")
        layout.addWidget(note)
        return wrapper

    def _on_filter(self, index: int) -> None:
        button = self.group.button(index)
        self._filter = button.property("filterValue") if button else "all"
        self._render()

    def _render(self) -> None:
        clear_layout(self.list_box)
        findings = self.scan.findings
        if self._filter != "all":
            findings = [item for item in findings if item.severity == self._filter]
        if not findings:
            if self._filter == "all":
                self.list_box.addWidget(
                    EmptyState(
                        "mdi.shield-check-outline",
                        "没有发现安全问题",
                        "当前 SSH 状态良好。继续使用口令保护私钥，并定期检查 known_hosts 与配置。",
                    )
                )
            else:
                self.list_box.addWidget(
                    EmptyState(
                        "mdi.shield-check-outline",
                        "这一等级没有项目",
                        "切换到其他筛选条件查看剩余检查结果。",
                    )
                )
            return
        for finding in findings:
            self.list_box.addWidget(FindingRow(finding))

    def _build_rules(self) -> QWidget:
        card = SectionCard(
            "评分说明",
            "评分只用于快速概览，不替代人工判断",
            icon_name="mdi.information-outline",
            margins=(20, 16, 20, 16),
        )
        text = QLabel(
            "检查范围包括私钥口令保护与权限、密钥算法与长度、公私钥一致性、SSH 证书有效期、"
            "known_hosts 撤销记录、客户端 StrictHostKeyChecking/UserKnownHostsFile/ForwardAgent "
            "设置，以及本机 sshd 的密码登录、公钥登录和 root 登录配置。"
        )
        text.setProperty("role", "muted")
        text.setWordWrap(True)
        card.add_content(text)
        return card
