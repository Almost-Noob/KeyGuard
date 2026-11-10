"""Known hosts page."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.ssh import KnownHostEntry, ScanResult
from app.ui.helpers import clear_layout, copy_text, open_local_path
from app.ui.theme import theme
from app.ui.widgets import (
    EmptyState,
    IconBadge,
    ScrollPage,
    SectionCard,
    StatCard,
    badge,
    copy_button,
    icon,
    make_button,
)


class KnownHostRow(QFrame):
    copied = Signal(str)

    def __init__(self, entry: KnownHostEntry, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("HostRow")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(12)

        if entry.is_revoked:
            tone, icon_name = "danger", "mdi.server-off"
        elif entry.is_ca:
            tone, icon_name = "accent", "mdi.shield-account-outline"
        else:
            tone, icon_name = "primary", "mdi.server-network"
        layout.addWidget(IconBadge(icon_name, tone, 40, 20))

        body = QVBoxLayout()
        body.setSpacing(4)
        top = QHBoxLayout()
        top.setSpacing(7)
        label_text = entry.host_label
        if entry.hashed:
            label_text = "哈希主机名"
        host = QLabel(label_text)
        host.setStyleSheet("font-size: 14px; font-weight: 600;")
        if entry.hashed and entry.hosts:
            host.setToolTip(entry.hosts[0])
        top.addWidget(host)
        top.addWidget(badge(entry.key_type, "primary"))
        if entry.is_revoked:
            top.addWidget(badge("已撤销", "danger"))
        if entry.is_ca:
            top.addWidget(badge("证书颁发机构", "accent"))
        if entry.hashed:
            top.addWidget(badge("哈希", "muted"))
        top.addStretch(1)
        body.addLayout(top)

        fingerprint = QLabel(entry.fingerprint)
        fingerprint.setProperty("role", "mono")
        fingerprint.setStyleSheet(f"font-size: 11px; color: {theme()['muted']};")
        fingerprint.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        body.addWidget(fingerprint)

        meta_bits = [f"{entry.source} 第 {entry.line} 行"]
        if entry.bits:
            meta_bits.append(f"{entry.bits} 位")
        if len(entry.hosts) > 1:
            meta_bits.append(f"{len(entry.hosts)} 个主机名")
        meta = QLabel(" · ".join(meta_bits))
        meta.setProperty("role", "dim")
        body.addWidget(meta)
        layout.addLayout(body, 1)

        copy_btn = copy_button(entry.fingerprint, "复制主机指纹", size=28, icon_size=14)
        copy_btn.clicked.connect(lambda: self.copied.emit(entry.fingerprint))
        layout.addWidget(copy_btn, 0, Qt.AlignmentFlag.AlignVCenter)


class HostsPage(ScrollPage):
    notify = Signal(str, str)

    TITLE = "已知主机"
    SUBTITLE = "known_hosts 中已信任的服务器主机密钥"

    def __init__(self, scan: ScanResult, parent: QWidget | None = None):
        super().__init__(parent)
        self.scan = scan
        self._query = ""
        self._build()

    def _build(self) -> None:
        self.add(self._build_stats())

        card = SectionCard(
            "已知主机记录",
            "主机密钥用于识别服务器身份，首次连接时应通过可信渠道核对指纹。",
            icon_name="mdi.server-network",
            action=self._make_open_button(),
        )
        toolbar = QHBoxLayout()
        toolbar.setSpacing(9)
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索主机名、密钥类型或指纹")
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(300)
        self.search.addAction(icon("mdi.magnify", theme()["dim"]), QLineEdit.ActionPosition.LeadingPosition)
        self.search.textChanged.connect(self._on_search)
        toolbar.addWidget(self.search)
        toolbar.addStretch(1)
        self.count_label = QLabel()
        self.count_label.setProperty("role", "muted")
        toolbar.addWidget(self.count_label)
        card.content.addLayout(toolbar)
        self.list_box = QVBoxLayout()
        self.list_box.setSpacing(9)
        card.content.addLayout(self.list_box)
        self.add(card)

        if not self.scan.known_hosts:
            info = SectionCard("还没有信任记录", "首次通过 SSH 连接服务器时，会提示确认主机指纹。", icon_name="mdi.information-outline")
            text = QLabel(
                "确认后，服务器的主机密钥会写入 known_hosts。请勿在未核对指纹的情况下直接接受未知主机。"
            )
            text.setProperty("role", "muted")
            text.setWordWrap(True)
            info.add_content(text)
            self.add(info)

        self._render_list()
        self.finish()

    def _build_stats(self) -> QWidget:
        wrapper = QWidget()
        layout = QHBoxLayout(wrapper)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)
        revoked = sum(1 for entry in self.scan.known_hosts if entry.is_revoked)
        cas = sum(1 for entry in self.scan.known_hosts if entry.is_ca)
        layout.addWidget(
            StatCard(
                "已知主机",
                str(self.scan.unique_known_hosts),
                "唯一主机名 / 地址",
                icon_name="mdi.server-network",
                tone="primary",
            )
        )
        layout.addWidget(
            StatCard(
                "信任记录",
                str(len(self.scan.known_hosts)),
                f"来自 known_hosts · {self.scan.known_hosts_old_count} 条旧记录",
                icon_name="mdi.shield-check-outline",
                tone="success",
            )
        )
        layout.addWidget(
            StatCard(
                "撤销 / CA",
                f"{revoked} / {cas}",
                "需要关注的主机密钥",
                icon_name="mdi.shield-alert-outline",
                tone="danger" if revoked else "accent",
            )
        )
        return wrapper

    def _make_open_button(self):
        button = make_button("打开 known_hosts", "secondary", icon_name="mdi.folder-open-outline")
        path = str(Path(self.scan.ssh_dir) / "known_hosts")
        button.clicked.connect(lambda: self._open_file(path))
        return button

    def _open_file(self, path: str) -> None:
        if not open_local_path(path, select=True):
            self.notify.emit("known_hosts 文件不存在", "warning")

    def _on_search(self, text: str) -> None:
        self._query = text.strip().lower()
        self._render_list()

    def _filtered(self) -> list[KnownHostEntry]:
        if not self._query:
            return self.scan.known_hosts
        result = []
        for entry in self.scan.known_hosts:
            haystack = " ".join(
                [*entry.hosts, entry.key_type, entry.fingerprint, entry.marker, entry.source]
            ).lower()
            if self._query in haystack:
                result.append(entry)
        return result

    def _render_list(self) -> None:
        clear_layout(self.list_box)
        entries = self._filtered()
        self.count_label.setText(f"{len(entries)} / {len(self.scan.known_hosts)} 条记录")
        if not entries:
            if self.scan.known_hosts:
                self.list_box.addWidget(
                    EmptyState("mdi.magnify", "没有匹配的主机", "尝试搜索 IP、域名或指纹片段。")
                )
            else:
                self.list_box.addWidget(
                    EmptyState(
                        "mdi.server-network",
                        "known_hosts 为空",
                        "连接一台新服务器并确认其主机指纹后，记录会出现在这里。",
                    )
                )
            return
        for entry in entries:
            row = KnownHostRow(entry)
            row.copied.connect(lambda fp: self._copied(fp))
            self.list_box.addWidget(row)

    def _copied(self, fingerprint: str) -> None:
        copy_text(fingerprint)
        self.notify.emit("主机指纹已复制到剪贴板", "success")
