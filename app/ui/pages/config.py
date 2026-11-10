"""SSH client configuration page."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.ssh import HostConfig, ScanResult
from app.ui.helpers import clear_layout, copy_text, open_local_path
from app.ui.theme import theme
from app.ui.widgets import (
    Card,
    EmptyState,
    HostRow,
    IconBadge,
    KeyValueRow,
    ScrollPage,
    SectionCard,
    StatCard,
    badge,
    icon,
    make_button,
)


class ConfigPage(ScrollPage):
    notify = Signal(str, str)

    TITLE = "SSH 配置"
    SUBTITLE = "解析 ~/.ssh/config 中的主机别名与连接参数"

    def __init__(self, scan: ScanResult, parent: QWidget | None = None):
        super().__init__(parent)
        self.scan = scan
        self._selected: str | None = None
        self._query = ""
        self._rows: list[tuple[HostConfig, HostRow]] = []
        self._build()

    def _build(self) -> None:
        self.add(self._build_stats())

        body = QHBoxLayout()
        body.setSpacing(16)
        detail = self._build_detail_container()
        host_list = self._build_host_list()
        body.addWidget(host_list, 0)
        body.addWidget(detail, 1)
        self.root.addLayout(body)

        if self.scan.config_files:
            self.add(self._build_raw_config())
        self.finish()

    def _build_stats(self) -> QWidget:
        wrapper = QWidget()
        layout = QHBoxLayout(wrapper)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)
        identity_files = len(
            {
                identity
                for host in self.scan.hosts
                for identity in host.identity_files
            }
        )
        layout.addWidget(
            StatCard(
                "配置主机",
                str(self.scan.host_count),
                "已定义的 Host 别名",
                icon_name="mdi.server-network",
                tone="primary",
            )
        )
        layout.addWidget(
            StatCard(
                "IdentityFile",
                str(identity_files),
                "配置中引用的密钥文件",
                icon_name="mdi.key-outline",
                tone="accent",
            )
        )
        layout.addWidget(
            StatCard(
                "配置文件",
                str(len(self.scan.config_files)),
                "用户配置 + 系统配置",
                icon_name="mdi.file-cog-outline",
                tone="info",
            )
        )
        return wrapper

    def _build_host_list(self) -> QWidget:
        card = SectionCard("主机条目", "选择主机查看完整配置", icon_name="mdi.format-list-bulleted")
        card.setFixedWidth(382)
        search = QLineEdit()
        search.setPlaceholderText("搜索别名、地址或用户")
        search.setClearButtonEnabled(True)
        search.addAction(icon("mdi.magnify", theme()["dim"]), QLineEdit.ActionPosition.LeadingPosition)
        search.textChanged.connect(self._on_search)
        card.content.addWidget(search)
        self.list_box = QVBoxLayout()
        self.list_box.setSpacing(9)
        card.content.addLayout(self.list_box)
        self.host_card = card
        self._render_hosts()
        return card

    def _build_detail_container(self) -> QWidget:
        self.detail_host = QWidget()
        self.detail_layout = QVBoxLayout(self.detail_host)
        self.detail_layout.setContentsMargins(0, 0, 0, 0)
        self.detail_layout.setSpacing(0)
        self._render_detail()
        return self.detail_host

    def _on_search(self, text: str) -> None:
        self._query = text.strip().lower()
        self._render_hosts()

    def _filtered(self) -> list[HostConfig]:
        if not self._query:
            return self.scan.hosts
        result = []
        for host in self.scan.hosts:
            haystack = " ".join(
                [host.alias, host.hostname, host.user, host.port, host.proxy_jump, *host.identity_files]
            ).lower()
            if self._query in haystack:
                result.append(host)
        return result

    def _render_hosts(self) -> None:
        clear_layout(self.list_box)
        self._rows = []
        hosts = self._filtered()
        if not hosts:
            if self.scan.hosts:
                self.list_box.addWidget(EmptyState("mdi.magnify", "没有匹配的主机", "换一个关键词试试。"))
            else:
                self.list_box.addWidget(
                    EmptyState(
                        "mdi.file-cog-outline",
                        "没有 Host 配置",
                        "在 ~/.ssh/config 中添加 Host 条目后，这里会显示别名、地址、用户和密钥设置。",
                    )
                )
            self._selected = None
        else:
            names = [host.alias for host in hosts]
            if self._selected not in names:
                self._selected = names[0]
            for host in hosts:
                row = HostRow(host)
                row.clicked.connect(lambda _=False, alias=host.alias: self._select(alias))
                row.set_selected(host.alias == self._selected)
                self._rows.append((host, row))
                self.list_box.addWidget(row)
        self._render_detail()

    def _select(self, alias: str) -> None:
        self._selected = alias
        for host, row in self._rows:
            row.set_selected(host.alias == alias)
        self._render_detail()

    def _selected_host(self) -> HostConfig | None:
        return next((host for host in self.scan.hosts if host.alias == self._selected), None)

    def _render_detail(self) -> None:
        clear_layout(self.detail_layout)
        host = self._selected_host()
        if host is None:
            card = Card(margins=(20, 20, 20, 20))
            card.add(
                EmptyState(
                    "mdi.file-cog-outline",
                    "选择一个主机",
                    "左侧会列出 ~/.ssh/config 中解析到的 Host 条目。",
                )
            )
            self.detail_layout.addWidget(card)
            self.detail_layout.addStretch(1)
            return

        card = Card(margins=(22, 20, 22, 20), spacing=14)
        top = QHBoxLayout()
        top.setSpacing(12)
        top.addWidget(IconBadge("mdi.server-network", "primary", 52, 25))
        title_box = QVBoxLayout()
        title_box.setSpacing(3)
        alias = QLabel(host.alias)
        alias.setStyleSheet("font-size: 20px; font-weight: 700;")
        title_box.addWidget(alias)
        chips = QHBoxLayout()
        chips.setSpacing(6)
        chips.addWidget(badge("Host 别名" if not host.is_pattern else "通配规则", "primary"))
        if host.port:
            chips.addWidget(badge(f"端口 {host.port}", "muted"))
        if host.proxy_jump:
            chips.addWidget(badge("ProxyJump", "accent"))
        chips.addStretch(1)
        title_box.addLayout(chips)
        top.addLayout(title_box, 1)
        card.body.addLayout(top)

        meta = QVBoxLayout()
        meta.setSpacing(8)
        meta.addWidget(KeyValueRow("HostName", host.hostname or host.alias, copyable=bool(host.hostname), mono=True))
        meta.addWidget(KeyValueRow("User", host.user or "—", copyable=bool(host.user), mono=True))
        meta.addWidget(KeyValueRow("Port", host.port or "22（默认）", copyable=bool(host.port), mono=True))
        if host.proxy_jump:
            meta.addWidget(KeyValueRow("ProxyJump", host.proxy_jump, copyable=True, mono=True))
        if host.identity_files:
            for index, identity in enumerate(host.identity_files):
                meta.addWidget(
                    KeyValueRow(f"IdentityFile {index + 1}", identity, copyable=True, mono=True)
                )
        else:
            meta.addWidget(KeyValueRow("IdentityFile", "未显式指定，将使用默认密钥或 agent", mono=True))
        meta.addWidget(KeyValueRow("配置来源", f"{Path(host.source).name} 第 {host.line} 行", mono=True))
        card.add_layout(meta)

        extra = {key: value for key, value in host.options.items() if key != "identityfile"}
        if extra:
            label = QLabel("其他选项")
            label.setProperty("role", "cardTitle")
            card.add(label)
            inner = QVBoxLayout()
            inner.setSpacing(7)
            for key, value in sorted(extra.items()):
                inner.addWidget(KeyValueRow(key, value, copyable=True, mono=True))
            card.add_layout(inner)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        connect = make_button("复制 ssh 命令", "primary", icon_name="mdi.console-line")
        connect.clicked.connect(lambda: self._copy(f"ssh {host.alias}", "ssh 命令已复制"))
        actions.addWidget(connect)
        open_config = make_button("打开配置文件", "secondary", icon_name="mdi.folder-open-outline")
        open_config.clicked.connect(lambda: self._open(host.source))
        actions.addWidget(open_config)
        actions.addStretch(1)
        card.add_layout(actions)

        self.detail_layout.addWidget(card)
        self.detail_layout.addStretch(1)

    def _copy(self, text: str, message: str) -> None:
        copy_text(text)
        self.notify.emit(message, "success")

    def _open(self, path: str) -> None:
        if not open_local_path(path, select=True):
            self.notify.emit("配置文件不存在", "warning")

    def _build_raw_config(self) -> QWidget:
        card = SectionCard(
            "原始配置",
            "以文本方式查看配置文件原文",
            icon_name="mdi.text-box-outline",
        )
        top = QHBoxLayout()
        top.setSpacing(8)
        self.config_selector = QComboBox()
        for path in self.scan.config_files:
            self.config_selector.addItem(Path(path).name, path)
        if not self.scan.config_files:
            self.config_selector.addItem("无配置文件", "")
        top.addWidget(self.config_selector, 1)

        copy_btn = make_button("复制配置", "secondary", icon_name="mdi.content-copy")
        copy_btn.clicked.connect(self._copy_current_config)
        top.addWidget(copy_btn)
        open_btn = make_button("打开文件", "secondary", icon_name="mdi.folder-open-outline")
        open_btn.clicked.connect(lambda: self._open(self.config_selector.currentData() or ""))
        top.addWidget(open_btn)
        card.content.addLayout(top)

        self.raw_editor = QPlainTextEdit()
        self.raw_editor.setReadOnly(True)
        self.raw_editor.setFixedHeight(220)
        self.raw_editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        card.content.addWidget(self.raw_editor)
        self.config_selector.currentIndexChanged.connect(self._update_raw)
        self._update_raw()
        return card

    def _update_raw(self) -> None:
        path = self.config_selector.currentData() if hasattr(self, "config_selector") else None
        if not path:
            self.raw_editor.setPlainText("未找到配置文件")
            return
        self.raw_editor.setPlainText(self.scan.raw_configs.get(path, ""))

    def _copy_current_config(self) -> None:
        text = self.raw_editor.toPlainText() if hasattr(self, "raw_editor") else ""
        if text:
            self._copy(text, "配置内容已复制到剪贴板")
