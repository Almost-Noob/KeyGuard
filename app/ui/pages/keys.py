"""SSH key inventory page."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app.core.ssh import KeyRecord, ScanResult
from app.ui.helpers import clear_layout, copy_text, open_local_path
from app.ui.theme import theme
from app.ui.widgets import (
    Card,
    EmptyState,
    IconBadge,
    KeyRow,
    KeyValueRow,
    SectionCard,
    badge,
    copy_button,
    icon,
    make_button,
)


class KeysPage(QWidget):
    generate_requested = Signal()
    notify = Signal(str, str)
    selection_changed = Signal(str)

    TITLE = "密钥库"
    SUBTITLE = "管理系统中的 SSH 密钥对与公钥授权"

    def __init__(self, scan: ScanResult, parent: QWidget | None = None, selected: str | None = None):
        super().__init__(parent)
        self.scan = scan
        self._selected = selected
        self._filter = "all"
        self._query = ""
        self._rows: list[tuple[KeyRecord, KeyRow]] = []
        self._build()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 6, 0)
        root.setSpacing(14)

        root.addLayout(self._build_toolbar())
        content = QHBoxLayout()
        content.setSpacing(16)
        content.addWidget(self._build_list(), 1)
        content.addWidget(self._build_detail_scroll(), 0)
        root.addLayout(content, 1)

        self._refresh_list()

    def _build_toolbar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(9)

        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索名称、注释或指纹")
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(250)
        self.search.addAction(icon("mdi.magnify", theme()["dim"]), QLineEdit.ActionPosition.LeadingPosition)
        self.search.textChanged.connect(self._on_search)
        bar.addWidget(self.search)

        segment_bar = QFrame()
        segment_bar.setObjectName("SegmentBar")
        segment_layout = QHBoxLayout(segment_bar)
        segment_layout.setContentsMargins(3, 3, 3, 3)
        segment_layout.setSpacing(2)
        self.filter_group = QButtonGroup(self)
        self.filter_group.setExclusive(True)
        for index, (label, value) in enumerate((("全部", "all"), ("私钥", "private"), ("仅公钥", "public"))):
            button = make_button(label, "segment")
            button.setCheckable(True)
            button.setChecked(index == 0)
            self.filter_group.addButton(button, index)
            segment_layout.addWidget(button)
            button.setProperty("filterValue", value)
        self.filter_group.idClicked.connect(self._on_filter)
        bar.addWidget(segment_bar)
        bar.addStretch(1)

        count = QLabel(f"{len(self.scan.keys)} 个密钥")
        count.setProperty("role", "muted")
        bar.addWidget(count)

        open_dir = make_button("打开目录", "secondary", icon_name="mdi.folder-open-outline")
        open_dir.clicked.connect(lambda: open_local_path(self.scan.ssh_dir))
        bar.addWidget(open_dir)

        generate = make_button("生成密钥", "primary", icon_name="mdi.plus")
        generate.clicked.connect(self.generate_requested)
        bar.addWidget(generate)
        return bar

    def _build_list(self) -> QWidget:
        self.list_scroll = QScrollArea()
        self.list_scroll.setWidgetResizable(True)
        self.list_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.list_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.list_host = QWidget()
        self.list_layout = QVBoxLayout(self.list_host)
        self.list_layout.setContentsMargins(0, 0, 5, 14)
        self.list_layout.setSpacing(9)
        self.list_scroll.setWidget(self.list_host)
        return self.list_scroll

    def _build_detail_scroll(self) -> QWidget:
        self.detail_scroll = QScrollArea()
        self.detail_scroll.setWidgetResizable(True)
        self.detail_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.detail_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.detail_scroll.setFixedWidth(404)
        self.detail_host = QWidget()
        self.detail_layout = QVBoxLayout(self.detail_host)
        self.detail_layout.setContentsMargins(0, 0, 5, 14)
        self.detail_layout.setSpacing(14)
        self.detail_scroll.setWidget(self.detail_host)
        return self.detail_scroll

    # ------------------------------------------------------------------ list
    def _on_search(self, text: str) -> None:
        self._query = text.strip().lower()
        self._refresh_list()

    def _on_filter(self, index: int) -> None:
        button = self.filter_group.button(index)
        self._filter = button.property("filterValue") if button else "all"
        self._refresh_list()

    def _matches(self, key: KeyRecord) -> bool:
        if self._filter == "private" and not key.has_private:
            return False
        if self._filter == "public" and not (key.has_public or key.reconstructed_public):
            return False
        if not self._query:
            return True
        haystack = " ".join(
            [
                key.name,
                key.comment,
                key.key_type,
                key.display_type,
                key.fingerprint,
                key.private_path or "",
                key.public_path or "",
            ]
        ).lower()
        return self._query in haystack

    def _refresh_list(self) -> None:
        clear_layout(self.list_layout)
        self._rows = []
        visible = [key for key in self.scan.keys if self._matches(key)]

        if visible:
            summary = QLabel(
                f"{len(visible)} 个结果 · {sum(1 for k in visible if k.has_private)} 个私钥"
            )
            summary.setProperty("role", "dim")
            self.list_layout.addWidget(summary)
            for key in visible:
                row = KeyRow(key)
                row.clicked.connect(lambda _=False, k=key: self._select(k.name))
                self._rows.append((key, row))
                self.list_layout.addWidget(row)
        else:
            if self.scan.keys:
                self.list_layout.addWidget(
                    EmptyState(
                        "mdi.magnify",
                        "没有匹配的密钥",
                        "换一个关键词，或切换到其他筛选条件。",
                    )
                )
            else:
                action = make_button("生成第一对密钥", "primary", icon_name="mdi.plus")
                action.clicked.connect(self.generate_requested)
                self.list_layout.addWidget(
                    EmptyState(
                        "mdi.key-outline",
                        "还没有 SSH 密钥",
                        "生成 Ed25519 密钥只需几秒。私钥留在本机，公钥可以添加到 GitHub、服务器或远端主机。",
                        action,
                    )
                )

        self.list_layout.addWidget(self._build_agent_card())
        if self.scan.authorized_keys:
            self.list_layout.addWidget(self._build_authorized_card())
        self.list_layout.addStretch(1)

        names = [key.name for key in visible]
        if self._selected not in names:
            self._selected = names[0] if names else None
        for key, row in self._rows:
            row.set_selected(key.name == self._selected)
        self._render_detail()

    # --------------------------------------------------------------- detail
    def _select(self, name: str) -> None:
        self._selected = name
        for key, row in self._rows:
            row.set_selected(key.name == name)
        self._render_detail()
        self.selection_changed.emit(name)

    def selected_key(self) -> KeyRecord | None:
        return next((key for key in self.scan.keys if key.name == self._selected), None)

    def _render_detail(self) -> None:
        clear_layout(self.detail_layout)
        key = self.selected_key()
        if key is None:
            card = Card(margins=(18, 18, 18, 18))
            card.add(EmptyState("mdi.key-outline", "选择一个密钥", "在左侧列表中选择密钥后，这里会显示指纹、路径和公钥内容。"))
            self.detail_layout.addWidget(card)
            self.detail_layout.addStretch(1)
            return

        card = Card(margins=(20, 18, 20, 18), spacing=14)
        top = QHBoxLayout()
        top.setSpacing(12)
        tone = "success" if key.encrypted else ("primary" if key.has_private else "muted")
        top.addWidget(IconBadge("mdi.key-variant" if key.has_private else "mdi.key-outline", tone, 52, 25))
        title_box = QVBoxLayout()
        title_box.setSpacing(3)
        name = QLabel(key.name)
        name.setStyleSheet("font-size: 18px; font-weight: 700;")
        name.setWordWrap(True)
        title_box.addWidget(name)
        chips = QHBoxLayout()
        chips.setSpacing(6)
        chips.addWidget(badge(key.display_type, "primary"))
        if key.has_private:
            chips.addWidget(badge("口令保护" if key.encrypted else "无口令", "success" if key.encrypted else "warning"))
        if key.certificate:
            chips.addWidget(badge("证书", "accent"))
        chips.addStretch(1)
        title_box.addLayout(chips)
        top.addLayout(title_box, 1)
        card.body.addLayout(top)

        fingerprint_box = QFrame()
        fingerprint_box.setObjectName("InnerCard")
        fp_layout = QVBoxLayout(fingerprint_box)
        fp_layout.setContentsMargins(13, 11, 13, 11)
        fp_layout.setSpacing(6)
        fp_header = QHBoxLayout()
        fp_title = QLabel("SHA256 指纹")
        fp_title.setProperty("role", "dim")
        fp_header.addWidget(fp_title)
        fp_header.addStretch(1)
        if key.fingerprint:
            fp_header.addWidget(copy_button(key.fingerprint, "复制指纹", size=26, icon_size=13))
        fp_layout.addLayout(fp_header)
        fp_value = QLabel(key.fingerprint or "不可用")
        fp_value.setProperty("role", "mono")
        fp_value.setStyleSheet("font-size: 10px;")
        fp_value.setWordWrap(True)
        fp_value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        fp_layout.addWidget(fp_value)
        card.add(fingerprint_box)

        if key.permission_warning:
            warn = QFrame()
            warn.setObjectName("InnerCard")
            warn_layout = QHBoxLayout(warn)
            warn_layout.setContentsMargins(11, 9, 11, 9)
            warn_layout.setSpacing(8)
            warn_icon = QLabel()
            warn_icon.setPixmap(icon("mdi.alert-outline", theme()["warning"]).pixmap(16, 16))
            warn_layout.addWidget(warn_icon, 0, Qt.AlignmentFlag.AlignTop)
            warn_text = QLabel(f"权限提醒：{key.permission_warning}")
            warn_text.setWordWrap(True)
            warn_text.setStyleSheet(f"color: {theme()['warning']}; font-size: 11px;")
            warn_layout.addWidget(warn_text, 1)
            card.add(warn)

        meta = QVBoxLayout()
        meta.setSpacing(8)
        meta.addWidget(KeyValueRow("私钥文件", key.private_path or "—", copyable=bool(key.private_path), mono=True))
        meta.addWidget(KeyValueRow("公钥文件", key.public_path or "—", copyable=bool(key.public_path), mono=True))
        meta.addWidget(KeyValueRow("注释", key.comment or "—"))
        meta.addWidget(KeyValueRow("密钥长度", f"{key.bits} 位" if key.bits else "—"))
        if key.modified:
            meta.addWidget(KeyValueRow("修改时间", key.modified.strftime("%Y-%m-%d %H:%M")))
        if key.certificate:
            cert = key.certificate
            meta.addWidget(KeyValueRow("证书 Key ID", cert.key_id or "—"))
            meta.addWidget(KeyValueRow("证书主体", ", ".join(cert.principals) or "—"))
        card.add_layout(meta)

        public_header = QHBoxLayout()
        public_title = QLabel("公钥内容")
        public_title.setProperty("role", "muted")
        public_header.addWidget(public_title)
        public_header.addStretch(1)
        if key.public_key:
            public_header.addWidget(copy_button(key.public_key, "复制公钥", size=27, icon_size=14))
        card.body.addLayout(public_header)

        preview = QPlainTextEdit()
        preview.setReadOnly(True)
        preview.setPlainText(key.public_key or "无可用公钥内容")
        preview.setFixedHeight(108)
        preview.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        card.add(preview)

        actions = QVBoxLayout()
        actions.setSpacing(8)
        copy_public = make_button(
            "复制公钥",
            "primary",
            icon_name="mdi.content-copy",
            tooltip="复制完整公钥，可直接粘贴到 GitHub 或 authorized_keys",
        )
        copy_public.setEnabled(bool(key.public_key))
        copy_public.clicked.connect(lambda: self._copy(key.public_key, "公钥已复制到剪贴板"))
        actions.addWidget(copy_public)

        row = QHBoxLayout()
        row.setSpacing(8)
        show = make_button("显示文件", "secondary", icon_name="mdi.folder-open-outline")
        show.clicked.connect(lambda: self._open_key(key))
        row.addWidget(show, 1)
        copy_fp = make_button("复制指纹", "ghost", icon_name="mdi.content-copy")
        copy_fp.setEnabled(bool(key.fingerprint))
        copy_fp.clicked.connect(lambda: self._copy(key.fingerprint, "指纹已复制到剪贴板"))
        row.addWidget(copy_fp, 1)
        actions.addLayout(row)
        card.add_layout(actions)

        self.detail_layout.addWidget(card)
        self.detail_layout.addStretch(1)

    def _copy(self, text: str, message: str) -> None:
        if not text:
            return
        copy_text(text)
        self.notify.emit(message, "success")

    def _open_key(self, key: KeyRecord) -> None:
        path = key.private_path or key.public_path
        if path:
            if not open_local_path(path, select=True):
                self.notify.emit("文件不存在或无法打开", "danger")

    def _build_authorized_card(self) -> QWidget:
        entries = self.scan.authorized_keys
        card = SectionCard(
            "authorized_keys",
            f"{len(entries)} 条允许登录本机的公钥",
            icon_name="mdi.key-chain",
        )
        for entry in entries[:4]:
            row = QWidget()
            layout = QHBoxLayout(row)
            layout.setContentsMargins(0, 1, 0, 1)
            layout.setSpacing(9)
            layout.addWidget(IconBadge("mdi.account-key-outline", "accent", 32, 16))
            box = QVBoxLayout()
            box.setSpacing(2)
            top = QHBoxLayout()
            top.setSpacing(6)
            name = QLabel(entry.comment or "未命名授权密钥")
            name.setStyleSheet("font-size: 12px; font-weight: 600;")
            top.addWidget(name)
            top.addWidget(badge(entry.key_type, "primary"))
            if entry.is_restricted:
                top.addWidget(badge("带限制", "warning"))
            top.addStretch(1)
            box.addLayout(top)
            fp = QLabel(entry.fingerprint)
            fp.setProperty("role", "dim")
            fp.setStyleSheet("font-family: 'Cascadia Code','Consolas'; font-size: 10px;")
            box.addWidget(fp)
            meta = QLabel(f"{entry.source_name} 第 {entry.line} 行")
            meta.setProperty("role", "dim")
            box.addWidget(meta)
            layout.addLayout(box, 1)
            copy_btn = copy_button(entry.fingerprint, "复制授权密钥指纹", size=27, icon_size=13)
            copy_btn.clicked.connect(lambda: self.notify.emit("授权密钥指纹已复制", "success"))
            layout.addWidget(copy_btn, 0, Qt.AlignmentFlag.AlignVCenter)
            card.add_content(row)
        if len(entries) > 4:
            more = QLabel(f"另有 {len(entries) - 4} 条授权密钥")
            more.setProperty("role", "dim")
            card.add_content(more)
        return card

    def _build_agent_card(self) -> QWidget:
        agent = self.scan.agent
        subtitle = f"{len(agent.keys)} 把密钥已加载" if agent.running else "未连接"
        card = SectionCard("ssh-agent", subtitle, icon_name="mdi.shield-key-outline")
        if agent.running and agent.keys:
            for agent_key in agent.keys[:4]:
                row = QWidget()
                layout = QHBoxLayout(row)
                layout.setContentsMargins(0, 0, 0, 0)
                layout.setSpacing(9)
                layout.addWidget(IconBadge("mdi.key-chain", "success", 32, 16))
                box = QVBoxLayout()
                box.setSpacing(2)
                name = QLabel(agent_key.comment or agent_key.key_type)
                name.setStyleSheet("font-size: 12px; font-weight: 600;")
                box.addWidget(name)
                fp = QLabel(agent_key.fingerprint)
                fp.setProperty("role", "dim")
                fp.setStyleSheet("font-family: 'Cascadia Code','Consolas'; font-size: 10px;")
                box.addWidget(fp)
                layout.addLayout(box, 1)
                layout.addWidget(copy_button(agent_key.fingerprint, "复制 agent 密钥指纹", size=26, icon_size=13))
                card.add_content(row)
        else:
            message = agent.message if not agent.running else "agent 中没有已加载的密钥。"
            text = QLabel(message or "ssh-agent 未运行")
            text.setProperty("role", "muted")
            text.setWordWrap(True)
            card.add_content(text)
            if not agent.running:
                hint = QLabel("Windows 可在“服务”中启动 OpenSSH Authentication Agent，然后执行 ssh-add。")
                hint.setProperty("role", "dim")
                hint.setWordWrap(True)
                card.add_content(hint)
        return card
