"""Device fingerprint page."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from app.core.device import DeviceFingerprint, collect_device_fingerprint, mask_value
from app.ui.helpers import clear_layout, copy_text
from app.ui.theme import theme
from app.ui.widgets import (
    IconBadge,
    ScrollPage,
    SectionCard,
    StatCard,
    badge,
    copy_button,
    make_button,
)


class DevicePage(ScrollPage):
    notify = Signal(str, str)

    TITLE = "设备指纹"
    SUBTITLE = "由硬件与系统标识计算出的稳定设备身份"

    def __init__(
        self,
        fingerprint: DeviceFingerprint | None = None,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.fingerprint = fingerprint or collect_device_fingerprint()
        self._show_sensitive = False
        self._build()

    def _build(self) -> None:
        self.add(self._build_hero())
        self.add(self._build_stats())

        action = QCheckBox("显示敏感信息")
        action.setChecked(self._show_sensitive)
        action.toggled.connect(self._toggle_sensitive)
        self.components_card = SectionCard(
            "标识组件",
            "敏感字段默认隐藏；导出 JSON 会包含完整原始值。",
            icon_name="mdi.identifier",
            action=action,
        )
        self.grid = QGridLayout()
        self.grid.setContentsMargins(0, 2, 0, 0)
        self.grid.setHorizontalSpacing(12)
        self.grid.setVerticalSpacing(12)
        self.components_card.content.addLayout(self.grid)
        self.add(self.components_card)
        self._render_components()

        self.add(self._build_explanation())
        self.finish()

    def _build_hero(self) -> QWidget:
        card = QFrame()
        card.setObjectName("HeroCard")
        layout = QHBoxLayout(card)
        layout.setContentsMargins(26, 24, 26, 24)
        layout.setSpacing(20)

        left = QVBoxLayout()
        left.setSpacing(10)
        eyebrow = QLabel("DEVICE IDENTITY  ·  本机生成")
        eyebrow.setProperty("role", "eyebrow")
        left.addWidget(eyebrow)

        title_row = QHBoxLayout()
        title_row.setSpacing(10)
        title = QLabel("设备指纹")
        title.setObjectName("HeroTitle")
        title_row.addWidget(title)
        title_row.addWidget(badge("SHA-256", "accent"))
        title_row.addStretch(1)
        left.addLayout(title_row)

        self.short_label = QLabel(self.fingerprint.short_id)
        self.short_label.setObjectName("FingerprintLarge")
        self.short_label.setStyleSheet(
            f"font-size: 20px; font-weight: 600; color: {theme()['text']};"
            "font-family: 'Cascadia Code', 'Consolas';"
        )
        self.short_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        left.addWidget(self.short_label)

        subtitle = QLabel(
            f"{self.fingerprint.hostname} · {self.fingerprint.os_name} · "
            f"{self.fingerprint.stable_count} 个稳定标识参与计算"
        )
        subtitle.setProperty("role", "muted")
        subtitle.setWordWrap(True)
        left.addWidget(subtitle)

        self.device_id_label = QLabel(self.fingerprint.device_id)
        self.device_id_label.setProperty("role", "mono")
        self.device_id_label.setWordWrap(True)
        self.device_id_label.setStyleSheet(
            f"font-size: 10px; color: {theme()['dim']}; font-family: 'Cascadia Code','Consolas';"
        )
        self.device_id_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        left.addWidget(self.device_id_label)

        if self.fingerprint.warning:
            warn = QLabel(self.fingerprint.warning)
            warn.setWordWrap(True)
            warn.setStyleSheet(f"color: {theme()['warning']}; font-size: 11px;")
            left.addWidget(warn)
        layout.addLayout(left, 1)

        right = QVBoxLayout()
        right.setSpacing(8)
        copy_fp = make_button("复制完整指纹", "primary", icon_name="mdi.content-copy")
        copy_fp.clicked.connect(self._copy_device_id)
        right.addWidget(copy_fp)
        export = make_button("导出 JSON", "secondary", icon_name="mdi.download-outline")
        export.clicked.connect(self._export)
        right.addWidget(export)
        refresh = make_button("重新采集", "ghost", icon_name="mdi.refresh")
        refresh.clicked.connect(self._refresh)
        right.addWidget(refresh)
        generated = QLabel(f"采集于 {self.fingerprint.collected_at.strftime('%Y-%m-%d %H:%M:%S')}")
        generated.setProperty("role", "dim")
        generated.setAlignment(Qt.AlignmentFlag.AlignRight)
        right.addWidget(generated)
        right.addStretch(1)
        layout.addLayout(right, 0)
        return card

    def _build_stats(self) -> QWidget:
        wrapper = QWidget()
        layout = QHBoxLayout(wrapper)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)
        layout.addWidget(
            StatCard(
                "稳定标识",
                str(self.fingerprint.stable_count),
                "参与主指纹计算",
                icon_name="mdi.fingerprint",
                tone="primary",
            )
        )
        layout.addWidget(
            StatCard(
                "标识组件",
                str(len(self.fingerprint.components)),
                "硬件 / 系统 / 网络",
                icon_name="mdi.chip",
                tone="accent",
            )
        )
        layout.addWidget(
            StatCard(
                "计算机名",
                self.fingerprint.hostname,
                self.fingerprint.username or "当前用户",
                icon_name="mdi.laptop",
                tone="info",
            )
        )
        return wrapper

    def _render_components(self) -> None:
        clear_layout(self.grid)
        components = self.fingerprint.components
        for index, component in enumerate(components):
            card = self._component_card(component)
            self.grid.addWidget(card, index // 2, index % 2)
        self.grid.setColumnStretch(0, 1)
        self.grid.setColumnStretch(1, 1)

    def _component_card(self, component) -> QWidget:
        hidden = component.sensitive and not self._show_sensitive
        value = mask_value(component.value) if hidden else component.display_value

        card = QFrame()
        card.setObjectName("ComponentCard")
        layout = QHBoxLayout(card)
        layout.setContentsMargins(15, 13, 15, 13)
        layout.setSpacing(11)
        layout.addWidget(IconBadge(component.icon, "primary" if not component.sensitive else "accent", 36, 18), 0, Qt.AlignmentFlag.AlignTop)

        body = QVBoxLayout()
        body.setSpacing(4)
        top = QHBoxLayout()
        top.setSpacing(6)
        label = QLabel(component.label)
        label.setProperty("role", "muted")
        label.setWordWrap(True)
        top.addWidget(label, 1)
        if component.sensitive:
            top.addWidget(badge("敏感", "muted"))
        body.addLayout(top)

        value_label = QLabel(value)
        value_label.setProperty("role", "mono")
        value_label.setWordWrap(True)
        value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        if hidden:
            value_label.setToolTip("勾选“显示敏感信息”后可查看与复制")
        body.addWidget(value_label)

        hint = QLabel(component.hint or f"值哈希 {component.value_hash}")
        hint.setProperty("role", "dim")
        hint.setWordWrap(True)
        body.addWidget(hint)
        layout.addLayout(body, 1)

        if component.value and not hidden:
            copy_btn = copy_button(component.value, f"复制{component.label}", size=27, icon_size=14)
            copy_btn.clicked.connect(
                lambda _=False, label=component.label: self.notify.emit(f"{label} 已复制", "success")
            )
            layout.addWidget(copy_btn, 0, Qt.AlignmentFlag.AlignTop)
        return card

    def _build_explanation(self) -> QWidget:
        card = SectionCard(
            "指纹如何计算",
            "全部计算在本地完成，不依赖云端服务",
            icon_name="mdi.information-outline",
        )
        lines = [
            "主指纹由 Machine ID、Windows 硬件 ID、系统盘卷序列号等稳定标识排序后拼接，再做一次 SHA-256。",
            "MAC 地址、BIOS 版本、主板型号等信息仅用于展示与核对，不参与主指纹，避免网络变化导致指纹漂移。",
            "重装系统、更换主板或系统盘可能改变部分标识，因此指纹并非绝对永久不变。",
            "导出的 JSON 包含原始硬件标识，属于敏感数据，请只保存在可信位置。",
        ]
        for line in lines:
            row = QHBoxLayout()
            row.setSpacing(8)
            dot = QLabel()
            dot.setFixedSize(6, 6)
            dot.setStyleSheet(f"background: {theme()['accent']}; border-radius: 3px;")
            row.addWidget(dot, 0, Qt.AlignmentFlag.AlignTop)
            text = QLabel(line)
            text.setProperty("role", "muted")
            text.setWordWrap(True)
            row.addWidget(text, 1)
            card.content.addLayout(row)
        return card

    def _toggle_sensitive(self, checked: bool) -> None:
        self._show_sensitive = checked
        QTimer.singleShot(0, self._rebuild)

    def _rebuild(self) -> None:
        clear_layout(self.root)
        self._build()

    def _copy_device_id(self) -> None:
        copy_text(self.fingerprint.device_id)
        self.notify.emit("完整设备指纹已复制到剪贴板", "success")

    def _refresh(self) -> None:
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            self.fingerprint = collect_device_fingerprint()
        finally:
            QApplication.restoreOverrideCursor()
        self._rebuild()
        self.notify.emit("设备指纹已重新采集", "success")

    def _export(self) -> None:
        default_name = f"device-fingerprint-{datetime.now().strftime('%Y%m%d-%H%M')}.json"
        documents = Path.home() / "Documents"
        base = documents if documents.is_dir() else Path.home()
        path, _ = QFileDialog.getSaveFileName(
            self,
            "导出设备指纹",
            str(base / default_name),
            "JSON 文件 (*.json)",
        )
        if not path:
            return
        try:
            Path(path).write_text(self.fingerprint.to_json(), encoding="utf-8")
        except OSError as exc:
            self.notify.emit(f"导出失败：{exc}", "danger")
            return
        self.notify.emit("设备指纹已导出", "success")
