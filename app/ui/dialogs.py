"""Generate SSH key dialog."""

from __future__ import annotations

import getpass
import socket
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from app.core.ssh import GenerationResult, default_key_name, generate_ssh_key, validate_key_name
from app.ui.theme import theme
from app.ui.widgets import IconBadge, icon, make_button


class GenerateKeyDialog(QDialog):
    def __init__(self, ssh_dir: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("生成 SSH 密钥")
        self.setModal(True)
        self.setMinimumWidth(650)
        self.result: GenerationResult | None = None
        self._key_type = "ed25519"
        self._auto_name = True
        self._busy = False
        self.directory = Path(ssh_dir).expanduser()
        self._build()
        self._update_type_ui()
        self._update_preview()

    # ----------------------------------------------------------------- build
    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 14, 18, 12)
        root.setSpacing(8)

        header = QFrame()
        header.setObjectName("DialogHeader")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(14, 12, 14, 12)
        header_layout.setSpacing(12)
        header_layout.addWidget(IconBadge("mdi.key-plus", "primary", 46, 22))
        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        title = QLabel("生成 SSH 密钥")
        title.setObjectName("DialogTitle")
        title_box.addWidget(title)
        subtitle = QLabel("创建一对 OpenSSH 密钥，私钥只保存在本机。")
        subtitle.setProperty("role", "muted")
        title_box.addWidget(subtitle)
        header_layout.addLayout(title_box, 1)
        root.addWidget(header)

        type_label = QLabel("密钥类型")
        type_label.setProperty("role", "muted")
        root.addWidget(type_label)

        segment = QFrame()
        segment.setObjectName("SegmentBar")
        segment_layout = QHBoxLayout(segment)
        segment_layout.setContentsMargins(4, 4, 4, 4)
        segment_layout.setSpacing(3)
        self.type_group = QButtonGroup(self)
        self.type_group.setExclusive(True)
        options = [
            ("ed25519", "Ed25519", "推荐"),
            ("rsa", "RSA", "兼容"),
            ("ecdsa", "ECDSA", "NIST"),
        ]
        for index, (value, label, tag) in enumerate(options):
            button = make_button(f"{label}   {tag}", "segment")
            button.setCheckable(True)
            button.setChecked(index == 0)
            button.setProperty("keyType", value)
            self.type_group.addButton(button, index)
            segment_layout.addWidget(button)
        self.type_group.idClicked.connect(self._on_type)
        root.addWidget(segment)

        self.type_hint = QLabel()
        self.type_hint.setProperty("role", "muted")
        self.type_hint.setWordWrap(True)
        self.type_hint.setStyleSheet(f"color: {theme()['dim']}; font-size: 11px;")
        root.addWidget(self.type_hint)

        row = QHBoxLayout()
        row.setSpacing(12)
        row.addWidget(self._field("密钥名称", self._name_edit(), "不带扩展名"), 3)
        self.bits_field = self._build_bits_field()
        row.addWidget(self.bits_field, 2)
        root.addLayout(row)

        dir_edit = QLineEdit(str(self.directory))
        dir_edit.textChanged.connect(self._on_directory_changed)
        self.dir_edit = dir_edit
        browse = make_button("浏览", "secondary", icon_name="mdi.folder-open-outline")
        browse.clicked.connect(self._browse)
        dir_row = QHBoxLayout()
        dir_row.setSpacing(8)
        dir_row.addWidget(dir_edit, 1)
        dir_row.addWidget(browse)
        dir_widget = QWidget()
        dir_widget.setLayout(dir_row)
        dir_row.setContentsMargins(0, 0, 0, 0)
        root.addWidget(self._field("保存位置", dir_widget))

        self.path_preview = QLabel()
        self.path_preview.setProperty("role", "dim")
        self.path_preview.setWordWrap(True)
        self.path_preview.setStyleSheet("font-family: 'Cascadia Code','Consolas'; font-size: 10px;")
        root.addWidget(self.path_preview)

        self.comment_edit = QLineEdit(f"{getpass.getuser()}@{socket.gethostname()}")
        root.addWidget(self._field("注释", self.comment_edit, "会写入公钥末尾，便于识别"))

        pass_row = QHBoxLayout()
        pass_row.setSpacing(12)
        pass_row.addWidget(self._field("口令", self._passphrase_edit(), "推荐设置，留空则私钥明文保存"), 1)
        self.confirm_edit = QLineEdit()
        self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_edit.setPlaceholderText("再次输入口令")
        self.confirm_edit.textChanged.connect(self._update_strength)
        pass_row.addWidget(self._field("确认口令", self.confirm_edit, "与上方口令保持一致"), 1)
        root.addLayout(pass_row)

        strength_row = QHBoxLayout()
        strength_row.setSpacing(9)
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 4)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setValue(0)
        strength_row.addWidget(self.strength_bar, 1)
        self.strength_label = QLabel("未设置口令")
        self.strength_label.setProperty("role", "dim")
        self.strength_label.setFixedWidth(92)
        strength_row.addWidget(self.strength_label)
        root.addLayout(strength_row)

        self.agent_check = QCheckBox("生成后添加到 ssh-agent（仅无口令密钥）")
        root.addWidget(self.agent_check)

        self.error_label = QLabel()
        self.error_label.setWordWrap(True)
        self.error_label.setStyleSheet(f"color: {theme()['danger']}; font-size: 11px;")
        self.error_label.hide()
        root.addWidget(self.error_label)

        line = QFrame()
        line.setObjectName("Divider")
        line.setFixedHeight(1)
        root.addWidget(line)

        footer = QHBoxLayout()
        footer.setSpacing(8)
        info = QLabel("私钥权限会自动限制为当前用户。")
        info.setProperty("role", "dim")
        footer.addWidget(info)
        footer.addStretch(1)
        self.cancel_button = make_button("取消", "secondary")
        self.cancel_button.clicked.connect(self.reject)
        footer.addWidget(self.cancel_button)
        self.generate_button = make_button("生成密钥", "primary", icon_name="mdi.key-plus")
        self.generate_button.clicked.connect(self._start_generate)
        footer.addWidget(self.generate_button)
        root.addLayout(footer)

    def _field(self, label: str, widget: QWidget, hint: str = "") -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)
        name = QLabel(label)
        name.setProperty("role", "muted")
        layout.addWidget(name)
        layout.addWidget(widget)
        if hint:
            hint_label = QLabel(hint)
            hint_label.setProperty("role", "dim")
            layout.addWidget(hint_label)
        return container

    def _name_edit(self) -> QLineEdit:
        self.name_edit = QLineEdit(default_key_name("ed25519"))
        self.name_edit.textEdited.connect(self._on_name_edited)
        self.name_edit.textChanged.connect(self._update_preview)
        return self.name_edit

    def _build_bits_field(self) -> QWidget:
        self.bits_combo = QComboBox()
        self.bits_combo.setEditable(False)
        self.bits_combo.currentIndexChanged.connect(self._update_preview)
        return self._field("算法参数", self.bits_combo)

    def _passphrase_edit(self) -> QLineEdit:
        self.passphrase_edit = QLineEdit()
        self.passphrase_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase_edit.setPlaceholderText("留空表示不设置口令")
        self.passphrase_edit.textChanged.connect(self._update_strength)
        self.eye_action = self.passphrase_edit.addAction(
            icon("mdi.eye-outline", theme()["dim"]),
            QLineEdit.ActionPosition.TrailingPosition,
        )
        self.eye_action.triggered.connect(self._toggle_echo)
        return self.passphrase_edit

    # ---------------------------------------------------------------- actions
    def _on_name_edited(self, _text: str) -> None:
        self._auto_name = False
        self._update_preview()

    def _on_directory_changed(self, text: str) -> None:
        self.directory = Path(text).expanduser()
        self._update_preview()

    def _on_type(self, index: int) -> None:
        button = self.type_group.button(index)
        if button is None:
            return
        self._key_type = button.property("keyType")
        self._update_type_ui()
        if self._auto_name:
            self.name_edit.setText(self._suggest_name(self._key_type))
        self._update_preview()

    def _update_type_ui(self) -> None:
        self.bits_combo.blockSignals(True)
        self.bits_combo.clear()
        if self._key_type == "ed25519":
            self.bits_combo.addItem("固定 256 位", 256)
            self.bits_combo.setEnabled(False)
            self.type_hint.setText("Ed25519 是当前最推荐的算法：密钥短、速度快，并且没有参数选择上的陷阱，兼容现代 OpenSSH。")
        elif self._key_type == "rsa":
            self.bits_combo.addItem("3072 位（推荐）", 3072)
            self.bits_combo.addItem("4096 位（更强）", 4096)
            self.bits_combo.addItem("2048 位（兼容旧系统）", 2048)
            self.bits_combo.setEnabled(True)
            self.type_hint.setText("RSA 兼容性最好。新密钥建议至少 3072 位，避免继续使用 2048 位以下的密钥。")
        else:
            self.bits_combo.addItem("P-256（推荐）", 256)
            self.bits_combo.addItem("P-384", 384)
            self.bits_combo.addItem("P-521", 521)
            self.bits_combo.setEnabled(True)
            self.type_hint.setText("ECDSA 基于 NIST 曲线，兼容多数现代服务器；部分旧系统可能不支持 P-521。")
        self.bits_combo.blockSignals(False)
        self._update_strength()

    def _toggle_echo(self) -> None:
        hidden = self.passphrase_edit.echoMode() == QLineEdit.EchoMode.Password
        mode = QLineEdit.EchoMode.Normal if hidden else QLineEdit.EchoMode.Password
        self.passphrase_edit.setEchoMode(mode)
        self.confirm_edit.setEchoMode(mode)
        self.eye_action.setIcon(icon("mdi.eye-off-outline" if hidden else "mdi.eye-outline", theme()["dim"]))

    def _suggest_name(self, key_type: str) -> str:
        base = default_key_name(key_type)
        candidate = base
        index = 2
        while (self.directory / candidate).exists() or (self.directory / f"{candidate}.pub").exists():
            candidate = f"{base}_{index}"
            index += 1
        return candidate

    def _update_preview(self) -> None:
        if not hasattr(self, "path_preview"):
            return
        name = self.name_edit.text().strip() if hasattr(self, "name_edit") else ""
        directory = self.directory
        if name:
            preview = directory / name
            self.path_preview.setText(f"将创建：{preview}  与  {preview}.pub")
            exists = preview.exists() or (directory / f"{name}.pub").exists()
            if exists:
                self.path_preview.setStyleSheet(f"color: {theme()['warning']}; font-size: 10px;")
            else:
                self.path_preview.setStyleSheet("")
                self.path_preview.setProperty("role", "dim")
        else:
            self.path_preview.setText("请填写密钥名称")

    def _update_strength(self) -> None:
        password = self.passphrase_edit.text() if hasattr(self, "passphrase_edit") else ""
        self.agent_check.setEnabled(not password)
        if password:
            self.agent_check.setChecked(False)
            self.agent_check.setToolTip("受口令保护的密钥需要手动 ssh-add，所以不会自动加载。")
        else:
            self.agent_check.setToolTip("")

        if not password:
            score = 0
            text = "未设置口令"
            tone = "danger"
        else:
            score = 1
            if len(password) >= 8:
                score += 1
            if len(password) >= 12:
                score += 1
            if any(c.isdigit() for c in password) and any(not c.isalnum() for c in password):
                score += 1
            if len(password) >= 16:
                score = 4
            text = {1: "弱", 2: "一般", 3: "良好", 4: "强"}.get(score, "一般")
            tone = {1: "danger", 2: "warning", 3: "success", 4: "success"}.get(score, "warning")
        self.strength_bar.setValue(score)
        self.strength_bar.setProperty("tone", tone)
        self.strength_bar.style().unpolish(self.strength_bar)
        self.strength_bar.style().polish(self.strength_bar)
        self.strength_label.setText(text)

    def _browse(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "选择密钥保存目录", str(self.directory))
        if selected:
            self.dir_edit.setText(selected)
            self._update_preview()

    def _show_error(self, message: str) -> None:
        self.error_label.setText(message)
        self.error_label.show()

    def _validate(self) -> str | None:
        name = self.name_edit.text().strip()
        error = validate_key_name(name)
        if error:
            return error
        if not str(self.directory).strip():
            return "请选择保存目录"
        if self.passphrase_edit.text() != self.confirm_edit.text():
            return "两次输入的口令不一致"
        if not self.directory.exists() and not self.directory.parent.exists():
            return "保存位置的上级目录不存在"
        if self.passphrase_edit.text() and len(self.passphrase_edit.text()) < 5:
            return "口令太短，建议至少 8 个字符"
        return None

    def _start_generate(self) -> None:
        if self._busy:
            return
        self.error_label.hide()
        error = self._validate()
        if error:
            self._show_error(error)
            return
        self._busy = True
        self.generate_button.setEnabled(False)
        self.generate_button.setText("正在生成…")
        self.cancel_button.setEnabled(False)
        self.name_edit.setEnabled(False)
        self.dir_edit.setEnabled(False)
        QApplication.processEvents()
        QTimer.singleShot(40, self._generate)

    def _generate(self) -> None:
        if not self.isVisible():
            self._busy = False
            return
        bits = self.bits_combo.currentData()
        result = generate_ssh_key(
            key_type=self._key_type,
            directory=self.directory,
            name=self.name_edit.text().strip(),
            comment=self.comment_edit.text().strip(),
            passphrase=self.passphrase_edit.text(),
            bits=bits if self._key_type != "ed25519" else None,
            add_agent=self.agent_check.isChecked(),
        )
        self._busy = False
        if not result.ok:
            self.generate_button.setEnabled(True)
            self.generate_button.setText("生成密钥")
            self.cancel_button.setEnabled(True)
            self.name_edit.setEnabled(True)
            self.dir_edit.setEnabled(True)
            self._show_error(result.message)
            return
        self.result = result
        self.accept()
