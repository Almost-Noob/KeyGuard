"""Main application window and navigation."""

from __future__ import annotations

import ctypes
import os
import re
from pathlib import Path

from PySide6.QtCore import QSettings, QSize, Qt
from PySide6.QtGui import QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app.core.device import DeviceFingerprint, collect_device_fingerprint
from app.core.ssh import ScanResult, scan_system
from app.ui.dialogs import GenerateKeyDialog
from app.ui.pages.audit import AuditPage
from app.ui.pages.config import ConfigPage
from app.ui.pages.device import DevicePage
from app.ui.pages.hosts import HostsPage
from app.ui.pages.keys import KeysPage
from app.ui.pages.overview import OverviewPage
from app.ui.theme import ASSETS, active_theme_name, apply_theme, theme
from app.ui.widgets import Toast, icon, icon_button

PAGE_SPECS = [
    ("概览", "本机 SSH 身份与安全状态一览", "mdi.view-dashboard-outline"),
    ("密钥库", "管理系统中的 SSH 密钥对与公钥授权", "mdi.key-outline"),
    ("已知主机", "known_hosts 中已信任的服务器主机密钥", "mdi.server-network"),
    ("SSH 配置", "解析 ~/.ssh/config 中的主机别名与连接参数", "mdi.file-cog-outline"),
    ("设备指纹", "由硬件与系统标识计算出的稳定设备身份", "mdi.fingerprint"),
    ("安全检查", "针对本机 SSH 密钥、权限与配置的风险建议", "mdi.shield-check-outline"),
]


class MainWindow(QMainWindow):
    def __init__(
        self,
        ssh_dir: str | None = None,
        parent: QWidget | None = None,
        *,
        scan: ScanResult | None = None,
        device: DeviceFingerprint | None = None,
    ):
        super().__init__(parent)
        self.settings = QSettings("KeyGuard", "SSH Key Manager")
        self.ssh_dir = str(Path(ssh_dir).expanduser().resolve()) if ssh_dir else str(Path.home() / ".ssh")
        self.theme_name = active_theme_name()
        self._selected_key: str | None = None
        self._device: DeviceFingerprint | None = device
        self._current_index = 0
        self._scanning = False

        self.setWindowTitle("KeyGuard · SSH 密钥与设备指纹管理器")
        self.setWindowIcon(QIcon(str(ASSETS / "logo.svg")))
        self.setMinimumSize(1180, 760)

        if scan is not None:
            self.scan = scan
            self.ssh_dir = scan.ssh_dir
        else:
            self.scan = self._run_scan(initial=True)
        self._build_ui()
        self._restore_geometry()
        self._install_shortcuts()

    # ------------------------------------------------------------------ scan
    def _run_scan(self, initial: bool = False) -> ScanResult:
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            return scan_system(self.ssh_dir)
        finally:
            QApplication.restoreOverrideCursor()

    def refresh_scan(self, notify: bool = True) -> None:
        if self._scanning:
            return
        self._scanning = True
        self._set_status("正在扫描…", "warning")
        QApplication.processEvents()
        try:
            self.scan = self._run_scan()
            self._device = None
            self._rebuild_pages()
            self._update_sidebar_status()
            self._set_status(
                f"已扫描 {self.scan.scanned_at.strftime('%H:%M:%S')}",
                "success",
            )
            if notify:
                count = len(self.scan.keys)
                self.show_toast(f"扫描完成，发现 {count} 个密钥、{self.scan.unique_known_hosts} 台已知主机", "success")
        except Exception as exc:
            self._set_status("扫描失败", "danger")
            self.show_toast(f"扫描失败：{exc}", "danger")
        finally:
            self._scanning = False

    # ------------------------------------------------------------------- ui
    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("AppRoot")
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._build_sidebar())

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(28, 20, 28, 18)
        content_layout.setSpacing(14)
        content_layout.addWidget(self._build_header())
        self.stack = QStackedWidget()
        content_layout.addWidget(self.stack, 1)
        layout.addWidget(content, 1)

        self.toast = Toast(central)
        self.setCentralWidget(central)
        self._build_pages()
        self.navigate(self._current_index, force=True)
        self._update_sidebar_status()

    def _build_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(236)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(14, 20, 14, 16)
        layout.setSpacing(6)

        logo_row = QHBoxLayout()
        logo_row.setSpacing(11)
        logo = QLabel()
        logo.setPixmap(QIcon(str(ASSETS / "logo.svg")).pixmap(42, 42))
        logo_row.addWidget(logo)
        name_box = QVBoxLayout()
        name_box.setSpacing(1)
        name = QLabel("KeyGuard")
        name.setObjectName("LogoName")
        name_box.addWidget(name)
        tag = QLabel("SSH IDENTITY MANAGER")
        tag.setObjectName("LogoTag")
        name_box.addWidget(tag)
        logo_row.addLayout(name_box)
        logo_row.addStretch(1)
        layout.addLayout(logo_row)
        layout.addSpacing(22)

        section = QLabel("工作台")
        section.setObjectName("SidebarSection")
        layout.addWidget(section)
        layout.addSpacing(2)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self.nav_buttons: list[QPushButton] = []
        for index in range(3):
            self._add_nav_button(layout, index)
        layout.addSpacing(14)
        section2 = QLabel("系统与安全")
        section2.setObjectName("SidebarSection")
        layout.addWidget(section2)
        layout.addSpacing(2)
        for index in range(3, 6):
            self._add_nav_button(layout, index)
        layout.addStretch(1)

        footer = QFrame()
        footer.setObjectName("SidebarFooter")
        footer_layout = QVBoxLayout(footer)
        footer_layout.setContentsMargins(12, 11, 12, 11)
        footer_layout.setSpacing(6)
        top = QHBoxLayout()
        top.setSpacing(7)
        self.sidebar_dot = QLabel()
        self.sidebar_dot.setFixedSize(7, 7)
        self.sidebar_dot.setStyleSheet(f"background: {theme()['success']}; border-radius: 3px;")
        top.addWidget(self.sidebar_dot)
        self.sidebar_version = QLabel("OpenSSH")
        self.sidebar_version.setStyleSheet("font-size: 11px; font-weight: 600;")
        top.addWidget(self.sidebar_version, 1)
        footer_layout.addLayout(top)
        self.sidebar_agent = QLabel()
        self.sidebar_agent.setProperty("role", "dim")
        footer_layout.addWidget(self.sidebar_agent)
        self.sidebar_path = QLabel()
        self.sidebar_path.setObjectName("PathChip")
        self.sidebar_path.setWordWrap(False)
        footer_layout.addWidget(self.sidebar_path)
        layout.addWidget(footer)

        version = QLabel("KeyGuard 1.0 · 本地优先")
        version.setProperty("role", "dim")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(version)
        self.nav_group.idClicked.connect(self.navigate)
        return sidebar

    def _add_nav_button(self, layout: QVBoxLayout, index: int) -> None:
        label, subtitle, icon_name = PAGE_SPECS[index]
        button = QPushButton(label)
        button.setProperty("nav", True)
        button.setCheckable(True)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.setFixedHeight(40)
        button.setIcon(icon(icon_name, theme()["muted"]))
        button.setIconSize(QSize(18, 18))
        button.setProperty("iconName", icon_name)
        button.setToolTip(subtitle)
        self.nav_group.addButton(button, index)
        self.nav_buttons.append(button)
        layout.addWidget(button)

    def _build_header(self) -> QWidget:
        header = QWidget()
        header.setObjectName("Header")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(10)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        self.title_label = QLabel("概览")
        self.title_label.setObjectName("PageTitle")
        self.subtitle_label = QLabel(PAGE_SPECS[0][1])
        self.subtitle_label.setObjectName("PageSubtitle")
        title_box.addWidget(self.title_label)
        title_box.addWidget(self.subtitle_label)
        layout.addLayout(title_box, 1)

        path = QLabel(self._display_ssh_dir())
        path.setObjectName("PathChip")
        path.setToolTip(self.ssh_dir)
        layout.addWidget(path, 0, Qt.AlignmentFlag.AlignVCenter)

        status_frame = QFrame()
        status_frame.setObjectName("HeaderStatus")
        status_layout = QHBoxLayout(status_frame)
        status_layout.setContentsMargins(10, 5, 11, 5)
        status_layout.setSpacing(6)
        self.status_dot = QLabel()
        self.status_dot.setFixedSize(8, 8)
        status_layout.addWidget(self.status_dot)
        self.status_label = QLabel()
        self.status_label.setStyleSheet("font-size: 11px;")
        status_layout.addWidget(self.status_label)
        layout.addWidget(status_frame, 0, Qt.AlignmentFlag.AlignVCenter)

        self.refresh_button = icon_button("mdi.refresh", "重新扫描 SSH 状态 (Ctrl+R)", size=34, icon_size=17)
        self.refresh_button.clicked.connect(lambda: self.refresh_scan(notify=True))
        layout.addWidget(self.refresh_button)

        self.theme_button = icon_button(self._theme_icon_name(), "切换浅色 / 深色主题", size=34, icon_size=17)
        self.theme_button.clicked.connect(self.toggle_theme)
        layout.addWidget(self.theme_button)

        self._set_status(f"已扫描 {self.scan.scanned_at.strftime('%H:%M:%S')}", "success")
        return header

    def _build_pages(self) -> None:
        while self.stack.count():
            widget = self.stack.widget(0)
            self.stack.removeWidget(widget)
            widget.deleteLater()

        overview = OverviewPage(self.scan)
        overview.generate_requested.connect(self.open_generate_dialog)
        overview.refresh_requested.connect(lambda: self.refresh_scan(True))
        overview.keys_requested.connect(lambda: self.navigate(1))
        overview.audit_requested.connect(lambda: self.navigate(5))
        overview.key_requested.connect(self._on_key_requested)

        keys = KeysPage(self.scan, selected=self._selected_key)
        keys.generate_requested.connect(self.open_generate_dialog)
        keys.notify.connect(self.show_toast)
        keys.selection_changed.connect(self._remember_selection)

        hosts = HostsPage(self.scan)
        hosts.notify.connect(self.show_toast)

        config = ConfigPage(self.scan)
        config.notify.connect(self.show_toast)

        if self._device is None:
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            try:
                self._device = collect_device_fingerprint()
            finally:
                QApplication.restoreOverrideCursor()
        device = DevicePage(self._device)
        device.notify.connect(self.show_toast)

        audit = AuditPage(self.scan)
        audit.refresh_requested.connect(lambda: self.refresh_scan(True))

        for page in (overview, keys, hosts, config, device, audit):
            self.stack.addWidget(page)
        self.pages = [overview, keys, hosts, config, device, audit]
        self._update_sidebar_status()

    def _rebuild_pages(self) -> None:
        self._build_pages()
        self.navigate(self._current_index, force=True)

    def navigate(self, index: int, force: bool = False) -> None:
        if index < 0 or index >= len(PAGE_SPECS):
            return
        self._current_index = index
        if hasattr(self, "stack") and self.stack.count() > index:
            self.stack.setCurrentIndex(index)
        for button_index, button in enumerate(getattr(self, "nav_buttons", [])):
            button.setChecked(button_index == index)
            icon_name = button.property("iconName")
            if icon_name:
                button.setIcon(icon(icon_name, theme()["primary"] if button_index == index else theme()["muted"]))
        if hasattr(self, "title_label"):
            self.title_label.setText(PAGE_SPECS[index][0])
            self.subtitle_label.setText(PAGE_SPECS[index][1])

    def _on_key_requested(self, name: str) -> None:
        self._selected_key = name
        if hasattr(self, "pages") and len(self.pages) > 1:
            try:
                self.pages[1]._select(name)
            except Exception:
                pass
        self.navigate(1)

    def _remember_selection(self, name: str) -> None:
        self._selected_key = name

    # --------------------------------------------------------------- actions
    def open_generate_dialog(self) -> None:
        dialog = GenerateKeyDialog(self.scan.ssh_dir, self)
        if dialog.exec() != GenerateKeyDialog.DialogCode.Accepted or dialog.result is None:
            return
        result = dialog.result
        if result.key:
            self._selected_key = result.key.name
        else:
            self._selected_key = Path(result.private_path).name
        self.refresh_scan(notify=False)
        self.navigate(1)
        message = "密钥已生成"
        if result.fingerprint:
            message += f" · {result.fingerprint[:28]}…"
        if result.agent_added:
            message += "，已加载到 ssh-agent"
        elif result.agent_message:
            message += f"；{result.agent_message}"
        self.show_toast(message, "success" if result.agent_added or not result.agent_message else "warning")

    def toggle_theme(self) -> None:
        new_name = "light" if self.theme_name == "dark" else "dark"
        index = self._current_index
        if hasattr(self, "pages") and len(self.pages) > 4:
            self._device = self.pages[4].fingerprint
        self.theme_name = new_name
        apply_theme(QApplication.instance(), new_name)
        self.settings.setValue("theme", new_name)
        self._build_ui()
        self.navigate(index, force=True)
        self._apply_native_title_bar()

    def _theme_icon_name(self) -> str:
        return "mdi.weather-night" if self.theme_name == "dark" else "mdi.white-balance-sunny"

    def show_toast(self, message: str, tone: str = "success") -> None:
        if hasattr(self, "toast"):
            self.toast.show_message(message, tone)

    def _set_status(self, text: str, tone: str = "success") -> None:
        color = theme().get(tone, theme()["success"])
        if hasattr(self, "status_dot"):
            self.status_dot.setStyleSheet(f"background: {color}; border-radius: 4px;")
        if hasattr(self, "status_label"):
            self.status_label.setText(text)

    def _update_sidebar_status(self) -> None:
        if not hasattr(self, "sidebar_version"):
            return
        match = re.search(r"OpenSSH(?: for Windows)?\s+([0-9][0-9A-Za-z.\-]*)", self.scan.ssh_version)
        version = f"OpenSSH {match.group(1)}" if match else "OpenSSH"
        self.sidebar_version.setText(version)
        self.sidebar_version.setToolTip(self.scan.ssh_version)
        if self.scan.agent.running:
            self.sidebar_agent.setText(f"agent · {len(self.scan.agent.keys)} 把密钥")
            color = theme()["success"]
        else:
            self.sidebar_agent.setText("agent 未运行")
            color = theme()["dim"]
        if hasattr(self, "sidebar_dot"):
            self.sidebar_dot.setStyleSheet(f"background: {color}; border-radius: 3px;")
        path = self._display_ssh_dir()
        self.sidebar_path.setText(path)
        self.sidebar_path.setToolTip(self.scan.ssh_dir)

    def _display_ssh_dir(self) -> str:
        home = str(Path.home())
        if self.scan.ssh_dir.startswith(home):
            suffix = self.scan.ssh_dir[len(home) :].lstrip("\\/")
            return "~/" + suffix.replace("\\", "/")
        path = Path(self.scan.ssh_dir)
        if len(self.scan.ssh_dir) > 28:
            return f"…/{path.name}"
        return self.scan.ssh_dir

    # --------------------------------------------------------------- system
    def _install_shortcuts(self) -> None:
        QShortcut(QKeySequence("Ctrl+R"), self, activated=lambda: self.refresh_scan(True))
        QShortcut(QKeySequence("Ctrl+N"), self, activated=self.open_generate_dialog)
        for index in range(6):
            QShortcut(QKeySequence(f"Ctrl+{index + 1}"), self, activated=lambda i=index: self.navigate(i))
        QShortcut(QKeySequence("Ctrl+Q"), self, activated=self.close)

    def _restore_geometry(self) -> None:
        geometry = self.settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)
        else:
            self.resize(1420, 900)
            screen = QApplication.primaryScreen()
            if screen is not None:
                available = screen.availableGeometry()
                self.move(
                    available.x() + max(0, (available.width() - self.width()) // 2),
                    available.y() + max(0, (available.height() - self.height()) // 2),
                )

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self._apply_native_title_bar()

    def _apply_native_title_bar(self) -> None:
        if os.name != "nt":
            return
        try:
            hwnd = int(self.winId())
            value = ctypes.c_int(1 if self.theme_name == "dark" else 0)
            for attribute in (20, 19):
                result = ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd,
                    attribute,
                    ctypes.byref(value),
                    ctypes.sizeof(value),
                )
                if result == 0:
                    break
        except Exception:
            pass

    def closeEvent(self, event) -> None:  # noqa: N802
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("theme", self.theme_name)
        super().closeEvent(event)
