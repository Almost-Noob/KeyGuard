"""KeyGuard — a local-first SSH key and device fingerprint manager."""

from __future__ import annotations

import argparse
import ctypes
import os
import sys

from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QGuiApplication, QIcon
from PySide6.QtWidgets import QApplication

from app.ui.main_window import MainWindow
from app.ui.theme import ASSETS, apply_theme, base_font


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="KeyGuard SSH key and device fingerprint manager")
    parser.add_argument("--ssh-dir", help="SSH directory to inspect (default: ~/.ssh)")
    parser.add_argument("--theme", choices=("dark", "light"), help="UI theme")
    args, _ = parser.parse_known_args()
    return args


def main() -> int:
    args = _parse_args()

    if os.name == "nt":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("KeyGuard.SSH.IdentityManager")
        except Exception:
            pass

    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("KeyGuard")
    app.setOrganizationName("KeyGuard")
    app.setApplicationDisplayName("KeyGuard")
    app.setApplicationVersion("1.0.0")
    app.setFont(base_font())
    app.setWindowIcon(QIcon(str(ASSETS / "logo.svg")))

    settings = QSettings("KeyGuard", "SSH Key Manager")
    theme_name = args.theme or str(settings.value("theme", "dark"))
    if theme_name not in ("dark", "light"):
        theme_name = "dark"
    apply_theme(app, theme_name)

    window = MainWindow(ssh_dir=args.ssh_dir)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
