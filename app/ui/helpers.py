from __future__ import annotations

import os
import subprocess
from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import QMessageBox, QWidget


def clear_layout(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()
        elif item.layout() is not None:
            clear_layout(item.layout())


def copy_text(text: str) -> None:
    QGuiApplication.clipboard().setText(text or "")


def open_local_path(path: str | Path, *, select: bool = False) -> bool:
    target = Path(path).expanduser()
    if not target.exists():
        return False
    if os.name == "nt" and select and target.is_file():
        try:
            subprocess.Popen(["explorer", "/select,", str(target)])
            return True
        except OSError:
            pass
    return QDesktopServices.openUrl(QUrl.fromLocalFile(str(target)))


def show_error(parent: QWidget, title: str, text: str) -> None:
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Warning)
    box.setWindowTitle(title)
    box.setText(text)
    box.setStandardButtons(QMessageBox.StandardButton.Ok)
    box.exec()


def show_confirm(parent: QWidget, title: str, text: str) -> bool:
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Question)
    box.setWindowTitle(title)
    box.setText(text)
    box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
    box.setDefaultButton(QMessageBox.StandardButton.Cancel)
    return box.exec() == QMessageBox.StandardButton.Yes
