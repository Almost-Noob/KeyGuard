"""Theme tokens and the application stylesheet."""

from __future__ import annotations

from pathlib import Path
from string import Template

from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import QApplication

ASSETS = Path(__file__).resolve().parents[2] / "assets"


DARK: dict[str, str] = {
    "name": "dark",
    "bg": "#070B12",
    "sidebar": "#0A101B",
    "surface": "#0F1726",
    "surface_2": "#141F33",
    "surface_3": "#1C2942",
    "input_bg": "#0B1220",
    "code_bg": "#080E18",
    "border": "#1E2B42",
    "border_strong": "#2B3B58",
    "text": "#EDF2FB",
    "muted": "#94A3BC",
    "dim": "#65758F",
    "primary": "#6E8BFF",
    "primary_hover": "#89A1FF",
    "primary_pressed": "#5874E8",
    "primary_soft": "#246E8BFF",
    "primary_border": "#556FA8",
    "accent": "#2DD4BF",
    "accent_soft": "#222DD4BF",
    "success": "#3DDC97",
    "success_soft": "#223DDC97",
    "warning": "#F6C453",
    "warning_soft": "#26F6C453",
    "danger": "#FB7185",
    "danger_soft": "#26FB7185",
    "info": "#60A5FA",
    "info_soft": "#2260A5FA",
    "hero_start": "#18233B",
    "hero_mid": "#111B2D",
    "hero_end": "#102B2F",
    "hero_border": "#263B59",
    "selection": "#3B5BDB",
    "shadow": "#000000",
}

LIGHT: dict[str, str] = {
    "name": "light",
    "bg": "#F3F6FB",
    "sidebar": "#FFFFFF",
    "surface": "#FFFFFF",
    "surface_2": "#F6F8FC",
    "surface_3": "#EDF2F8",
    "input_bg": "#F8FAFD",
    "code_bg": "#F4F7FB",
    "border": "#E2E8F2",
    "border_strong": "#CBD6E5",
    "text": "#172033",
    "muted": "#5F6E86",
    "dim": "#8A98AD",
    "primary": "#4F6BFF",
    "primary_hover": "#617CFF",
    "primary_pressed": "#3E58E6",
    "primary_soft": "#1F4F6BFF",
    "primary_border": "#B9C6FF",
    "accent": "#0FAF9B",
    "accent_soft": "#1A0FAF9B",
    "success": "#0E9F6E",
    "success_soft": "#1A0E9F6E",
    "warning": "#C27A06",
    "warning_soft": "#22C27A06",
    "danger": "#DC3E58",
    "danger_soft": "#1FDC3E58",
    "info": "#2F7BE8",
    "info_soft": "#1F2F7BE8",
    "hero_start": "#EEF3FF",
    "hero_mid": "#F7F9FF",
    "hero_end": "#E9FBF7",
    "hero_border": "#D8E2F5",
    "selection": "#4F6BFF",
    "shadow": "#8A9AB8",
}

_THEMES = {"dark": DARK, "light": LIGHT}
_active = "dark"


def theme(name: str | None = None) -> dict[str, str]:
    return _THEMES.get(name or _active, DARK)


def active_theme_name() -> str:
    return _active


_QSS = Template(
    r"""
* {
    outline: 0;
}
QWidget {
    color: $text;
    font-family: "Segoe UI Variable Text", "Microsoft YaHei UI", "Segoe UI", "Arial";
    font-size: 13px;
}
QMainWindow, QDialog {
    background: $bg;
}
#AppRoot {
    background: $bg;
}
QToolTip {
    background: $surface_3;
    color: $text;
    border: 1px solid $border_strong;
    border-radius: 7px;
    padding: 6px 9px;
    font-size: 12px;
}

/* ---------------------------------------------------------------- sidebar */
#Sidebar {
    background: $sidebar;
    border-right: 1px solid $border;
}
#Sidebar QLabel {
    background: transparent;
}
#LogoName {
    color: $text;
    font-size: 17px;
    font-weight: 700;
}
#LogoTag {
    color: $dim;
    font-size: 10px;
}
#SidebarSection {
    color: $dim;
    font-size: 10px;
    font-weight: 700;
    padding: 0 10px;
}
#SidebarFooter {
    background: $surface_2;
    border: 1px solid $border;
    border-radius: 12px;
}
QPushButton[nav="true"] {
    background: transparent;
    color: $muted;
    border: 1px solid transparent;
    border-radius: 10px;
    padding: 9px 12px;
    text-align: left;
    font-size: 13px;
    font-weight: 500;
}
QPushButton[nav="true"]:hover {
    background: $surface_2;
    color: $text;
}
QPushButton[nav="true"]:checked {
    background: $primary_soft;
    color: $primary;
    border: 1px solid $primary_border;
    font-weight: 600;
}
QPushButton[nav="true"]:checked:hover {
    background: $primary_soft;
}

/* ----------------------------------------------------------------- header */
#Header {
    background: transparent;
}
#PageTitle {
    color: $text;
    font-size: 25px;
    font-weight: 700;
}
#PageSubtitle {
    color: $muted;
    font-size: 12px;
}
#HeaderStatus {
    background: $surface_2;
    border: 1px solid $border;
    border-radius: 11px;
    color: $muted;
    padding: 5px 11px;
    font-size: 11px;
}
#StatusDot {
    border-radius: 4px;
    min-width: 8px;
    max-width: 8px;
    min-height: 8px;
    max-height: 8px;
}
#PathChip {
    color: $muted;
    background: $surface_2;
    border: 1px solid $border;
    border-radius: 9px;
    padding: 4px 9px;
    font-size: 11px;
    font-family: "Cascadia Code", "Consolas", monospace;
}

/* ------------------------------------------------------------------ cards */
QFrame#Card {
    background: $surface;
    border: 1px solid $border;
    border-radius: 16px;
}
QFrame#HeroCard {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 $hero_start, stop:0.55 $hero_mid, stop:1 $hero_end);
    border: 1px solid $hero_border;
    border-radius: 20px;
}
QFrame#InnerCard {
    background: $surface_2;
    border: 1px solid $border;
    border-radius: 12px;
}
QFrame#KeyRow, QFrame#HostRow, QFrame#FindingRow {
    background: $surface;
    border: 1px solid $border;
    border-radius: 14px;
}
QFrame#KeyRow:hover, QFrame#HostRow:hover, QFrame#FindingRow:hover {
    background: $surface_2;
    border-color: $border_strong;
}
QFrame#KeyRow[selected="true"], QFrame#HostRow[selected="true"] {
    background: $surface_2;
    border: 1px solid $primary;
}
QFrame#ComponentCard {
    background: $surface_2;
    border: 1px solid $border;
    border-radius: 13px;
}
QFrame#Divider {
    background: $border;
    border: none;
    min-height: 1px;
    max-height: 1px;
}
QFrame#Toast {
    background: $surface_3;
    border: 1px solid $border_strong;
    border-radius: 12px;
}
QFrame#DialogHeader {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 $primary_soft, stop:1 transparent);
    border: none;
    border-radius: 14px;
}
QFrame#SegmentBar {
    background: $surface_2;
    border: 1px solid $border;
    border-radius: 12px;
}

/* ----------------------------------------------------------------- labels */
QLabel {
    background: transparent;
}
QLabel[role="muted"] { color: $muted; }
QLabel[role="dim"] { color: $dim; font-size: 11px; }
QLabel[role="cardTitle"] {
    color: $text;
    font-size: 15px;
    font-weight: 600;
}
QLabel[role="sectionTitle"] {
    color: $text;
    font-size: 16px;
    font-weight: 650;
}
QLabel[role="statValue"] {
    color: $text;
    font-size: 28px;
    font-weight: 700;
}
QLabel[role="statLabel"] {
    color: $muted;
    font-size: 12px;
}
QLabel[role="mono"] {
    font-family: "Cascadia Code", "JetBrains Mono", "Consolas", monospace;
    font-size: 12px;
    color: $text;
}
QLabel[role="eyebrow"] {
    color: $accent;
    font-size: 11px;
    font-weight: 700;
}
QLabel#HeroTitle {
    color: $text;
    font-size: 24px;
    font-weight: 700;
}
QLabel#FingerprintLarge {
    color: $text;
    font-family: "Cascadia Code", "JetBrains Mono", "Consolas", monospace;
    font-size: 14px;
    font-weight: 500;
}
QLabel#DialogTitle {
    color: $text;
    font-size: 19px;
    font-weight: 700;
}
QLabel#EmptyTitle {
    color: $text;
    font-size: 16px;
    font-weight: 600;
}
QLabel#EmptyText {
    color: $muted;
    font-size: 12px;
}
QLabel[badge="true"] {
    border-radius: 9px;
    padding: 2px 9px;
    font-size: 11px;
    font-weight: 600;
}
QLabel[badge="true"][tone="primary"] {
    background: $primary_soft;
    color: $primary;
}
QLabel[badge="true"][tone="success"] {
    background: $success_soft;
    color: $success;
}
QLabel[badge="true"][tone="warning"] {
    background: $warning_soft;
    color: $warning;
}
QLabel[badge="true"][tone="danger"] {
    background: $danger_soft;
    color: $danger;
}
QLabel[badge="true"][tone="info"] {
    background: $info_soft;
    color: $info;
}
QLabel[badge="true"][tone="muted"] {
    background: $surface_3;
    color: $muted;
}
QLabel[badge="true"][tone="accent"] {
    background: $accent_soft;
    color: $accent;
}

/* ---------------------------------------------------------------- buttons */
QPushButton {
    border: none;
    background: transparent;
    color: $text;
}
QPushButton[variant="primary"] {
    background: $primary;
    color: #FFFFFF;
    border: 1px solid $primary;
    border-radius: 10px;
    padding: 9px 16px;
    font-weight: 600;
}
QPushButton[variant="primary"]:hover {
    background: $primary_hover;
    border-color: $primary_hover;
}
QPushButton[variant="primary"]:pressed {
    background: $primary_pressed;
}
QPushButton[variant="secondary"] {
    background: $surface_2;
    color: $text;
    border: 1px solid $border_strong;
    border-radius: 10px;
    padding: 8px 14px;
    font-weight: 500;
}
QPushButton[variant="secondary"]:hover {
    background: $surface_3;
    border-color: $primary_border;
}
QPushButton[variant="ghost"] {
    background: transparent;
    color: $muted;
    border: 1px solid transparent;
    border-radius: 9px;
    padding: 8px 12px;
    font-weight: 500;
}
QPushButton[variant="ghost"]:hover {
    background: $surface_2;
    color: $text;
}
QPushButton[variant="danger"] {
    background: $danger_soft;
    color: $danger;
    border: 1px solid transparent;
    border-radius: 9px;
    padding: 8px 12px;
    font-weight: 500;
}
QPushButton[variant="danger"]:hover {
    border-color: $danger;
}
QPushButton[variant="segment"] {
    background: transparent;
    color: $muted;
    border: 1px solid transparent;
    border-radius: 8px;
    padding: 7px 12px;
    font-size: 12px;
    font-weight: 600;
}
QPushButton[variant="segment"]:hover {
    color: $text;
    background: $surface_3;
}
QPushButton[variant="segment"]:checked {
    background: $primary_soft;
    color: $primary;
    border: 1px solid $primary_border;
}
QPushButton[variant="icon"] {
    background: transparent;
    color: $muted;
    border: 1px solid transparent;
    border-radius: 8px;
    padding: 5px;
}
QPushButton[variant="icon"]:hover {
    background: $surface_2;
    color: $text;
}
QPushButton[variant="link"] {
    color: $primary;
    background: transparent;
    padding: 2px;
    font-weight: 600;
}
QPushButton[variant="link"]:hover {
    color: $primary_hover;
}
QPushButton:disabled {
    color: $dim;
    background: $surface_2;
    border-color: $border;
}
QToolButton {
    background: transparent;
    color: $muted;
    border: none;
    border-radius: 8px;
    padding: 5px;
}
QToolButton:hover {
    background: $surface_2;
    color: $text;
}

/* ----------------------------------------------------------------- inputs */
QLineEdit, QComboBox, QSpinBox {
    background: $input_bg;
    color: $text;
    border: 1px solid $border;
    border-radius: 10px;
    padding: 8px 12px;
    min-height: 19px;
    selection-background-color: $selection;
    selection-color: #FFFFFF;
}
QLineEdit:hover, QComboBox:hover, QSpinBox:hover {
    border-color: $border_strong;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid $primary;
}
QLineEdit:disabled, QComboBox:disabled {
    color: $dim;
    background: $surface_2;
}
QComboBox::drop-down {
    border: none;
    width: 28px;
}
QComboBox::down-arrow {
    image: url("$ASSETS/chevron-down.svg");
    width: 12px;
    height: 8px;
}
QComboBox QAbstractItemView {
    background: $surface_2;
    color: $text;
    border: 1px solid $border_strong;
    border-radius: 8px;
    padding: 5px;
    selection-background-color: $primary_soft;
    selection-color: $primary;
    outline: none;
}
QPlainTextEdit, QTextEdit {
    background: $code_bg;
    color: $text;
    border: 1px solid $border;
    border-radius: 10px;
    padding: 9px;
    font-family: "Cascadia Code", "JetBrains Mono", "Consolas", monospace;
    font-size: 12px;
    selection-background-color: $selection;
    selection-color: #FFFFFF;
}
QPlainTextEdit:focus, QTextEdit:focus {
    border-color: $primary_border;
}
QCheckBox {
    color: $muted;
    spacing: 8px;
    font-size: 12px;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 5px;
    border: 1px solid $border_strong;
    background: $input_bg;
}
QCheckBox::indicator:hover {
    border-color: $primary;
}
QCheckBox::indicator:checked {
    background: $primary;
    border-color: $primary;
    image: url("$ASSETS/check.svg");
}
QProgressBar {
    background: $surface_3;
    border: none;
    border-radius: 4px;
    min-height: 6px;
    max-height: 6px;
    color: transparent;
}
QProgressBar::chunk {
    background: $primary;
    border-radius: 4px;
}
QProgressBar[tone="warning"]::chunk { background: $warning; }
QProgressBar[tone="success"]::chunk { background: $success; }
QProgressBar[tone="danger"]::chunk { background: $danger; }

/* ----------------------------------------------------------------- scroll */
QScrollArea {
    background: transparent;
    border: none;
}
QScrollArea > QWidget > QWidget {
    background: transparent;
}
QAbstractScrollArea::corner {
    background: transparent;
}
QScrollBar:vertical {
    background: transparent;
    width: 10px;
    margin: 2px;
}
QScrollBar::handle:vertical {
    background: $border_strong;
    min-height: 32px;
    border-radius: 4px;
}
QScrollBar::handle:vertical:hover {
    background: $dim;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: transparent;
}
QScrollBar:horizontal {
    background: transparent;
    height: 10px;
    margin: 2px;
}
QScrollBar::handle:horizontal {
    background: $border_strong;
    min-width: 32px;
    border-radius: 4px;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

/* ------------------------------------------------------------------ misc */
QSplitter::handle {
    background: transparent;
}
QMenu {
    background: $surface_2;
    color: $text;
    border: 1px solid $border_strong;
    border-radius: 10px;
    padding: 5px;
}
QMenu::item {
    padding: 7px 22px 7px 11px;
    border-radius: 6px;
}
QMenu::item:selected {
    background: $primary_soft;
    color: $primary;
}
QMenu::separator {
    height: 1px;
    background: $border;
    margin: 5px 8px;
}
QFileDialog {
    background: $bg;
}
QTabWidget::pane {
    border: none;
}
QTabBar::tab {
    background: transparent;
    color: $muted;
    padding: 8px 14px;
    border-radius: 8px;
}
QTabBar::tab:selected {
    background: $primary_soft;
    color: $primary;
}
"""
)


def build_stylesheet(name: str) -> str:
    tokens = dict(theme(name))
    tokens["ASSETS"] = ASSETS.as_posix()
    return _QSS.substitute(tokens)


def apply_theme(app: QApplication, name: str) -> dict[str, str]:
    global _active
    _active = name if name in _THEMES else "dark"
    tokens = theme(_active)

    app.setStyle("Fusion")
    app.setStyleSheet(build_stylesheet(_active))

    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(tokens["bg"]))
    palette.setColor(QPalette.ColorRole.Base, QColor(tokens["input_bg"]))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(tokens["surface_2"]))
    palette.setColor(QPalette.ColorRole.Text, QColor(tokens["text"]))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(tokens["text"]))
    palette.setColor(QPalette.ColorRole.Button, QColor(tokens["surface_2"]))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(tokens["text"]))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(tokens["primary"]))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#FFFFFF"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(tokens["surface_3"]))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(tokens["text"]))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor(tokens["dim"]))
    app.setPalette(palette)
    return tokens


def base_font() -> QFont:
    font = QFont()
    font.setFamilies(
        [
            "Segoe UI Variable Text",
            "Microsoft YaHei UI",
            "Segoe UI",
            "Arial",
        ]
    )
    font.setPointSize(10)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    return font
