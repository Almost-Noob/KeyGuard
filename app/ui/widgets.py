"""Reusable UI primitives for KeyGuard."""

from __future__ import annotations

import qtawesome as qta
from PySide6.QtCore import QEasingCurve, QEvent, QPropertyAnimation, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QGuiApplication, QIcon, QPainter, QPen
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.ui.theme import active_theme_name, theme

_ICON_CACHE: dict[tuple[str, str, str], QIcon] = {}


def icon(name: str, color: str | None = None) -> QIcon:
    tokens = theme()
    color = color or tokens["muted"]
    key = (name, color, active_theme_name())
    cached = _ICON_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        result = qta.icon(name, color=color)
    except Exception:
        result = qta.icon("mdi.circle-outline", color=color)
    _ICON_CACHE[key] = result
    return result


def repolish(widget: QWidget) -> None:
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    widget.update()


def set_prop(widget: QWidget, name: str, value: object) -> None:
    widget.setProperty(name, value)
    repolish(widget)


def tone_color(tone: str) -> str:
    tokens = theme()
    return tokens.get(tone, tokens["primary"])


def tone_soft(tone: str) -> str:
    tokens = theme()
    return tokens.get(f"{tone}_soft", tokens["primary_soft"])


def elide_middle(text: str, max_chars: int = 32) -> str:
    if len(text) <= max_chars:
        return text
    keep = max(6, (max_chars - 1) // 2)
    return f"{text[:keep]}…{text[-keep:]}"


class IconBadge(QFrame):
    """A rounded, tinted icon tile."""

    def __init__(
        self,
        icon_name: str,
        tone: str = "primary",
        size: int = 40,
        icon_size: int = 20,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.setStyleSheet(
            f"IconBadge {{ background: {tone_soft(tone)}; border-radius: {max(10, size // 3)}px; }}"
        )
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.label = QLabel(self)
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setPixmap(icon(icon_name, tone_color(tone)).pixmap(icon_size, icon_size))
        layout.addWidget(self.label)


class Badge(QLabel):
    def __init__(self, text: str = "", tone: str = "muted", parent: QWidget | None = None):
        super().__init__(text, parent)
        self.setProperty("badge", True)
        self.setProperty("tone", tone)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        self.setContentsMargins(0, 1, 0, 1)

    def set_tone(self, tone: str) -> None:
        set_prop(self, "tone", tone)


def badge(text: str, tone: str = "muted") -> Badge:
    return Badge(text, tone)


class Card(QFrame):
    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        object_name: str = "Card",
        margins: tuple[int, int, int, int] = (20, 18, 20, 18),
        spacing: int = 12,
    ):
        super().__init__(parent)
        self.setObjectName(object_name)
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(*margins)
        self.body.setSpacing(spacing)

    def add(self, widget: QWidget) -> QWidget:
        self.body.addWidget(widget)
        return widget

    def add_layout(self, layout) -> None:
        self.body.addLayout(layout)


class SectionCard(Card):
    def __init__(
        self,
        title: str,
        subtitle: str = "",
        *,
        icon_name: str | None = None,
        action: QWidget | None = None,
        parent: QWidget | None = None,
        margins: tuple[int, int, int, int] = (20, 18, 20, 18),
        spacing: int = 12,
    ):
        super().__init__(parent, margins=margins, spacing=spacing)
        header = QHBoxLayout()
        header.setSpacing(10)
        if icon_name:
            header.addWidget(IconBadge(icon_name, "primary", 34, 17))
        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        title_label = QLabel(title)
        title_label.setProperty("role", "cardTitle")
        title_box.addWidget(title_label)
        if subtitle:
            subtitle_label = QLabel(subtitle)
            subtitle_label.setProperty("role", "muted")
            subtitle_label.setWordWrap(True)
            title_box.addWidget(subtitle_label)
        header.addLayout(title_box, 1)
        if action is not None:
            header.addWidget(action, 0, Qt.AlignmentFlag.AlignVCenter)
        self.body.addLayout(header)
        self.content = QVBoxLayout()
        self.content.setSpacing(spacing)
        self.body.addLayout(self.content)
        self.body.addStretch(1)

    def add_content(self, widget: QWidget) -> QWidget:
        self.content.addWidget(widget)
        return widget


class StatCard(Card):
    def __init__(
        self,
        label: str,
        value: str = "—",
        hint: str = "",
        *,
        icon_name: str,
        tone: str = "primary",
        parent: QWidget | None = None,
    ):
        super().__init__(parent, margins=(17, 15, 17, 15), spacing=9)
        top = QHBoxLayout()
        top.setSpacing(10)
        self.badge = IconBadge(icon_name, tone, 36, 18)
        top.addWidget(self.badge)
        top.addStretch(1)
        self.hint = QLabel(hint)
        self.hint.setProperty("role", "dim")
        top.addWidget(self.hint, 0, Qt.AlignmentFlag.AlignTop)
        self.body.addLayout(top)

        self.value_label = QLabel(value)
        self.value_label.setProperty("role", "statValue")
        self.body.addWidget(self.value_label)
        self.label = QLabel(label)
        self.label.setProperty("role", "statLabel")
        self.body.addWidget(self.label)

    def set_value(self, value: str) -> None:
        self.value_label.setText(value)

    def set_hint(self, hint: str) -> None:
        self.hint.setText(hint)


class Divider(QFrame):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("Divider")
        self.setFixedHeight(1)


def make_button(
    text: str,
    variant: str = "secondary",
    *,
    icon_name: str | None = None,
    tone: str | None = None,
    tooltip: str = "",
    parent: QWidget | None = None,
) -> QPushButton:
    button = QPushButton(text, parent)
    button.setProperty("variant", variant)
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    if tooltip:
        button.setToolTip(tooltip)
    if icon_name:
        tokens = theme()
        if variant == "primary":
            color = "#FFFFFF"
        elif variant == "danger":
            color = tokens["danger"]
        else:
            color = tone_color(tone or "muted")
        button.setIcon(icon(icon_name, color))
        button.setIconSize(QSize(16, 16))
    return button


def icon_button(
    icon_name: str,
    tooltip: str,
    *,
    tone: str = "muted",
    size: int = 32,
    icon_size: int = 16,
    parent: QWidget | None = None,
) -> QPushButton:
    button = QPushButton(parent)
    button.setProperty("variant", "icon")
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    button.setFixedSize(size, size)
    button.setIcon(icon(icon_name, tone_color(tone)))
    button.setIconSize(QSize(icon_size, icon_size))
    button.setToolTip(tooltip)
    return button


def copy_button(text: str, tooltip: str = "复制", *, size: int = 30, icon_size: int = 15, parent=None) -> QPushButton:
    button = icon_button("mdi.content-copy", tooltip, size=size, icon_size=icon_size, parent=parent)
    button.clicked.connect(lambda: QGuiApplication.clipboard().setText(text))
    return button


class ClickableFrame(QFrame):
    clicked = Signal()

    def __init__(self, parent: QWidget | None = None, *, object_name: str = ""):
        super().__init__(parent)
        if object_name:
            self.setObjectName(object_name)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton and self.rect().contains(event.position().toPoint()):
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class EmptyState(QWidget):
    def __init__(
        self,
        icon_name: str,
        title: str,
        text: str,
        action: QWidget | None = None,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 44, 24, 44)
        layout.setSpacing(12)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tile = IconBadge(icon_name, "primary", 64, 30)
        layout.addWidget(tile, 0, Qt.AlignmentFlag.AlignHCenter)
        heading = QLabel(title)
        heading.setObjectName("EmptyTitle")
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(heading)
        body = QLabel(text)
        body.setObjectName("EmptyText")
        body.setAlignment(Qt.AlignmentFlag.AlignCenter)
        body.setWordWrap(True)
        body.setMaximumWidth(430)
        layout.addWidget(body, 0, Qt.AlignmentFlag.AlignHCenter)
        if action is not None:
            layout.addSpacing(4)
            layout.addWidget(action, 0, Qt.AlignmentFlag.AlignHCenter)


class ScrollPage(QScrollArea):
    def __init__(self, parent: QWidget | None = None, *, spacing: int = 18):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setObjectName("Page")
        self._container = QWidget()
        self._container.setObjectName("PageContainer")
        self.root = QVBoxLayout(self._container)
        self.root.setContentsMargins(0, 0, 6, 18)
        self.root.setSpacing(spacing)
        self.setWidget(self._container)

    def add(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self.root.addWidget(widget, stretch)
        return widget

    def finish(self) -> None:
        self.root.addStretch(1)


class KeyRow(ClickableFrame):
    def __init__(self, key, parent: QWidget | None = None):
        super().__init__(parent, object_name="KeyRow")
        self.key = key
        self.setProperty("selected", False)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 13, 14, 13)
        layout.setSpacing(12)

        if key.has_private:
            tone = "success" if key.encrypted else "primary"
            icon_name = "mdi.key-variant" if key.encrypted else "mdi.key-outline"
        else:
            tone = "muted"
            icon_name = "mdi.key-outline"
        layout.addWidget(IconBadge(icon_name, tone, 40, 20), 0, Qt.AlignmentFlag.AlignTop)

        text_box = QVBoxLayout()
        text_box.setSpacing(5)
        top = QHBoxLayout()
        top.setSpacing(8)
        name = QLabel(key.name)
        name.setStyleSheet("font-size: 14px; font-weight: 600;")
        top.addWidget(name)
        top.addWidget(badge(key.display_type, "primary"))
        if key.has_private:
            if key.encrypted:
                top.addWidget(badge("口令保护", "success"))
            else:
                top.addWidget(badge("无口令", "warning"))
        else:
            top.addWidget(badge("仅公钥", "muted"))
        if key.certificate:
            top.addWidget(badge("证书", "accent"))
        top.addStretch(1)
        text_box.addLayout(top)

        fingerprint = QLabel(key.fingerprint or "指纹不可用")
        fingerprint.setProperty("role", "mono")
        fingerprint.setStyleSheet("font-size: 11px; color: %s;" % theme()["muted"])
        text_box.addWidget(fingerprint)

        meta_bits = []
        if key.bits:
            meta_bits.append(f"{key.bits} 位")
        if key.comment:
            meta_bits.append(key.comment)
        if key.modified:
            meta_bits.append(key.modified.strftime("%Y-%m-%d"))
        if key.pair_mismatch:
            meta_bits.append("公私钥不匹配")
        meta = QLabel(" · ".join(meta_bits) if meta_bits else "—")
        meta.setProperty("role", "dim")
        text_box.addWidget(meta)
        layout.addLayout(text_box, 1)

        arrow = QLabel()
        arrow.setPixmap(icon("mdi.chevron-right", theme()["dim"]).pixmap(18, 18))
        layout.addWidget(arrow, 0, Qt.AlignmentFlag.AlignVCenter)

    def set_selected(self, selected: bool) -> None:
        set_prop(self, "selected", selected)


class HostRow(ClickableFrame):
    def __init__(self, host, parent: QWidget | None = None):
        super().__init__(parent, object_name="HostRow")
        self.host = host
        self.setProperty("selected", False)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(12)
        layout.addWidget(IconBadge("mdi.server-network", "primary", 40, 20))

        text_box = QVBoxLayout()
        text_box.setSpacing(4)
        top = QHBoxLayout()
        top.setSpacing(8)
        alias = QLabel(host.alias)
        alias.setStyleSheet("font-size: 14px; font-weight: 600;")
        top.addWidget(alias)
        if host.is_pattern:
            top.addWidget(badge("通配规则", "muted"))
        elif host.port:
            top.addWidget(badge(f"端口 {host.port}", "muted"))
        top.addStretch(1)
        text_box.addLayout(top)

        endpoint = host.endpoint
        if host.user:
            endpoint = f"{host.user}@{endpoint}"
        endpoint_label = QLabel(endpoint)
        endpoint_label.setProperty("role", "mono")
        endpoint_label.setStyleSheet("font-size: 11px; color: %s;" % theme()["muted"])
        text_box.addWidget(endpoint_label)

        identity = host.identity_files[0] if host.identity_files else "未指定 IdentityFile"
        meta = QLabel(identity)
        meta.setProperty("role", "dim")
        text_box.addWidget(meta)
        layout.addLayout(text_box, 1)

        arrow = QLabel()
        arrow.setPixmap(icon("mdi.chevron-right", theme()["dim"]).pixmap(18, 18))
        layout.addWidget(arrow, 0, Qt.AlignmentFlag.AlignVCenter)

    def set_selected(self, selected: bool) -> None:
        set_prop(self, "selected", selected)


class FindingRow(QFrame):
    def __init__(self, finding, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("FindingRow")
        self.finding = finding
        tone = {"critical": "danger", "warning": "warning", "info": "info"}.get(finding.severity, "info")
        icon_name = {
            "critical": "mdi.alert-octagon-outline",
            "warning": "mdi.alert-outline",
            "info": "mdi.information-outline",
        }.get(finding.severity, "mdi.information-outline")
        label = {"critical": "严重", "warning": "建议", "info": "提示"}.get(finding.severity, "提示")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 13, 14, 13)
        layout.setSpacing(12)
        layout.addWidget(IconBadge(icon_name, tone, 38, 19), 0, Qt.AlignmentFlag.AlignTop)

        body = QVBoxLayout()
        body.setSpacing(5)
        top = QHBoxLayout()
        top.setSpacing(8)
        title = QLabel(finding.title)
        title.setStyleSheet("font-size: 13px; font-weight: 600;")
        title.setWordWrap(True)
        top.addWidget(title, 1)
        top.addWidget(badge(label, tone))
        if finding.category:
            top.addWidget(badge(finding.category, "muted"))
        body.addLayout(top)

        detail = QLabel(finding.detail)
        detail.setProperty("role", "muted")
        detail.setWordWrap(True)
        body.addWidget(detail)
        if finding.remediation:
            remediation = QLabel(f"建议：{finding.remediation}")
            remediation.setWordWrap(True)
            remediation.setStyleSheet(f"color: {theme()['dim']}; font-size: 11px;")
            body.addWidget(remediation)
        layout.addLayout(body, 1)


class KeyValueRow(QWidget):
    def __init__(
        self,
        label: str,
        value: str,
        *,
        copyable: bool = False,
        mono: bool = False,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        name = QLabel(label)
        name.setProperty("role", "muted")
        name.setMinimumWidth(80)
        name.setMaximumWidth(110)
        layout.addWidget(name, 0, Qt.AlignmentFlag.AlignTop)
        text = QLabel(elide_middle(value or "—"))
        text.setWordWrap(False)
        text.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        text.setToolTip(value or "")
        text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        if mono:
            text.setProperty("role", "mono")
        else:
            text.setStyleSheet("font-size: 12px;")
        layout.addWidget(text, 1)
        if copyable and value:
            layout.addWidget(copy_button(value, f"复制{label}"), 0, Qt.AlignmentFlag.AlignTop)


class ScoreRing(QWidget):
    """Circular security score indicator."""

    def __init__(self, score: int = 100, grade: str = "优秀", parent: QWidget | None = None):
        super().__init__(parent)
        self._score = score
        self._grade = grade
        self.setFixedSize(138, 138)
        self.setToolTip(f"安全评分 {score} / 100 · {grade}")

    def set_score(self, score: int, grade: str) -> None:
        self._score = max(0, min(100, score))
        self._grade = grade
        self.setToolTip(f"安全评分 {self._score} / 100 · {grade}")
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        tokens = theme()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        side = min(self.width(), self.height())
        pad = 12
        rect = QRectF(pad, pad, side - pad * 2, side - pad * 2)

        painter.setPen(QPen(QColor(tokens["border"]), 9))
        painter.drawArc(rect, 0, 360 * 16)

        if self._score >= 90:
            arc_color = tokens["success"]
        elif self._score >= 75:
            arc_color = tokens["primary"]
        elif self._score >= 60:
            arc_color = tokens["warning"]
        else:
            arc_color = tokens["danger"]

        pen = QPen(QColor(arc_color), 9)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        span = -int(360 * 16 * self._score / 100)
        painter.drawArc(rect, 90 * 16, span)

        font = QFont()
        font.setFamilies(["Segoe UI Variable Display", "Segoe UI", "Arial"])
        font.setPixelSize(31)
        font.setWeight(QFont.Weight.Bold)
        painter.setFont(font)
        painter.setPen(QColor(tokens["text"]))
        score_rect = QRectF(0, side / 2 - 31, side, 38)
        painter.drawText(score_rect, Qt.AlignmentFlag.AlignCenter, str(self._score))

        font.setPixelSize(11)
        font.setWeight(QFont.Weight.Medium)
        painter.setFont(font)
        painter.setPen(QColor(tokens["muted"]))
        grade_rect = QRectF(0, side / 2 + 7, side, 18)
        painter.drawText(grade_rect, Qt.AlignmentFlag.AlignCenter, f"安全评分 · {self._grade}")
        painter.end()


class Toast(QFrame):
    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setObjectName("Toast")
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setVisible(False)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 16, 10)
        layout.setSpacing(9)
        self.icon_label = QLabel()
        layout.addWidget(self.icon_label)
        self.text_label = QLabel()
        self.text_label.setStyleSheet("font-size: 12px; font-weight: 500;")
        layout.addWidget(self.text_label)
        self.effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.effect)
        self.animation = QPropertyAnimation(self.effect, b"opacity", self)
        self.animation.setDuration(160)
        self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._hide_connected = False
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self._fade_out)
        parent.installEventFilter(self)

    def show_message(self, text: str, tone: str = "success", duration: int = 2800) -> None:
        tokens = theme()
        color = tokens.get(tone, tokens["success"])
        icon_name = {
            "success": "mdi.check-circle-outline",
            "danger": "mdi.alert-circle-outline",
            "warning": "mdi.alert-outline",
            "info": "mdi.information-outline",
        }.get(tone, "mdi.check-circle-outline")
        self.icon_label.setPixmap(icon(icon_name, color).pixmap(18, 18))
        self.text_label.setText(text)
        self.adjustSize()
        self._reposition()
        self.setVisible(True)
        self.raise_()
        self.effect.setOpacity(0.0)
        self.animation.stop()
        if self._hide_connected:
            try:
                self.animation.finished.disconnect()
            except (RuntimeError, TypeError):
                pass
            self._hide_connected = False
        self.animation.setStartValue(0.0)
        self.animation.setEndValue(1.0)
        self.animation.start()
        self.timer.start(duration)

    def _fade_out(self) -> None:
        self.animation.stop()
        self.animation.setStartValue(self.effect.opacity())
        self.animation.setEndValue(0.0)
        if not self._hide_connected:
            self.animation.finished.connect(self.hide)
            self._hide_connected = True
        self.animation.start()

    def _reposition(self) -> None:
        parent = self.parentWidget()
        if not parent:
            return
        self.move(
            max(12, (parent.width() - self.width()) // 2),
            max(12, parent.height() - self.height() - 26),
        )

    def eventFilter(self, obj, event) -> bool:  # noqa: N802
        if event.type() == QEvent.Type.Resize and self.isVisible():
            self._reposition()
        return super().eventFilter(obj, event)


def field_column(title: str, value: str, copyable: bool = False) -> QWidget:
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(3)
    name = QLabel(title)
    name.setProperty("role", "dim")
    layout.addWidget(name)
    row = QHBoxLayout()
    row.setSpacing(4)
    text = QLabel(value or "—")
    text.setProperty("role", "mono")
    text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    row.addWidget(text, 1)
    if copyable and value:
        row.addWidget(copy_button(value, f"复制{title}", size=26, icon_size=13))
    layout.addLayout(row)
    return widget
