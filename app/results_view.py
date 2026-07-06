"""Renders a core.models.ScanResult into Kivy widgets shared by all screens."""

from __future__ import annotations

from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label

from core.models import ScanResult

_RISK_COLORS = {
    "LOW": (0.20, 0.70, 0.30, 1),
    "MEDIUM": (0.95, 0.65, 0.10, 1),
    "HIGH": (0.90, 0.35, 0.10, 1),
    "CRITICAL": (0.80, 0.10, 0.10, 1),
}


def populate_results(container: BoxLayout, result: ScanResult) -> None:
    container.clear_widgets()

    banner_color = _RISK_COLORS.get(result.risk_level, (0.5, 0.5, 0.5, 1))
    banner = Label(
        text=f"{result.risk_level} RISK  —  score {result.score}/100",
        bold=True,
        color=(1, 1, 1, 1),
        size_hint_y=None,
        height=48,
    )
    with banner.canvas.before:
        from kivy.graphics import Color, Rectangle

        Color(*banner_color)
        rect = Rectangle(pos=banner.pos, size=banner.size)

        def _sync_rect(_instance, _value):
            rect.pos = banner.pos
            rect.size = banner.size

        banner.bind(pos=_sync_rect, size=_sync_rect)

    container.add_widget(banner)

    label_line = Label(
        text=f"[b]{result.channel.upper()}[/b]: {result.label}",
        markup=True,
        size_hint_y=None,
        height=32,
        halign="left",
        valign="middle",
    )
    label_line.bind(size=lambda inst, val: setattr(inst, "text_size", val))
    container.add_widget(label_line)

    if not result.findings:
        container.add_widget(
            Label(
                text="No suspicious indicators found.",
                size_hint_y=None,
                height=40,
            )
        )
        return

    for i, finding in enumerate(result.findings, start=1):
        text = (
            f"[b]{i}. [{finding.severity.label}][/b] ({finding.category}) "
            f"{finding.title}\n[size=13]{finding.detail}[/size]"
        )
        item = Label(
            text=text,
            markup=True,
            size_hint_y=None,
            halign="left",
            valign="top",
        )
        item.bind(width=lambda inst, val: setattr(inst, "text_size", (val, None)))
        item.bind(texture_size=lambda inst, val: setattr(inst, "height", val[1] + 10))
        container.add_widget(item)
