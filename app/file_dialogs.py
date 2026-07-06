"""Cross-platform "pick a file" helper.

Tries plyer first (works via native pickers on Android/iOS/desktop), and
falls back to a Kivy FileChooser popup on platforms/setups where plyer's
filechooser provider isn't available (e.g. plain desktop Linux dev runs).
"""

from __future__ import annotations

from collections.abc import Callable


def open_file_chooser(
    on_selection: Callable[[str], None], filters: list[str] | None = None
) -> None:
    try:
        from plyer import filechooser

        def _handle(selection):
            if selection:
                on_selection(selection[0])

        filechooser.open_file(on_selection=_handle, filters=filters or [])
        return
    except Exception:
        pass

    _open_kivy_file_popup(on_selection, filters)


def _open_kivy_file_popup(on_selection: Callable[[str], None], filters: list[str] | None) -> None:
    from kivy.uix.boxlayout import BoxLayout
    from kivy.uix.button import Button
    from kivy.uix.filechooser import FileChooserListView
    from kivy.uix.popup import Popup

    content = BoxLayout(orientation="vertical")
    chooser = FileChooserListView(filters=filters or [])
    content.add_widget(chooser)

    buttons = BoxLayout(size_hint_y=None, height=48)
    select_btn = Button(text="Select")
    cancel_btn = Button(text="Cancel")
    buttons.add_widget(select_btn)
    buttons.add_widget(cancel_btn)
    content.add_widget(buttons)

    popup = Popup(title="Choose a file", content=content, size_hint=(0.9, 0.9))

    def _select(_instance):
        if chooser.selection:
            on_selection(chooser.selection[0])
        popup.dismiss()

    select_btn.bind(on_release=_select)
    cancel_btn.bind(on_release=popup.dismiss)
    popup.open()
