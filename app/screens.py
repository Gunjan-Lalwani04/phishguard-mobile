"""Screen classes for the PhishGuard mobile app."""

from __future__ import annotations

from kivy.uix.screenmanager import Screen

from app.file_dialogs import open_file_chooser
from app.results_view import populate_results
from core.engine import scan_email_raw, scan_qr_image, scan_sms, scan_url


class HomeScreen(Screen):
    pass


class EmailScreen(Screen):
    def choose_file(self) -> None:
        def _loaded(path: str) -> None:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    self.ids.eml_input.text = fh.read()
            except OSError as exc:
                self.ids.eml_input.text = f"# Could not read file: {exc}"

        open_file_chooser(_loaded, filters=["*.eml", "*.txt"])

    def analyze(self) -> None:
        raw_text = self.ids.eml_input.text.strip()
        if not raw_text:
            return
        result = scan_email_raw(raw_text)
        populate_results(self.ids.results_box, result)


class SmsScreen(Screen):
    def analyze(self) -> None:
        sender_id = self.ids.sms_sender.text.strip()
        body = self.ids.sms_body.text.strip()
        if not sender_id and not body:
            return
        result = scan_sms(sender_id, body)
        populate_results(self.ids.results_box, result)


class LinkQrScreen(Screen):
    def analyze_url(self) -> None:
        url = self.ids.url_input.text.strip()
        if not url:
            return
        result = scan_url(url)
        populate_results(self.ids.results_box, result)

    def choose_image(self) -> None:
        def _loaded(path: str) -> None:
            result = scan_qr_image(path)
            self.ids.url_input.text = result.label
            populate_results(self.ids.results_box, result)

        open_file_chooser(_loaded, filters=["*.png", "*.jpg", "*.jpeg"])

    def open_camera(self) -> None:
        self.manager.get_screen("camera").return_to = "linkqr"
        self.manager.current = "camera"


class CameraScreen(Screen):
    """Only constructs the Kivy Camera widget (which opens the real device
    camera) when this screen is actually entered, and tears it down again on
    exit. This avoids holding the camera open for the app's whole lifetime
    and matches how a real phone app should behave around camera access.
    """

    return_to = "linkqr"
    _camera_widget = None

    def on_enter(self) -> None:
        from kivy.uix.camera import Camera

        if self._camera_widget is None:
            self._camera_widget = Camera(resolution=(640, 480), play=True)
            self.ids.camera_container.add_widget(self._camera_widget)
        else:
            self._camera_widget.play = True

    def on_leave(self) -> None:
        if self._camera_widget is not None:
            self._camera_widget.play = False
            self.ids.camera_container.remove_widget(self._camera_widget)
            self._camera_widget = None

    def capture(self) -> None:
        import os
        import tempfile

        camera = self._camera_widget
        if camera is None or camera.texture is None:
            self._go_back()
            return

        tmp_path = os.path.join(tempfile.gettempdir(), "phishguard_qr_capture.png")
        camera.texture.save(tmp_path, flipped=False)

        result = scan_qr_image(tmp_path)
        target = self.manager.get_screen(self.return_to)
        target.ids.url_input.text = result.label
        populate_results(target.ids.results_box, result)
        self._go_back()

    def _go_back(self) -> None:
        self.manager.current = self.return_to
