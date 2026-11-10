from __future__ import annotations

import os
import shutil
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from app.core.ssh import generate_ssh_key  # noqa: E402
from app.ui.dialogs import GenerateKeyDialog  # noqa: E402
from app.ui.main_window import MainWindow  # noqa: E402
from app.ui.theme import apply_theme, base_font  # noqa: E402

WORK = Path(".tmp") / "unit-ui"


class UISmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setFont(base_font())
        apply_theme(cls.app, "dark")
        shutil.rmtree(WORK, ignore_errors=True)
        WORK.mkdir(parents=True, exist_ok=True)
        generate_ssh_key(
            key_type="ed25519",
            directory=WORK,
            name="id_test",
            comment="ui@test",
            passphrase="",
        )
        (WORK / "config").write_text(
            "Host demo\n    HostName demo.example.com\n    User tester\n    IdentityFile ~/.ssh/id_test\n",
            encoding="utf-8",
        )

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(WORK, ignore_errors=True)

    def test_main_window_pages(self) -> None:
        window = MainWindow(ssh_dir=str(WORK))
        window.resize(1200, 800)
        window.show()
        self.app.processEvents()
        self.assertEqual(window.stack.count(), 6)
        for index in range(6):
            window.navigate(index)
            self.app.processEvents()
            self.assertEqual(window.stack.currentIndex(), index)
        self.assertEqual(window.pages[0].scan.private_count, 1)

    def test_theme_toggle(self) -> None:
        window = MainWindow(ssh_dir=str(WORK))
        window.show()
        self.app.processEvents()
        before = window.theme_name
        window.navigate(2)
        window.toggle_theme()
        self.app.processEvents()
        self.assertNotEqual(before, window.theme_name)
        self.assertEqual(window.stack.count(), 6)
        self.assertEqual(window._current_index, 2)

    def test_generate_dialog_validation(self) -> None:
        dialog = GenerateKeyDialog(str(WORK))
        dialog.show()
        self.app.processEvents()
        dialog.name_edit.setText("bad/name")
        dialog._start_generate()
        self.app.processEvents()
        self.assertTrue(dialog.error_label.isVisible())
        dialog.name_edit.setText("id_dialog")
        dialog.passphrase_edit.setText("abc12345")
        dialog.confirm_edit.setText("abc1234")
        dialog._start_generate()
        self.app.processEvents()
        self.assertIn("不一致", dialog.error_label.text())
        dialog.close()


if __name__ == "__main__":
    unittest.main()
