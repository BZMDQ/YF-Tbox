"""验证无线烧录的页内路由和共用停止按钮，不创建 GUI 或连接设备。"""
import threading
import unittest
from unittest.mock import Mock, patch

import local_tcp_gui as gui


class WirelessPageTests(unittest.TestCase):
    def test_wireless_navigation_switches_between_cards_on_the_same_page(self):
        app = gui.LocalTcpApp.__new__(gui.LocalTcpApp)
        app.root = Mock()
        app.is_running = False
        app.pages = {'home': Mock()}
        app.page_builders = {'w78': app._build_w78_page}
        app.active_page_key = 'home'
        app.page_title_var = Mock()
        app.nav_buttons = {name: Mock() for name in app.pages}
        app.nav_buttons['w78'] = Mock()
        app._cancel_scroll_animation = Mock()
        app._register_action = Mock(side_effect=lambda widget: widget)
        app._font = Mock()
        page, selector_card, hex_card, d133_card, mode_var = (Mock() for _ in range(5))
        mode_var.get.return_value = gui.WIRELESS_HEX_MODE

        def add_page(key):
            app.pages[key] = page
            return page

        app._page = Mock(side_effect=add_page)
        app._page_card = Mock(return_value=selector_card)
        app._build_wireless_hex_card = Mock(return_value=hex_card)
        with patch.object(gui.tk, 'StringVar', return_value=mode_var) as create_mode_var, \
                patch.object(gui.ctk, 'CTkRadioButton') as create_choice, \
                patch.object(gui.d133_proxy_ui, 'build_card', return_value=d133_card) as build_d133:
            app._show_page('w78')

        self.assertEqual(app.active_page_key, 'w78')
        self.assertEqual(list(app.pages), ['home', 'w78'])
        app._page.assert_called_once_with('w78')
        app._build_wireless_hex_card.assert_called_once_with(page)
        self.assertIs(build_d133.call_args.args[2], page)
        app.page_title_var.set.assert_called_once_with('无线烧录')
        create_mode_var.assert_called_once_with(master=app.root, value=gui.WIRELESS_HEX_MODE)
        self.assertEqual([call.kwargs['value'] for call in create_choice.call_args_list],
                         [gui.WIRELESS_HEX_MODE, gui.WIRELESS_D133_MODE])
        d133_card.grid_remove.assert_called_once()
        hex_card.grid.assert_called_once()

        select_hex, select_d133 = [call.kwargs['command'] for call in create_choice.call_args_list]
        mode_var.get.return_value = gui.WIRELESS_D133_MODE
        select_d133()
        d133_card.grid.assert_called_once()
        hex_card.grid_remove.assert_called_once()
        self.assertEqual(app.active_page_key, 'w78')
        mode_var.get.return_value = gui.WIRELESS_HEX_MODE
        select_hex()
        self.assertEqual(hex_card.grid.call_count, 2)
        self.assertEqual(d133_card.grid_remove.call_count, 2)

    def test_shared_stop_preserves_usb_stage_while_viewing_another_page(self):
        for committed, status in ((False, '取消未提交事务'), (True, '仅停止电脑等待')):
            with self.subTest(committed=committed):
                app = gui.LocalTcpApp.__new__(gui.LocalTcpApp)
                app.active_page_key = 'home'
                app.is_running = app.d133_proxy_running = True
                app.d133_proxy_committed = committed
                app.stop_event = threading.Event()
                app.task_thread = Mock()
                app.task_thread.is_alive.return_value = True
                app.stop_button = Mock()
                app.d133_proxy_status_var = Mock()
                app._append_log = Mock()
                app._set_status = Mock()

                app._stop_operation()
                self.assertTrue(app.stop_event.is_set())
                app.stop_button.configure.assert_called_once_with(state='disabled')
                self.assertIn(status, app.d133_proxy_status_var.set.call_args.args[0])


if __name__ == '__main__':
    unittest.main()
