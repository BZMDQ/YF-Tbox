"""只读连接恢复与旧 App 包入口的定向验证，不接触开发板。"""
from contextlib import contextmanager
from types import SimpleNamespace
import threading
import unittest
from unittest.mock import patch

import local_tcp_gui as gui


class ImmediateStop:
    """验证重连退避可取消，不实际等待倒计时。"""
    def __init__(self):
        self.stopped = False
        self.delays = []

    def is_set(self):
        return self.stopped

    def wait(self, delay):
        self.delays.append(delay)
        self.stopped = True
        return True


class GuiConnectionPolicy(unittest.TestCase):
    def listener(self, connection):
        app = gui.LocalTcpApp.__new__(gui.LocalTcpApp)
        app._connection = connection
        app.posts = []
        app._post = lambda *event: app.posts.append(event)
        app._on_device_info = lambda body: app.posts.append(('info', body))
        app._start_task = lambda title, action: setattr(app, 'action', action)
        app._listen()
        return app

    def test_old_app_packages_rejected_before_reading_file(self):
        app = gui.LocalTcpApp.__new__(gui.LocalTcpApp)
        for suffix in ('.fapp', '.fappb'):
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(ValueError, '系统 OTA'):
                    app._set_package('missing-old-package' + suffix)
        self.assertFalse(hasattr(gui.LocalTcpApp, '_upload_app'))

    def test_monitor_recovers_transport_without_replaying_writes(self):
        stop = threading.Event()
        sockets = []

        @contextmanager
        def connection(*_):
            sock = SimpleNamespace(settimeout=lambda _: None)
            sockets.append(sock)
            yield sock

        app = self.listener(connection)
        commands = []

        def request(sock, op, **_):
            commands.append(op)
            if len(sockets) == 2:
                stop.set()
            return b'{"version":"test"}'

        # 用立即返回的可取消等待替代真实退避，避免测试耗时。
        with patch.object(gui, 'request', side_effect=request), \
                patch.object(gui, 'receive', side_effect=ConnectionResetError('reset')), \
                patch.object(stop, 'wait', return_value=False):
            with self.assertRaises(InterruptedError):
                app.action(None, b'', stop)
        self.assertEqual(len(sockets), 2)
        self.assertEqual(commands, [1, 1])

    def test_auth_rejection_and_bad_frames_do_not_retry(self):
        for error in (gui.DeviceError(13), ValueError('CRC错误')):
            attempts = []

            @contextmanager
            def connection(*_):
                attempts.append(1)
                raise error
                yield

            app = self.listener(connection)
            with self.subTest(error=type(error).__name__):
                with self.assertRaises(type(error)):
                    app.action(None, b'', threading.Event())
                self.assertEqual(len(attempts), 1)

    def test_stop_during_reconnect_does_not_create_another_connection(self):
        attempts = []

        @contextmanager
        def connection(*_):
            attempts.append(1)
            raise ConnectionResetError('reset')
            yield

        stop = ImmediateStop()
        app = self.listener(connection)
        with self.assertRaises(InterruptedError):
            app.action(None, b'', stop)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(stop.delays, [0.5])

    def test_cancelled_connect_clears_registered_socket(self):
        app = gui.LocalTcpApp.__new__(gui.LocalTcpApp)
        app.socket_lock = threading.Lock()
        app.active_socket = app.connecting_socket = None
        app._post = lambda *_: None
        app._on_device_info = lambda *_: None
        app._close_socket = lambda *_: None
        stop = threading.Event()

        def connect(*_, **kwargs):
            kwargs['on_socket'](object())
            stop.set()
            raise InterruptedError()

        with patch.object(gui, 'connect', side_effect=connect):
            with self.assertRaises(InterruptedError):
                with app._connection(SimpleNamespace(host='127.0.0.1', port=5000), b'', stop):
                    self.fail('取消后仍进入业务阶段')
        self.assertIsNone(app.active_socket)
        self.assertIsNone(app.connecting_socket)


if __name__ == '__main__':
    unittest.main()
