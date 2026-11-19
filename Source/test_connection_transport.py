"""连接与物理网卡缓存的定向验证；仅使用模拟接口及本机回环。"""
import concurrent.futures
import socket
import struct
import sys
import threading
import time
import types
import unittest
from unittest.mock import patch

try:
    import customtkinter  # noqa: F401
except ImportError:
    # 不运行GUI；允许独立Python环境验证网络层。
    sys.modules['customtkinter'] = types.ModuleType('customtkinter')

import device_directory as directory
import local_tcp_client as client


class LoopbackServer:
    def __init__(self, handler, count=1):
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen()
        self.listener.settimeout(3)
        self.port = self.listener.getsockname()[1]
        self.errors = []
        self.accepted = 0
        self.handler = handler
        self.count = count

    def __enter__(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        return self

    def run(self):
        try:
            for _ in range(self.count):
                with self.listener.accept()[0] as connection:
                    self.accepted += 1
                    self.handler(connection, self.accepted)
        except Exception as exc:
            self.errors.append(exc)
        finally:
            self.listener.close()

    def __exit__(self, *_):
        self.thread.join(4)
        if self.thread.is_alive():
            raise AssertionError('回环测试服务未退出')
        if self.errors:
            raise self.errors[0]


def read_request(connection):
    header = client.exact(connection, 20)
    _, op, offset, size, _ = client.HEADER.unpack(header)
    body = client.exact(connection, size)
    return op, offset, body


def reply(connection, op, body=b'', status=0):
    connection.sendall(client.frame(op | 0x80000000, status, body))


class TransportTests(unittest.TestCase):
    def args(self, server):
        return types.SimpleNamespace(host='127.0.0.1', port=server.port)

    def test_success_sets_socket_options_and_callback_before_auth(self):
        created = []
        def handler(connection, _):
            self.assertEqual(read_request(connection), (0, 0, b'k' * 32))
            reply(connection, 0)
        with LoopbackServer(handler) as server:
            with client.connect(self.args(server), b'k' * 32,
                                on_socket=created.append) as connection:
                self.assertEqual(connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY), 1)
                self.assertEqual(connection.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE), 1)
                self.assertIs(created[0], connection)
                self.assertEqual(connection.gettimeout(), 120)

    def test_auth_rejection_never_retries(self):
        created = []
        def handler(connection, _):
            read_request(connection)
            reply(connection, 0, status=13)
        with LoopbackServer(handler) as server:
            with self.assertRaises(client.DeviceError):
                client.connect(self.args(server), b'k' * 32, on_socket=created.append)
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].fileno(), -1)

    def test_bad_crc_never_retries(self):
        created = []
        def handler(connection, _):
            read_request(connection)
            packet = bytearray(client.frame(0x80000000))
            packet[16] ^= 1
            connection.sendall(packet)
        with LoopbackServer(handler) as server:
            with self.assertRaisesRegex(ValueError, 'CRC'):
                client.connect(self.args(server), b'k' * 32, on_socket=created.append)
        self.assertEqual(len(created), 1)

    def test_closed_handshake_retries_once_with_new_socket(self):
        created = []
        def handler(connection, number):
            read_request(connection)
            if number == 2:
                reply(connection, 0)
        with LoopbackServer(handler, count=2) as server:
            with client.connect(self.args(server), b'k' * 32,
                                on_socket=created.append):
                pass
        self.assertEqual(len(created), 2)
        self.assertEqual(created[0].fileno(), -1)

    def test_cancel_during_partial_auth_response_does_not_resume_frame(self):
        cancelled = threading.Event()
        created = []
        def handler(connection, _):
            read_request(connection)
            connection.sendall(client.frame(0x80000000)[:8])
            cancelled.set()
            # 等待客户端退出，保证服务没有通过第二帧补齐半帧。
            connection.settimeout(2)
            self.assertEqual(connection.recv(1), b'')
        with LoopbackServer(handler) as server:
            started = time.monotonic()
            with self.assertRaises(InterruptedError):
                client.connect(self.args(server), b'k' * 32, cancel=cancelled,
                               on_socket=created.append)
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(len(created), 1)

    def test_precancel_does_not_create_socket(self):
        cancelled = threading.Event()
        cancelled.set()
        with patch.object(client.socket, 'socket') as factory:
            with self.assertRaises(InterruptedError):
                client.connect(types.SimpleNamespace(host='127.0.0.1', port=1), b'', cancel=cancelled)
            factory.assert_not_called()


class InterfaceCacheTests(unittest.TestCase):
    def setUp(self):
        directory.invalidate_lan_interfaces()

    def tearDown(self):
        directory.invalidate_lan_interfaces()

    def test_concurrent_requests_share_one_enumeration_and_copy_result(self):
        value = [{'InterfaceIndex': 7, 'IPAddress': ['192.168.18.8'],
                  'IPSubnet': ['255.255.255.0'], 'DefaultIPGateway': ['192.168.18.1']}]
        started = threading.Event()
        release = threading.Event()
        def enumerate_interfaces(cancel=None):
            started.set()
            release.wait(2)
            return value
        with patch.object(directory, '_enumerate_lan_interfaces', side_effect=enumerate_interfaces) as enumerate_mock:
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
                futures = [executor.submit(directory.lan_interfaces) for _ in range(6)]
                self.assertTrue(started.wait(1))
                release.set()
                results = [future.result(2) for future in futures]
            results[0][0]['IPAddress'].clear()
            self.assertEqual(directory.lan_interfaces()[0]['IPAddress'], ['192.168.18.8'])
            self.assertEqual(enumerate_mock.call_count, 1)

    def test_invalidation_refreshes_cache(self):
        with patch.object(directory, '_enumerate_lan_interfaces', return_value=[]) as enumerate_mock:
            directory.lan_interfaces()
            directory.lan_interfaces()
            directory.invalidate_lan_interfaces()
            directory.lan_interfaces()
            self.assertEqual(enumerate_mock.call_count, 2)

    def test_cancelled_waiter_does_not_cancel_shared_enumeration(self):
        started = threading.Event()
        release = threading.Event()
        cancelled = threading.Event()
        def enumerate_interfaces(cancel=None):
            started.set()
            release.wait(2)
            return [{'InterfaceIndex': 7}]
        with patch.object(directory, '_enumerate_lan_interfaces', side_effect=enumerate_interfaces):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                owner = executor.submit(directory.lan_interfaces)
                self.assertTrue(started.wait(1))
                cancelled.set()
                self.assertEqual(directory.lan_interfaces(cancelled), [])
                release.set()
                self.assertEqual(owner.result(2), [{'InterfaceIndex': 7}])

    def test_routed_company_lan_retains_physical_gateway(self):
        adapters = [{'InterfaceIndex': 7, 'IPAddress': ['192.168.18.8'],
                     'IPSubnet': ['255.255.255.0'], 'DefaultIPGateway': ['192.168.18.1'],
                     'IPConnectionMetric': 25}]
        self.assertEqual(directory.route_interface('192.168.21.20', adapters), (7, '192.168.18.8'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
