"""连接与物理网卡缓存的定向验证；仅使用模拟接口及本机回环。"""
import asyncio
import concurrent.futures
import socket
import struct
import sys
import threading
import time
import types
import unittest
import zlib
from unittest.mock import patch

try:
    import customtkinter  # noqa: F401
except ImportError:
    # 不运行GUI；允许独立Python环境验证网络层。
    sys.modules['customtkinter'] = types.ModuleType('customtkinter')

import device_directory as directory
import local_tcp_client as client


class DiscoverySchedulingTests(unittest.IsolatedAsyncioTestCase):
    async def test_ready_lane_keeps_scanning_while_one_address_is_slow(self):
        release = asyncio.Event()
        last_started = asyncio.Event()
        received = []

        async def probe_one(ip):
            if ip == 0:
                await release.wait()
            if ip == 5:
                last_started.set()
            return ip

        task = asyncio.create_task(directory.scan_pass(
            range(6), probe_one, threading.Event(), 2, received.append))
        try:
            await asyncio.wait_for(last_started.wait(), 2)
            self.assertFalse(task.done())
        finally:
            release.set()
        await asyncio.wait_for(task, 2)
        self.assertEqual(sorted(received), list(range(6)))

    async def test_global_2048_1024_512_limits_across_scan_threads(self):
        limits = (directory._SCAN_STARTUP_LIMIT, directory._SCAN_FIRST_LIMIT, directory._SCAN_RETRY_LIMIT)
        self.assertEqual(limits, (2048, 1024, 512))
        for limit, expected_threads in zip(limits, (8, 4, 2)):
            with self.subTest(limit=limit):
                release = threading.Event()
                lock = threading.Lock()
                thread_ids, received = set(), []
                active = peak = 0

                async def probe_one(ip):
                    nonlocal active, peak
                    with lock:
                        thread_ids.add(threading.get_ident())
                        active += 1
                        peak = max(peak, active)
                    try:
                        while not release.is_set():
                            await asyncio.sleep(0.01)
                    finally:
                        with lock:
                            active -= 1
                    return ip

                async def wait_until_full():
                    while peak < limit:
                        await asyncio.sleep(0.01)

                with patch.object(directory.os, 'cpu_count', return_value=16):
                    task = asyncio.create_task(directory.scan_pass(
                        range(limit + 17), probe_one, threading.Event(), limit, received.append))
                    try:
                        await asyncio.wait_for(wait_until_full(), 5)
                        self.assertEqual(len(thread_ids), expected_threads)
                    finally:
                        release.set()
                    await asyncio.wait_for(task, 5)
                self.assertEqual(peak, limit)
                self.assertEqual(len(set(received)), limit + 17)
                self.assertEqual(active, 0)

    async def test_cancel_closes_an_in_progress_tcp_probe_without_scanning_next(self):
        cancel = threading.Event()
        waiting = threading.Event()
        probed, received = [], []

        def handler(connection, _):
            self.assertEqual(read_request(connection), (27, 0, b''))
            waiting.set()
            connection.settimeout(3)
            self.assertEqual(connection.recv(1), b'')

        async def wait_for_request():
            while not waiting.is_set():
                await asyncio.sleep(0.01)

        with LoopbackServer(handler) as server:
            async def probe_one(ip):
                probed.append(ip)
                return await directory.probe(ip, server.port)

            task = asyncio.create_task(directory.scan_pass(
                ['127.0.0.1', '127.0.0.2'], probe_one, cancel, 1, received.append))
            try:
                await asyncio.wait_for(wait_for_request(), 2)
            finally:
                cancel.set()
            await asyncio.wait_for(task, 2)
        self.assertEqual(probed, ['127.0.0.1'])
        self.assertEqual(received, [])

    async def test_late_udp_hint_sets_port_for_supplemental_probe(self):
        ip = '192.168.1.25'
        primary_started = threading.Event()
        calls, results = [], []

        def udp_discover(_targets, _routes, _cancel, publish):
            self.assertTrue(primary_started.wait(3))
            info = {'uid': 'AABBCC', 'port': 6123}
            publish(ip, info)
            return {ip: info}

        async def probe_one(address, port, _route, known=False, confirm=False):
            calls.append((port, confirm))
            if not confirm:
                primary_started.set()
                return 'failed', (address, 'TCP 连接', '拒绝连接', False)
            return 'found', (address, {'uid': 'AABBCC', 'device_name': '开发板'})

        with patch.object(directory, 'udp_discover', side_effect=udp_discover), \
                patch.object(directory, 'probe', side_effect=probe_one):
            await directory.scan_network([ip], {ip: None}, 5000, set(), False,
                                         threading.Event(), lambda *event: results.append(event))
        self.assertEqual(calls, [(5000, False), (6123, True)])
        self.assertEqual([value[0] for kind, value in results if kind == 'found'], [ip])
        self.assertIn(('retrying', 1), results)

    async def test_split_frames_and_legacy_fallback_use_identical_lnet_validation(self):
        body = '{"board":"STM32F750","uid":"ONE","device_name":"probe"}'.encode('ascii')

        def handler(connection, _):
            self.assertEqual(read_request(connection), (27, 0, b''))
            reply(connection, 27, status=11)
            self.assertEqual(read_request(connection), (0, 0, b''))
            reply(connection, 0)
            self.assertEqual(read_request(connection), (1, 0, b''))
            response = client.frame(0x80000001, payload=body)
            connection.sendall(response[:7])
            time.sleep(0.03)
            connection.sendall(response[7:])

        with LoopbackServer(handler) as server:
            kind, (ip, info) = await directory.probe('127.0.0.1', server.port)
        self.assertEqual((kind, ip, info['uid']), ('found', '127.0.0.1', 'ONE'))


class DiscoveryRangeTests(unittest.TestCase):
    def test_dnet_hint_requires_matching_origin_identity_nonce_and_crc(self):
        ip, uid, nonce = '192.168.1.25', b'P' * 12, 0x12345678
        payload = struct.pack('<HB', 6123, 2) + b'RD' + bytes([3]) + b'1.0'
        header = struct.pack('<4sBBH12s12sI4s', b'DNET', 1, 6, len(payload) + 4, bytes(12),
                             uid, nonce, socket.inet_aton(ip))
        body = header + payload
        packet = body + struct.pack('<I', zlib.crc32(body) & 0xffffffff)
        candidate = directory._udp_candidate(packet, (ip, 5000), {ip}, uid, nonce)
        self.assertEqual(candidate[0], ip)
        self.assertEqual(candidate[1]['port'], 6123)
        self.assertIsNone(directory._udp_candidate(packet, ('192.168.1.26', 5000), {ip}, uid, nonce))
        self.assertIsNone(directory._udp_candidate(packet, (ip, 5000), {ip}, uid, nonce + 1))
        self.assertIsNone(directory._udp_candidate(packet[:-1] + bytes([packet[-1] ^ 1]),
                                                   (ip, 5000), {ip}, uid, nonce))

    def test_physical_subnet_used_and_startup_budget_is_bounded(self):
        interfaces = [
            {'InterfaceIndex': 3, 'IPAddress': ['192.168.6.20'], 'IPSubnet': ['255.255.248.0']},
            {'InterfaceIndex': 7, 'IPAddress': ['172.20.1.10'], 'IPSubnet': ['255.255.255.0']},
        ]
        targets = directory.discovery_targets(
            '192.168.5.88', ('192.168.3.50',), directory._lan_routes(interfaces), 2048)
        self.assertEqual(len(targets), 2048)
        self.assertEqual(targets[:2], ['192.168.5.88', '192.168.3.50'])
        self.assertIn('192.168.7.254', targets)
        self.assertNotIn('192.168.6.20', targets)
        self.assertEqual(len(set(targets)), len(targets))


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
