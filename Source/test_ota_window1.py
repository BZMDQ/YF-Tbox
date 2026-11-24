"""验证系统 OTA 窗口 2、旧固件回退，以及写入回执的边界。"""
import select
import socket
import struct
import threading
import unittest
from contextlib import contextmanager
from unittest.mock import Mock

import local_tcp_client as client


@contextmanager
def server(handler):
    errors = []
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(3)

    def run():
        try:
            with listener.accept()[0] as connection:
                connection.settimeout(3)
                handler(connection)
        except Exception as exc:
            errors.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    sock = socket.create_connection(listener.getsockname(), timeout=3)
    try:
        yield sock
    finally:
        sock.close()
        thread.join(4)
        if thread.is_alive():
            raise AssertionError('回环服务未结束')
        if errors:
            raise errors[0]


def read_frame(connection):
    header = client.exact(connection, 20)
    magic, op, offset, size, _ = client.HEADER.unpack(header)
    assert magic == b'LNET' and size <= 32768
    return op, offset, client.exact(connection, size)


class WindowOne(unittest.TestCase):
    def test_fixed_window1_never_negotiates_and_waits_each_ack(self):
        for size in (16384, 4096):
            package = bytes(range(256)) * 150 + b'tail'
            modes, progress, info = [], [], []

            def handler(connection):
                offset = 0
                while offset < len(package):
                    op, position, block = read_frame(connection)
                    self.assertEqual((op, position), (3, offset))
                    self.assertEqual(block, package[offset:offset + size])
                    self.assertFalse(select.select([connection], [], [], 0.01)[0],
                                     '收到ACK前发送了第二片')
                    offset += len(block)
                    if position == 0:
                        connection.sendall(client.frame(0x80000001, payload=b'{}'))
                    packet = client.frame(0x80000003, payload=struct.pack('<I', offset))
                    connection.sendall(packet[:7])
                    connection.sendall(packet[7:])

            with self.subTest(chunk_size=size), server(handler) as connection:
                client.upload_ota_stream(connection, package, chunk_size=size,
                                         on_mode=lambda *value: modes.append(value),
                                         on_progress=progress.append, on_info=info.append)
            self.assertEqual(modes, [(size, 1)])
            self.assertEqual(progress[-1], len(package))
            self.assertEqual(info, [b'{}'])

    def test_32k_window2_sends_two_and_refills_after_first_ack(self):
        size = 32768
        package = b'a' * size + b'b' * size + b'last'
        modes, progress = [], []

        def handler(connection):
            self.assertEqual(read_frame(connection), (35, 0, b''))
            connection.sendall(client.frame(0x80000023, payload=struct.pack('<II', size, 2)))
            self.assertEqual(read_frame(connection), (3, 0, b'a' * size))
            self.assertEqual(read_frame(connection), (3, size, b'b' * size))
            self.assertFalse(select.select([connection], [], [], 0.02)[0],
                             '确认前多发了第三块')
            connection.sendall(client.frame(0x80000003, payload=struct.pack('<I', size)))
            self.assertEqual(read_frame(connection), (3, size * 2, b'last'))
            for offset in (size * 2, len(package)):
                connection.sendall(client.frame(0x80000003, payload=struct.pack('<I', offset)))

        with server(handler) as connection:
            client.upload_ota_stream(connection, package, chunk_size=size, window=2,
                                     on_mode=lambda *value: modes.append(value),
                                     on_progress=progress.append)
        self.assertEqual(modes, [(32768, 2)])
        self.assertEqual(progress, [32768, 65536, len(package)])

    def test_unsupported_capabilities_falls_back_before_first_write(self):
        package = b'x' * 16384 + b'tail'
        modes = []

        def handler(connection):
            self.assertEqual(read_frame(connection), (35, 0, b''))
            connection.sendall(client.frame(0x80000023, offset=11))
            self.assertEqual(read_frame(connection), (3, 0, package[:16384]))
            self.assertFalse(select.select([connection], [], [], 0.02)[0])
            connection.sendall(client.frame(0x80000003, payload=struct.pack('<I', 16384)))
            self.assertEqual(read_frame(connection), (3, 16384, b'tail'))
            connection.sendall(client.frame(0x80000003, payload=struct.pack('<I', len(package))))

        with server(handler) as connection:
            client.upload_ota_stream(connection, package, chunk_size=32768, window=2,
                                     on_mode=lambda *value: modes.append(value))
        self.assertEqual(modes, [(16384, 1)])

    def test_read_ahead_preserves_two_acks_and_info_before_commit(self):
        size = 32768
        package = b'a' * size + b'tail'
        capability = client.frame(0x80000023, payload=struct.pack('<II', size, 2))
        ack1 = client.frame(0x80000003, payload=struct.pack('<I', size))
        ack2 = client.frame(0x80000003, payload=struct.pack('<I', len(package)))
        info = client.frame(0x80000001, payload=b'{}')
        commit = client.frame(0x80000004)
        sock = Mock()
        sock.recv.side_effect = [capability, ack1 + ack2 + info, commit]
        reader = client.SocketReader(sock, read_ahead=client.OTA_RESPONSE_READ_SIZE)
        progress, messages = [], []

        client.upload_ota_stream(sock, package, chunk_size=size, window=2, reader=reader,
                                 on_progress=progress.append, on_info=messages.append)
        client.request(sock, 4, on_info=messages.append, reader=reader)

        # 同次读取到的两条 ACK 仍按偏移消费，后续通知交给提交阶段。
        self.assertEqual(progress, [size, len(package)])
        self.assertEqual(messages, [b'{}'])
        self.assertEqual(sock.recv.call_count, 3)
        self.assertEqual([call.args[0] for call in sock.sendall.call_args_list], [
            client.frame(35),
            client.frame(3, 0, package[:size]) + client.frame(3, size, package[size:]),
            client.frame(4),
        ])

    def test_layout_preflight_refuses_wrong_board_before_begin(self):
        def handler(connection):
            self.assertEqual(read_frame(connection), (36, 0, b''))
            connection.sendall(client.frame(0x80000024, payload=struct.pack('<I', 2)))
            self.assertEqual(connection.recv(1), b'')

        with server(handler) as connection:
            with self.assertRaisesRegex(ValueError, '不匹配'):
                client.check_ota_layout(connection, 1)

    def test_layout_preflight_legacy_on_unsupported_query(self):
        def handler(connection):
            self.assertEqual(read_frame(connection), (36, 0, b''))
            connection.sendall(client.frame(0x80000024, offset=11))

        with server(handler) as connection:
            client.check_ota_layout(connection, 1)
        with server(handler) as connection:
            with self.assertRaisesRegex(ValueError, '不匹配'):
                client.check_ota_layout(connection, 2)

    def test_invalid_ack_or_rejection_never_sends_next_frame(self):
        for failure in ('offset', 'crc', 'reject'):
            def handler(connection):
                self.assertEqual(read_frame(connection)[:2], (3, 0))
                packet = bytearray(client.frame(0x80000003,
                    offset=6 if failure == 'reject' else 0,
                    payload=b'' if failure == 'reject' else struct.pack('<I', 1 if failure == 'offset' else 16384)))
                if failure == 'crc':
                    packet[16] ^= 1
                connection.sendall(packet)
                self.assertEqual(connection.recv(1), b'')

            with self.subTest(failure=failure):
                with self.assertRaises((ValueError, client.DeviceError)):
                    with server(handler) as connection:
                        client.upload_ota_stream(connection, b'x' * 20000)

    def test_precancel_sends_nothing(self):
        stop = threading.Event()
        stop.set()
        with self.assertRaises(InterruptedError):
            with server(lambda connection: self.assertEqual(connection.recv(1), b'')) as connection:
                client.upload_ota_stream(connection, b'x', cancel=stop)


if __name__ == '__main__':
    unittest.main()
