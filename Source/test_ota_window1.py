"""验证系统OTA固定窗口1，不向仍运行1.4.37的开发板协商窗口2。"""
import select
import socket
import struct
import threading
import unittest
from contextlib import contextmanager

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
    assert magic == b'LNET' and size <= 16384
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
