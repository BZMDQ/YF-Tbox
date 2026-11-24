"""验证多设备无线烧录的调度契约，无需 GUI、网口或开发板。"""

import threading
import unittest
from collections import defaultdict
from types import SimpleNamespace
from unittest.mock import Mock

import wireless_batch


class WirelessBatchTests(unittest.TestCase):
    def setUp(self):
        self.args = [SimpleNamespace(host=f'192.0.2.{index}', port=5000)
                     for index in range(1, 4)]
        self.key = b'test-key'
        self.cancel = threading.Event()
        self.events = defaultdict(list)
        self.events_lock = threading.Lock()

    def notify(self, host, state, percent, detail, stage):
        # 工作线程并发回调，按设备保留事件顺序。
        with self.events_lock:
            self.events[host].append((state, percent, detail, stage))

    def test_concurrent_results_and_progress_are_isolated(self):
        first, second = self.args[:2]
        both_workers_ready = threading.Barrier(2, timeout=5)

        def program(target):
            self.assertIs(target.cancel, self.cancel)
            self.assertEqual(target.key, self.key)
            self.assertEqual(target.args.host, target.host)
            self.assertEqual(target.args.port, 5000)
            both_workers_ready.wait()
            if target.host == first.host:
                target.progress(64, '读回校验', 3)
                return '已写入并校验'
            target.progress(23, '写入目标', 2)
            raise RuntimeError('目标正忙')

        outcomes = wireless_batch.run(self.args[:2], self.key, self.cancel,
                                      program, self.notify, max_workers=2)

        self.assertEqual(outcomes, {first.host: 'success', second.host: 'failed'})
        self.assertIn(('running', 64, '读回校验', 3), self.events[first.host])
        self.assertIn(('running', 23, '写入目标', 2), self.events[second.host])
        self.assertEqual(self.events[first.host][-1][0], 'success')
        self.assertEqual(self.events[second.host][-1][0], 'failed')
        self.assertIn('目标正忙', self.events[second.host][-1][2])

    def test_commit_and_rejection_are_per_device(self):
        committed, rejected = self.args[:2]
        both_workers_ready = threading.Barrier(2, timeout=5)

        def program(target):
            target.mark_committed()
            both_workers_ready.wait()
            if target.host == rejected.host:
                target.reject_commit()
                self.assertFalse(target.committed)
                raise RuntimeError('拒绝提交')
            self.assertTrue(target.committed)
            return 'pending', '已提交，等待版本确认'

        outcomes = wireless_batch.run(self.args[:2], self.key, self.cancel,
                                      program, self.notify, max_workers=2)

        self.assertEqual(outcomes, {committed.host: 'pending', rejected.host: 'failed'})
        self.assertEqual(self.events[committed.host][-1][0], 'pending')
        self.assertIn('等待版本确认', self.events[committed.host][-1][2])
        self.assertEqual(self.events[rejected.host][-1][0], 'failed')
        self.assertIn('拒绝提交', self.events[rejected.host][-1][2])

    def test_cancel_skips_queued_devices_and_preserves_verified_result(self):
        programmed = []

        def program(target):
            programmed.append(target.host)
            # 第一个设备已有成功回执，其余设备还在等待工作线程。
            target.cancel.set()
            return '已写入并校验'

        outcomes = wireless_batch.run(self.args, self.key, self.cancel,
                                      program, self.notify, max_workers=1)

        first, second, third = [args.host for args in self.args]
        self.assertEqual(programmed, [first])
        self.assertEqual(outcomes, {first: 'success', second: 'stopped', third: 'stopped'})
        self.assertEqual(self.events[first][-1][0], 'success')
        for host in (second, third):
            self.assertEqual([event[0] for event in self.events[host]], ['stopped'])

    def test_hex_stop_only_sends_cancel_to_the_device_that_started_programming(self):
        programming, uploading = [wireless_batch.Target(args, self.key, self.cancel,
                                                        self.notify, lambda _text: None)
                                  for args in self.args[:2]]
        programming.mark_committed()
        programming_socket, uploading_socket = Mock(), Mock()
        programming.attach_socket(programming_socket)
        uploading.attach_socket(uploading_socket)
        closed = {sock: threading.Event() for sock in (programming_socket, uploading_socket)}
        app = SimpleNamespace(stop_event=self.cancel,
                              wireless_batch_job=SimpleNamespace(
                                  kind='hex', lock=threading.Lock(), active=[programming, uploading]),
                              _close_socket=lambda sock: closed[sock].set())
        stop_frame = b'wireless-stop'

        self.assertTrue(wireless_batch.stop(app, stop_frame))
        self.assertTrue(self.cancel.is_set())
        for done in closed.values():
            self.assertTrue(done.wait(5))
        # 已进入擦写的设备收到取消帧，上传中的设备只关闭套接字。
        programming_socket.sendall.assert_called_once_with(stop_frame)
        uploading_socket.sendall.assert_not_called()


if __name__ == '__main__':
    unittest.main()
