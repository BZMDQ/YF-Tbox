"""设备总览的本地操作摘要，独立于详细日志。"""
from contextlib import closing
import sqlite3
import time

HISTORY_SECONDS = 24 * 60 * 60
HistoryError = sqlite3.Error


class OperationHistory:
    def __init__(self, path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started INTEGER NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL)""")
            db.execute("CREATE INDEX IF NOT EXISTS operations_started ON operations(started)")

    def _connect(self):
        return sqlite3.connect(str(self.path), timeout=0.25)

    @staticmethod
    def _prune(db, now):
        db.execute("DELETE FROM operations WHERE started <= ?", (now - HISTORY_SECONDS,))

    def start(self, action, target):
        # 仅保存简短的操作名称和目标，不保存传输数据、密钥或耗时。
        now = int(time.time())
        with closing(self._connect()) as db, db:
            self._prune(db, now)
            row = db.execute(
                "INSERT INTO operations(started,action,target,status) VALUES(?,?,?,?)",
                (now, ' '.join(action.split())[:120], ' '.join(target.split())[:100], '已开始'))
            return row.lastrowid

    def finish(self, record_id, state):
        with closing(self._connect()) as db, db:
            db.execute("UPDATE operations SET status=? WHERE id=?", (state, record_id))
            self._prune(db, int(time.time()))

    def recent(self):
        now = int(time.time())
        with closing(self._connect()) as db, db:
            self._prune(db, now)
            return db.execute(
                "SELECT started,action,target,status FROM operations WHERE started <= ? "
                "ORDER BY started DESC,id DESC", (now,)).fetchall()
