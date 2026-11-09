-- 从 v1 升级到 v2（已有数据库执行一次）
ALTER TABLE users ADD COLUMN failed_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until INTEGER;

CREATE TABLE IF NOT EXISTS login_logs (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name    TEXT,
  ip      TEXT,
  ua      TEXT,
  at      INTEGER NOT NULL,
  ok      INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_login_logs_user ON login_logs(user_id, at DESC);
