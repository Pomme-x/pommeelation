-- 欢愉剧场 · 用户系统数据库
-- 用法：wrangler d1 execute elation-db --remote --file=./schema.sql

CREATE TABLE IF NOT EXISTS users (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT UNIQUE NOT NULL,
  pass_hash   TEXT NOT NULL,
  role        TEXT NOT NULL DEFAULT 'user',     -- user / admin
  status      TEXT NOT NULL DEFAULT 'active',   -- active / banned
  created_at  INTEGER NOT NULL,
  last_login  INTEGER,
  last_ip     TEXT,
  last_ua     TEXT,
  login_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  ip         TEXT,
  ua         TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at);

-- 默认设置：注册名额上限、共享注册码（首次部署后在管理后台改）
INSERT OR IGNORE INTO settings(key, value) VALUES ('max_users', '15');
INSERT OR IGNORE INTO settings(key, value) VALUES ('register_code', 'elation2026');
