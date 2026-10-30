-- 首版 schema：模板、密钥、邮箱验证、举报与发信计数

CREATE TABLE api_keys (
    id UUID PRIMARY KEY,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    email_hmac TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{read}',
    status TEXT NOT NULL DEFAULT 'pending_delivery' CHECK (status IN ('pending_delivery', 'active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

-- 同一邮箱最多一把 active 密钥，重置在吊销旧密钥的同一事务里激活新密钥
CREATE UNIQUE INDEX api_keys_one_active_per_email ON api_keys (email_hmac) WHERE status = 'active';
-- 封禁、管理员按邮箱查密钥时按账号身份找出全部状态的密钥
CREATE INDEX api_keys_email_idx ON api_keys (email_hmac);

CREATE TABLE email_verifications (
    id UUID PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    email_hmac TEXT NOT NULL,
    email_ciphertext BYTEA NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('issue', 'reset')),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip_hash TEXT NOT NULL
);

CREATE INDEX email_verifications_email_created_idx ON email_verifications (email_hmac, created_at DESC);

CREATE TABLE templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    ai_description TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL,
    defaults JSONB NOT NULL DEFAULT '{}'::jsonb,
    reference TEXT NOT NULL DEFAULT 'none' CHECK (reference IN ('none', 'optional', 'required')),
    tags TEXT[] NOT NULL DEFAULT '{}',
    author TEXT,
    owner_key_id UUID NOT NULL REFERENCES api_keys (id),
    owner_email_hmac TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'published' CHECK (status IN ('published', 'hidden', 'deleted')),
    version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX templates_status_updated_idx ON templates (status, updated_at DESC);
-- 归属按账号身份（email_hmac）判断；owner_key_id 只记录上传时用的密钥
CREATE INDEX templates_owner_idx ON templates (owner_email_hmac) WHERE status <> 'deleted';
-- 每小时新建额度按创建时间统计，含已删除的模板，用不上上面的部分索引
CREATE INDEX templates_owner_created_idx ON templates (owner_email_hmac, created_at DESC);
CREATE INDEX templates_owner_key_idx ON templates (owner_key_id);

CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    ip_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX reports_created_idx ON reports (created_at DESC);
CREATE INDEX reports_template_idx ON reports (template_id);

CREATE TABLE banned_accounts (
    email_hmac TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE email_daily_counter (
    day DATE PRIMARY KEY,
    count BIGINT NOT NULL DEFAULT 0
);
