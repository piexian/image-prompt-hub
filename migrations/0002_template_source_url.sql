-- 出处或许可页面链接；可空，校验在应用层完成
-- 回滚到不认识本迁移的旧版本时只删迁移记录、保留这一列，再次升级要能重复执行，所以用 IF NOT EXISTS
ALTER TABLE templates ADD COLUMN IF NOT EXISTS source_url TEXT;
