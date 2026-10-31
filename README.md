# image-prompt-hub

AstrBot 图片生成插件（`gemini image generation`）配套的在线提示词模板服务：公开只读检索与下载，申请密钥后可写。单个 Rust 二进制，PostgreSQL 存储，tantivy + jieba 的中文 BM25 检索。

## 功能

- 公开只读：模板检索（中英文、字段加权、命中片段）、详情（ETag/304）、批量、标签、举报。
- 目录快照：全部已公开模板的确定性 JSON 包（gzip、ETag 为内容哈希），供插件本地缓存同步。
- 密钥：邮箱白名单申请、一次性链接确认（打开不生效，必须点确认）、一邮箱一密钥、重置作废旧密钥、自助吊销。
- 写接口：上传、批量导入、修改（If-Match 乐观并发）、删除，仅限本人或 admin。模板归属绑定账号（邮箱身份），重置密钥不会丢失自己的模板；每个账号有每小时新建条数与模板总数两项额度。
- 管理：举报列表、模板下架与恢复、按邮箱查密钥（`POST /v1/admin/keys/lookup`，邮箱不进 URL）、吊销密钥、账号封禁与解封（吊销全部密钥，可同时隐藏其全部模板）。
- 接口文档：`GET /openapi.json`（OpenAPI 3.1，utoipa 生成）与 `GET /llms.txt`（给 AI 看的说明）。

## 本地运行

用 Docker 起 PostgreSQL（仅绑定回环地址，结束后删除）：

```bash
docker run -d --rm --name iph-test-pg \
  -e POSTGRES_PASSWORD=iph_test -e POSTGRES_DB=iph_test \
  -p 127.0.0.1:55432:5432 postgres:17-alpine
```

准备配置并启动（迁移自动执行）：

```bash
cp .env.example .env
# 编辑 .env：DATABASE_URL 指向上面那个库，其余密钥换成随机值
cargo run --release -- serve
```

创建第一把管理员密钥（只在终端显示一次）：

```bash
cargo run --release -- admin create-key --email you@example.com --scopes read,write,admin
```

## 命令行

```
image-prompt-hub serve                                    # 启动服务
image-prompt-hub migrate                                  # 只执行数据库迁移
image-prompt-hub reindex                                  # 从数据库重建检索索引（需先停止服务）
image-prompt-hub admin create-key --email <邮箱> [--scopes read,write,admin]
image-prompt-hub admin revoke-key --key-id <uuid>
image-prompt-hub admin ban --email <邮箱> [--hide-templates] --reason <理由>
image-prompt-hub admin unban --email <邮箱>
```

- `reindex` 只重建检索索引，不生成目录快照。服务运行时索引目录的写锁被占用，命令会失败并提示“请先停止服务”。服务每次启动本来就会按数据库整体重建索引。
- `admin ban` 吊销该账号全部密钥；加 `--hide-templates` 时把其全部公开模板改为隐藏。命令行不会通知运行中的服务，被隐藏的模板要等服务重启后才会从检索索引和目录快照里消失，服务运行时请优先用管理接口 `POST /v1/admin/accounts/ban`。
- `admin unban` 只解除封禁，不自动恢复模板。
- `admin create-key` 拒绝为被封禁账号创建密钥，需要先 `unban`。
- 被封禁账号的邮箱调用 `POST /v1/keys/request` 仍得到与其他邮箱完全一致的 202，冷却与每日上限也照常生效（不暴露封禁状态），但不会发信，封禁前发出的确认链接会被拒绝。

## 配置

环境变量加载自进程环境与 `.env`。必填项缺失或取值不合规时拒绝启动，并给出明确提示；所有密钥类配置的日志输出一律打码。取值校验：

- `KEY_PEPPER`、`EMAIL_HASH_SECRET`、`IP_HASH_SECRET` 至少 32 个字符、三者互不相同、不能包含 `change-me`；`EMAIL_ENC_KEY` 是 32 字节的 base64，且不能全零。`.env.example` 里这四项留空，照抄样例无法启动，生成方法见样例注释（例如 `openssl rand -base64 48`）。
- 布尔值只接受 `true/false/1/0/yes/no/on/off`，其他取值（比如拼错的 `SMTP_VALIDATE_CERTS=ture`）会拒绝启动，不会被当成 false。
- `PUBLIC_BASE_URL` 必须是 https；只有主机为 `localhost`、`127.0.0.1`、`[::1]` 时允许 http。
- 监听地址不是回环地址而 `TRUST_CF_CONNECTING_IP=true` 时，启动日志会给出警告：此时直连请求可以伪造 `CF-Connecting-IP`。该请求头不是合法 IP 时一律忽略，退回连接地址。

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `BIND_ADDR` | `127.0.0.1:8787` | 监听地址；生产经 Cloudflare Tunnel 接入 |
| `DATABASE_URL` | 必填 | PostgreSQL 连接串 |
| `DATA_DIR` | `./data` | 检索索引与目录快照目录 |
| `PUBLIC_BASE_URL` | 必填 | 对外地址，用于邮件验证链接与 llms.txt；必须是 https（本机地址除外） |
| `TRUST_CF_CONNECTING_IP` | `true` | 为 true 时客户端 IP 取 `CF-Connecting-IP`（须是合法 IP，否则退回连接地址） |
| `KEY_PEPPER` | 必填 | 密钥哈希的 HMAC 密钥（≥32 字符，三者互不相同） |
| `EMAIL_HASH_SECRET` | 必填 | 邮箱哈希的 HMAC 密钥（≥32 字符，三者互不相同） |
| `IP_HASH_SECRET` | 必填 | IP 哈希的 HMAC 密钥（≥32 字符，三者互不相同） |
| `EMAIL_ENC_KEY` | 必填 | 32 字节 base64，加密验证记录里的邮箱明文 |
| `EMAIL_DOMAIN_ALLOWLIST` | `qq.com,foxmail.com,163.com,gmail.com,*.edu.cn` | 邮箱后缀白名单 |
| `EMAIL_PROVIDER` | `disabled` | `disabled` / `smtp` / `cloudflare` |
| `SMTP_HOST` `SMTP_PORT`(587) `SMTP_USERNAME` `SMTP_PASSWORD` `SMTP_FROM` `SMTP_FROM_NAME` `SMTP_ENCRYPTION`(auto) `SMTP_AUTH_METHOD`(auto) `SMTP_VALIDATE_CERTS`(true) | — | 同名同义；`SMTP_ENCRYPTION` 的映射与插件市场不同：`starttls` 与 `auto`（非 465 端口）用必需 STARTTLS，`auto` 的 465 端口与 `ssl_tls` 用隐式 TLS，不做机会式 STARTTLS（需要明文必须显式 `none`） |
| `CLOUDFLARE_EMAIL_ACCOUNT_ID` `CLOUDFLARE_EMAIL_API_TOKEN` `CLOUDFLARE_EMAIL_FROM` `CLOUDFLARE_EMAIL_FROM_NAME` | — | 与插件市场同名同义 |
| `EMAIL_DAILY_LIMIT` | `0` | 全站每日发信上限（存库，重启不清零），0 不限 |
| `EMAIL_COOLDOWN_SECS` | `600` | 同一邮箱验证邮件冷却 |
| `EMAIL_PER_DAY_LIMIT` | `5` | 同一邮箱每日验证邮件上限 |
| `ACCOUNT_CREATE_PER_HOUR` | `100` | 账号每小时新建模板条数（导入逐条计入，超出 429） |
| `ACCOUNT_TEMPLATE_LIMIT` | `1000` | 账号未删除模板总数上限（超出 403） |
| `CATALOG_DEBOUNCE_SECS` | `60` | 数据变动后多久重新生成目录快照 |
| `RATE_ANON_READ_PER_MIN` | `60` | 匿名读限流（每 IP） |
| `RATE_KEYED_READ_PER_MIN` | `600` | 带密钥读限流（每密钥） |
| `RATE_WRITE_PER_MIN` | `60` | 写限流（每密钥） |
| `RATE_KEY_REQUEST_PER_HOUR` | `5` | 申请密钥限流（每 IP） |
| `RATE_KEY_VERIFY_PER_HOUR` | `20` | 验证确认限流（每 IP） |
| `RATE_REPORT_PER_HOUR` | `10` | 举报限流（每 IP） |
| `RATE_AUTH_ATTEMPT_PER_MIN` | `120` | 带 Bearer 请求的认证尝试限流（每 IP，查库前扣减，无效密钥也消耗额度） |
| `LOG_FORMAT` | `pretty` | `pretty` / `json` |

IPv6 客户端按 /64 网段作为限流键与 IP 哈希的输入（IPv4 按完整地址，IPv4 映射地址按其 IPv4 计），避免在一个网段内轮换地址绕过限流。限流状态在进程内存里，后台每 5 分钟清理已恢复满额度的键。

## 测试

```bash
# 单元测试（无需数据库）
cargo test --all-features

# 集成测试（需要 PostgreSQL，见上面的 docker run）
export DATABASE_URL=postgres://postgres:iph_test@127.0.0.1:55432/iph_test
cargo test --all-features
docker stop iph-test-pg
```

集成测试未设置 `DATABASE_URL` 时自动跳过（打印跳过原因后返回）；有数据库时每个测试使用自己的临时 schema（连接串带 `search_path`），互不干扰，测试结束立即删除。`DROP DATABASE` 每次都会强制检查点，并发收尾时既慢又容易在进程退出前来不及清理，所以不用一测试一库。

测试不依赖真实时钟：邮箱冷却、验证令牌过期、额度窗口都通过直接修改数据库里的时间戳来推进，限流额度默认放得很大，需要触发限流的测试再显式调小。命令行的测试直接运行编译出的二进制子进程。

## 安全说明

- 库里只存密钥的 HMAC 哈希、邮箱的 HMAC 哈希与 IP 的 HMAC 哈希；验证令牌只存 SHA-256；邮箱明文仅在验证记录有效期内加密存放，用完或过期即清空。
- 密钥只经 `Authorization: Bearer` 传递，不进 URL；访问日志不含查询字符串。
- 确认页与结果页带 `Content-Security-Policy: default-src 'none'`、`X-Frame-Options: DENY`、`Referrer-Policy: no-referrer`、`Cache-Control: no-store`。
- 请求体默认上限 256KB（导入接口 1MB），请求超时 10 秒，全站响应带 `X-Content-Type-Options: nosniff`，不开 CORS。
- 邮箱验证链接打开不生效，必须在确认页点“确认”，避免邮箱安全扫描自动触发重置。
- 邮箱身份做了规范化（gmail.com 去掉本地部分的点和 `+` 后缀，其他域名去掉 `+` 后缀），同一邮箱的变体地址共享密钥、限频与封禁状态。
- 密钥确认流程不在数据库事务里发信：先占用验证记录并登记 `pending_delivery` 密钥并提交，发信成功后再按邮箱身份加咨询锁、吊销旧密钥并激活新密钥；发信失败则删除 pending 密钥并恢复验证记录，链接可以重试。后台清理会删除卡住超过 1 小时的 pending 密钥。确认流程在独立任务里执行，请求超时或客户端断开不会让它停在半途。
- 模板归属绑定账号身份（`owner_email_hmac`），不绑定密钥 ID；`owner_key_id` 只记录上传时用的密钥。
- 带 Bearer 的请求在查库前先按客户端 IP 扣一次认证尝试额度，随机密钥的请求不能绕过限流去反复查库。
- 所有响应默认 `Cache-Control: no-store`；只有明确公开的只读接口的成功响应（200/304）允许共享缓存（目录快照 `public, max-age=300`，其余公开读接口 `public, max-age=60`）；带 `Authorization` 头的请求一律 `private, no-store`，错误响应与写操作永不缓存。
- SMTP 与插件市场的映射不同：`starttls` 与 `auto`（非 465 端口）使用必需 STARTTLS，服务器不提供时拒绝发送，账号密码不会以明文外泄；`auto` 的 465 端口与 `ssl_tls` 使用隐式 TLS；只有显式配置 `none` 才会明文连接。
- 发信失败的错误信息写日志前会脱敏邮箱地址，日志里没有密钥、验证令牌、邮箱明文和 IP 明文。
- 请求里的 NUL 等数据库无法存储的字符统一返回 400，不会变成 500；模板正文除换行、回车、制表符外不允许控制字符。
- 依赖审计：`cargo audit` 报告 0 个漏洞、0 条警告（tantivy 0.27 依赖已修复的 `lru 0.18`）。审计结论会随依赖和公告库更新而变化，发布前请重新运行。
