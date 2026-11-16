# 邮屿 · Mail Harbor

个人自托管多邮箱收件与通知中心。Go + Vue + SQLite，参考 Apple Mail 的邮件导航、列表和阅读区布局，支持深浅色及手机/平板/桌面。

当前版本 v0.2.0。源码：[GitHub](https://github.com/Stylle/mail-harbor)，镜像：[Docker Hub](https://hub.docker.com/r/stylle/mail-harbor)，支持 linux/amd64 和 linux/arm64。生产界面不包含示例邮件，真实邮箱和通知渠道需要部署者自行授权。

## 功能

- 最多20个邮箱：QQ、163、Gmail 使用 IMAP over TLS；Outlook 个人邮箱使用 Microsoft Graph 委托授权。
- 全部收件箱、账户筛选、未读、星标、索引搜索、纯文本正文及附件下载。已读和星标只影响本站，不修改或删除原邮箱邮件。
- 默认每分钟检查新邮件，网页关闭后仍运行。首次只建基线、不推送历史：IMAP 最近30封，Outlook 最近7天。UIDVALIDITY 改变会自动重建基线。
- Telegram 绑定流程：开启 → 填 Token → 保存设置 → 生成绑定码 → 私聊机器人发送完整 `/bind` 指令。保存时创建 `/help`、`/status` 菜单。
- Webhook 支持请求地址、POST/PUT/PATCH/GET、JSON 请求头、JSON/Text 正文模板和可选 HMAC-SHA256 签名。测试使用当前表单，不保存、不发送真实邮件；触发条件和内容范围由推送规则决定。
- 规则按邮箱、发件人、域名和标题/可用摘要筛选，支持白名单和黑名单。任一名单项命中算匹配；黑名单优先阻止所选通道，匹配的待发通知也会取消。普通新规则作用于后续新邮件。无规则时不推送。
- 持久化同步游标和通知队列；失败退避重试，最多8次，支持手动重试。正常同步去重；网络中断造成投递结果不确定时外部渠道仍可能重复通知。
- 单管理员、无注册；强制 TOTP 双重验证，强密码至少12字符且含大小写字母、数字和符号；一次性恢复码可用于重绑。密码 PBKDF2-SHA256 哈希，凭据 AES-256-GCM 加密。
- 写信和便捷回复：QQ/163/Gmail 使用 TLS SMTP，Outlook 使用 Graph Mail.Send。支持收件人、抄送、密送及附件；发信记录最多200条，提交ID防止重复点击，不自动重试结果不明的发信。
- 按邮箱配置可选 HTTP CONNECT/HTTPS/SOCKS5 代理，直连为默认。代理凭据加密，收信、发信与该邮箱 OAuth/Graph 共用，通知渠道不受影响。
- 中英文切换、主题和语言只保存在当前设备；邮件原文与用户自定义名称不翻译。圆角邮件卡片和较大字体适配多设备。

## 最简部署

```sh
docker compose up -d
```

打开 `http://服务器:28187` 创建管理账户，强制绑定验证器并保存恢复码，然后添加邮箱。已有v0.1账户升级后先用原密码登录，再设置强密码和验证器；邮箱、同步进度和索引保留。首次初始化前不要把未配置实例暴露到公网；公网访问使用 HTTPS 反向代理。

```sh
docker run -d --name mail-harbor --restart unless-stopped -p 28187:8080 -v mail-harbor-data:/data stylle/mail-harbor:v0.2.0
```

只需一个容器和一个数据卷，无 Redis 或外部数据库。容器 UID/GID10001。`/data` 的 `master.key` 和数据库必须同时保留，单个卷只供一个实例使用。

从源码构建可运行 `docker compose up -d --build`。更新前下载加密备份，并保留原数据卷；拉取新版后重新创建容器即可，不要删除数据卷。`latest` 跟随稳定版本，固定版本部署使用 `v0.2.0`。

可选环境变量：`LISTEN_ADDR`（容器默认 `:8080`）、`DATA_DIR`（默认 `/data`）；`USER`、`PASSWORD` 仅首次初始化生效，密码至少12字符，并包含大写、小写、数字和符号。`TRUST_PROXY=1` 仅用于由可信代理覆盖 `X-Forwarded-Proto` 的 HTTPS 部署，启用 Secure Cookie。会话在进程内保存，重启服务需要重新登录，邮箱授权和同步进度仍保留。

## 接入配置

| 邮箱 | 配置 |
|---|---|
| QQ | 网页邮箱设置 → 账号与安全 → 安全设置，开启 IMAP，生成客户端授权码。不要填普通邮箱密码。 |
| 163 | 网页邮箱设置 → POP3/SMTP/IMAP，开启 IMAP 并生成客户端授权码。应用发送 IMAP ID 兼容网易身份检查。 |
| Gmail | 开启 Google 两步验证，账户允许时生成应用专用密码。组织策略等可能禁止此功能。当前不包含 Google OAuth。 |
| Outlook | 支持个人 Outlook/Hotmail/Live 账户；在 Entra 注册支持个人微软账户的应用，开启公共客户端流，添加 Graph 委托权限 Mail.Read、User.Read、Mail.Send。填写主要邮箱地址和 Client ID，保存后连接微软账号，输入设备代码。请求包含 offline_access，不需要 Client Secret 或公网回调。 |

每个部署者自行注册微软应用，不借用其他项目的 Client ID。目前不支持组织租户、共享邮箱和世纪互联 Microsoft 365。服务器需要能访问各邮箱、微软及 Telegram；浏览器可访问不代表服务器可用。无需入站25端口。

参考：[QQ 授权码](https://help.mail.qq.com/detail/106/985)、[Google 应用专用密码](https://support.google.com/mail/answer/185833)、[微软设备授权](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)、[Graph 邮件增量](https://learn.microsoft.com/en-us/graph/delta-query-messages)。

## 通知与存储边界

一个 Bot 只供一个运行实例使用，已有 Webhook 的机器人会拒绝接入；请先在原服务关闭或创建专用 Bot。摘要约350字，Telegram 长正文按通道上限截断，Webhook 正文最多12000字符，不自动转发附件。附件在收件箱按需下载。

Webhook 签名头 `X-Mail-Harbor-Signature: sha256=HEX`，计算 HMAC 的内容为 `X-Mail-Harbor-Timestamp + "." + 原始JSON请求体`；时间头为 Unix 秒。接收端应检查时间窗口、签名及 `Idempotency-Key`。允许普通内网/公网 HTTP(S)，拒绝重定向、回环和链路本地地址。`mail.test` 为测试，`mail.received` 为新邮件。仅提醒模式不包含发件人、主题或正文。

最多缓存5000封邮件索引、10000条通知任务、150条日志。只读取 INBOX，不同步其他文件夹；正文、附件按需从原邮箱读取，单封上限20MB，正文显示上限1MB。HTML 转纯文本，不加载远程图片或执行脚本。邮件被原邮箱删除/移动或授权失效后可能无法读取，因此本站不是永久归档。IMAP 索引没有预载摘要，关键词主要匹配标题；不提供全文搜索或上游删除操作。写信使用SMTP或Graph，应用不缓存发送正文与附件；SMTP是否保留已发送副本取决于供应商。Outlook保存至原邮箱已发送文件夹。附件上限：其他邮箱8MB，Outlook2MB，最多10个；正文最多1MB。发信记录只表示提交状态，不保证最终送达。结果不明时请先查原邮箱，避免重复发送。Graph 游标过期时需重新接入，界面会提示。真实账号可用性受邮箱安全策略限制，需要实际授权验证。

## 加密备份

设置独立强备份密码（至少12字符，含大小写、数字和符号），下载 `.mhbackup`。包内包含管理密码哈希、双重验证配置、恢复码哈希、邮箱/代理/通知授权、规则、索引、同步游标、队列、发信记录及运行记录。PBKDF2-SHA256（600000次）派生密钥，AES-256-GCM 加密；密码无法找回。

新部署先创建临时管理账户，再上传备份，输入备份密码并确认替换。系统等待后台任务退出，验证后原子替换数据，凭据用新主机主密钥重新加密，旧会话全部失效。用备份中的管理账户及验证器重新登录；旧备份未启用2FA时需要完成安全升级。新备份包含schema v2，旧软件会拒绝导入，避免静默丢弃2FA；新软件可导入旧v1备份，恢复密码沿用原备份，不强制改动旧包。错误密码或损坏文件不会替换现有数据。正文与附件仍依赖原邮箱，已撤销授权需重新连接。不要同时运行两个使用同一 Bot 的实例。

## 开发

Go1.26.11+、Node24+：

```sh
cd frontend
npm ci
npm test
npm run build
cd ..
go test ./...
go vet ./...
go run .
```

原生默认 `127.0.0.1:28187`，健康端点 `/healthz`。前端构建包含 TypeScript 检查，必须先构建前端再编译 Go。`docker build --target test .` 运行 Linux race detector 和 vet。浏览器验证见 [设计与验证](docs/DESIGN-QA.md)。

MIT 开源，依赖许可见 [第三方说明](docs/THIRD-PARTY.md)。不向源码、Issue、日志或截图提交真实凭据、运行数据库或备份。


## 代理与安全

在邮箱编辑页展开“邮箱代理（可选）”，填写 `http://host:port`、`https://host:port` 或 `socks5://host:port`；需要认证时使用 `scheme://user:password@host:port`，特殊字符须 URL 编码。留空保留已有代理，勾选移除后恢复直连。CONNECT/SOCKS5只传输隧道，目标IMAP/SMTP仍验证TLS证书；Microsoft请求保持HTTPS。代理并不绕过邮箱自身的授权或限流。

新 Outlook 发信需要在 Entra 添加委托 `Mail.Send` 并重新授权；旧只读授权不会自动获得发信权限。不要把实际邮箱授权码、代理密码、验证器密钥、恢复码或备份文件提交到源码或聊天。

接口需要登录、强制2FA及写操作CSRF校验；登录和安全操作有限速。邮件文本通过参数化SQLite保存，不拼接SQL。正文仅显示文本和白名单协议链接，禁止执行HTML/JavaScript，不加载跟踪图片；外链使用noopener/noreferrer。请求头禁止CRLF和连接控制覆盖，Webhook禁止重定向及回环/链路本地目标。公网仍需HTTPS、及时更新和妥善保护主机/数据卷；这些措施不构成绝对安全保证，主机完全失陷仍可能暴露邮件和凭据。
