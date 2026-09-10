# 阶段验收记录

验证日期：2026-09-10 UTC。

## 已验证

| 范围 | 证据/结果 |
| --- | --- |
| Phase 0 | 本地 Python 3.14 virtualenv；FastAPI + SQLite 启动与健康检查通过 |
| 自动测试 | Windows Python 3.14：103 passed / 10 Linux-only skipped；Debian Python 3.11：113 passed |
| 代码检查 | Ruff lint、format、Git diff whitespace 检查通过 |
| 依赖 | 锁定运行/开发依赖；`pip check` 通过 |
| 持久化 | 应用重建后会话仍有效；退出、到期、重设管理员使旧会话失效 |
| 防护 | CSRF、同源、错误密码限速、全局限速、请求体大小限制、受信主机 |
| 数据恢复 | WAL 模式在线备份，完整性校验，恢复后旧会话不可用、管理员可重新登录 |
| 故障状态 | 数据库异常返回 503，不输出敏感路径或假 Online |
| 真实进程 | 本机 Uvicorn 监听 127.0.0.1:8000；真实 Chrome 登录/退出成功 |
| 页面布局 | Chrome 1440×1100 与 390×844；截图人工检查，无横向溢出、无浏览器脚本错误 |
| 部署脚本 | 在真实 Debian 12 VPS 执行，Python 3.11 + Caddy 2.11.4 + systemd 服务运行 |
| 公网 HTTPS | Let's Encrypt YE1 公网 IPv4 证书，TLS 1.3；Python 系统信任链及真实 Chrome/Edge 校验通过 |
| 线上登录 | Chrome/Edge 登录和退出通过；Secure、HttpOnly、SameSite=Strict 会话验证通过 |
| 线上响应式 | 1440×1100 与 390×844，无横向溢出、无页面脚本错误 |
| 服务恢复 | 分别重启 Controller 和 Caddy 后，公网健康检查恢复成功；已启用开机启动 |
| 线上备份 | pfem 非 root 用户在线备份和完整性校验成功；数据库 0600、目录 0700 |
| 防火墙 | 实测发现现有 UFW 仅放行 SSH；备份规则后添加 TCP 80/443，保留 SSH 规则；8000 仅监听 loopback |

浏览器验证发现并修复 `Referrer-Policy: no-referrer` 导致 POST 的 Origin 为 null 的登录问题。
现采用 same-origin；同源 POST 可用，跨站请求仍被拒绝，测试覆盖该响应头。

依赖测试工具目前有 2 条弃用警告（Starlette TestClient 的 httpx / AnyIO 兼容层），测试没有失败。
GitHub CI 配置覆盖 Linux Python 3.11 和 3.14，实际运行状态以仓库 Actions 为准。
公网 IP 部署提交 `7fd532d` 的两个 CI 环境均通过，含 40 项测试与 ShellCheck。

Chrome 自动化默认关闭组件更新时曾出现 CT 校验错误；恢复正常组件更新后验证通过，未使用忽略证书错误、禁用 CT 或自签名根证书。
短期证书自动续期由 Caddy 管理，尚未等待一个完整续期周期；当前已验证首次签发及重启后的证书加载。

## 未验证或未实现

- 域名模式的 DNS/证书未在现场执行；本次验证采用无域名的公网 IPv4 模式。
- Gateway 已完成现场部署；实际 SOCKS5 ISP 已通过认证、双源出口和后台复查。
- 设备管理、订阅、周期监控、History/Alerts 已完成并部署；仍需两台 iPhone 实机验收。
- 未使用真实 iPhone/Shadowrocket，MVP.md 的现场 Test 01–10 全部待执行。
- 未测试真实 Safari；390px Chrome 视口验证不是 iPhone 实机验收。

Phase 0–9 已完成。Phase 10 只剩两台 iPhone 的真实链路验收。

## Phase 2 开发验证

新增 21 项测试覆盖 v1 数据迁移、凭据引用、鉴权与 CSRF、恢复密钥下载、非法目标、重复注册清理、并发任务互斥、失败信息脱敏、成功后凭据清理、检测过期、重启中断恢复、SSH 主机密钥不匹配及未完成登录保护。
真实 Debian 12 已校验官方 sing-box 1.14.0 amd64 发行包 SHA-256，并通过初始拒绝代理配置的 check。完整服务部署和重复部署现已通过现场验证。

### Phase 2 现场结果（2026-09-09 UTC）

- Windows Python 3.14 与 Debian 12 Python 3.11：均 61 项测试通过；Ruff、ShellCheck 通过。
- 浏览器登记服务器、保存恢复密钥、提交部署任务成功；真实 sing-box 1.14.0 服务启动，SSH 密钥认证和 CPU/RAM/磁盘采样正常。
- 重复部署前后配置、防火墙文件、root 与 proxyadmin 公钥文件的 SHA-256 完全相同。
- 主动停止网关后检测任务失败，显示 CRITICAL；控制台重启网关后恢复 HEALTHY，PID 已变化。
- root 密码认证被拒绝；恢复密钥可登录；proxyadmin 无法使用 sudo 执行任意命令。
- 核心 SOCKS CONNECT 被拒绝；同一外部目标 root 可连接，pfem-proxy 用户被 nftables 阻断。
- 网关、独立防火墙、Controller、Caddy 四个服务均设为开机启动；尚未实际重启整台 VPS。
- Chrome 1440×1100 与 390×844 真实登录/退出、Gateway 页面、Cookie、TLS 校验通过，无页面溢出。
- 首次升级因 release 依赖目录权限不足失败，自动恢复旧代码及数据库；修复后升级成功，验证了真实回滚路径。
- GitHub 连接恢复后已逐个同步模块与修复提交；同步前本地验证提交祖先关系及内容一致，未强制改写主分支。

## Phase 3 开发验证

- Windows：78 passed，3 个仅 Linux helper 测试跳过；新增 ISP 测试覆盖首次冻结、IP 漂移、SQL 身份不可改写、认证/凭据脱敏、表单保护、队列互斥、分钟调度、重启恢复、过期状态及 SOCKS 协议分片响应。
- 真实 Gateway 上的预检：两个独立 HTTPS 服务取得相同公网出口，正确凭据通过；仅在测试请求中使用错误密码时返回 AUTH_FAILED，未修改实际保存的凭据。
- ISP 页面登记、固定身份持久化、分钟后台复查均已在线上通过，自动任务连续成功。Chrome 1440×1100 与 390×844 无横向溢出。
- Debian Python 3.11 现场 81 passed；GitHub Linux Python 3.11/3.14 CI 全部通过，Actions run 34296200145。

## Phase 4 开发验证

- Windows：90 passed；3 个 Gateway helper 测试以及 6 个配置事务测试只在 Linux 执行。覆盖鉴权/CSRF、凭据脱敏、过期 ISP 拒绝、完整出口匹配才提交、失败状态、重启恢复及拒绝直连的配置生成。
- Linux 事务测试覆盖候选配置校验失败不影响运行配置、实际出口失败恢复旧配置、防火墙一同恢复、回滚失败保留恢复任务、启动前恢复、提交幂等。
- Debian 99 passed；Ruff、格式检查、ShellCheck、真实 sing-box/nftables 语法校验通过。GitHub Python 3.11/3.14 CI run 34360821445 成功。
- 真实页面创建 EXIT-01，两个 HTTPS 服务经过网关核心和 ISP 得到相同固定出口；桌面和 390px 页面无溢出。
- 分别注入错误代理密码和错误预期 IP，均失败并恢复旧配置，原出口重新验证成功；未修改已保存的 ISP 凭据及身份。
- 故意不确认修改后的本地探测凭据，远程 120 秒定时器触发回滚，核心配置、防火墙、manifest 哈希全部恢复，旧出口复核成功。
- 五个服务 active 且 boot enabled；完整整机重启和手机测试仍未执行。

## Phase 5 设备管理

设备登记、编辑、唯一名称、输入长度、鉴权/CSRF、HTML 转义及修改历史已实现。Windows 全套 92 passed / 9 Linux-only skipped；生产界面验收将在后续部署中执行。

## Phase 6 订阅组

两台不同设备绑定、设备唯一归属、同网关出口切换的一次性确认与旧/新 ISP 审计通过测试。Windows 95 passed / 9 Linux-only skipped。此阶段登记不开放手机入口；待 Phase 7 生成并验证订阅。

## Phase 7 加密入口与订阅

实现单节点 SIP002/Base64 订阅、秘密引用、令牌轮换与旧链接撤销；配置事务通过真实加密客户端验证出口。Gateway 独立探针每次完成后 15 秒复查；入口租约 70 秒未刷新即关闭。TCP-only，手机和 UDP 尚未实测。Windows 98 passed / 10 Linux-only skipped；生产验证进行中。

登录后可同时显示订阅二维码和复制链接，两种方式包含同一条私密订阅地址。生产二维码截图已用独立 ZXing 解码器回读，结果与当前订阅地址完全一致；私密令牌未写入仓库或日志。

## Phase 8 网络监控

两个独立出口身份站已改为并行请求；后台任务最迟拾取间隔由 2 秒缩短至 0.5 秒。生产环境三次服务器检测约 0.55 秒，三次出口检测约 0.54–0.55 秒。页面显示的出口耗时是代理连接、TLS 和站点响应的完整耗时，不等同于纯网络延迟。Gateway 到 ISP 入口的十次 TCP 测试约 1–2 ms，抖动低于 1 ms，未出现连接失败。

新增 Gateway 健康任务、线路质量任务、资源与入口连接统计、五分钟 TCP 延迟/抖动/ICMP 采样、质量参考分和过期状态。质量页明确显示“服务器 → ISP 代理入口”，不把手机 RTT 或网站完整响应时间混入线路指标。Windows 103 passed / 10 Linux-only skipped；Debian 113 passed；生产 schema 8、健康和质量任务均成功，真实样本为 TCP 延迟约 1.16 ms、0/10 TCP 连接失败。

## Phase 9 运营页面

新增告警去重与恢复时间、ISP 到期提醒、网关/ISP/出口异常告警、审计历史分页和真实概览计数。生产 schema 9；Chrome 390px 页面验证 Network、Alerts、History 均无横向溢出，Controller、Gateway、入口守卫和监控任务均 active。

## Phase 10 真实手机验收

未执行。需要两台 iPhone 在 Shadowrocket 导入同一私密订阅，分别验证固定出口 IP、Wi-Fi/蜂窝延迟、IPv6/DNS 行为和异常恢复；Windows 或 Chrome 视口不能替代该项。
