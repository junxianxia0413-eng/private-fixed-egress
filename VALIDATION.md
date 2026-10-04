# 阶段验收记录

验证日期：2026-09-11 UTC。

## 已验证

| 范围 | 证据/结果 |
| --- | --- |
| Phase 0 | 本地 Python 3.14 virtualenv；FastAPI + SQLite 启动与健康检查通过 |
| 自动测试 | Windows Python 3.14：111 passed / 15 Linux-only skipped；Debian Python 3.11：127 passed |
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
- 设备管理、订阅、周期监控、History/Alerts 已完成并部署；两台 iPhone 已完成首次导入和连接验收。
- 未测试真实 Safari；390px Chrome 视口验证不是 iPhone 实机验收。

Phase 0–10 已完成；Wi-Fi/蜂窝切换、IPv6/DNS 和 UDP 游戏按实际使用环境继续观察。

## 统一订阅、VPS 直出与 AI 分流（生产验证）

- Windows 完整回归：135 passed / 16 Linux-only skipped；Ruff 与 Git whitespace 检查通过。Debian 候选版本回归、`sing-box check` 和 `nft -c` 也已通过。
- 同一生产订阅地址已分别以 Shadowrocket、Clash Verge Rev 和浏览器 User-Agent 请求，依次得到 Base64 VLESS、Mihomo YAML 和使用说明页；响应禁止缓存且携带 `Vary: User-Agent, Accept`。
- 从 MetaCubeX 官方 Release 下载 Mihomo v1.19.31，核对 GitHub API 发布的 SHA-256 后，真实内核成功加载生产订阅 YAML。
- 生产数据库从 schema 10 升级到 schema 12。原有三条 ISP 线路、三个订阅组、令牌、设备映射和审计记录保持，`foreign_key_check` 无错误。
- 东京 VPS 直出由两个独立检测站确认并锁定为该服务器公网 IPv4；第四条线路通过完整候选检查、应用和双站出口验证。为避免服务器仅返回不可达 IPv6 DNS 结果，每条直出线路使用带相同路由标记的 IPv4 DNS；默认未匹配出站仍由 nftables 拒绝。
- 在生产数据的一个订阅上临时启用 Anthropic、OpenAI、Gemini AI 分流：真实网关配置通过 sing-box 检查并应用，AI 域名指向 VPS 直出，普通域名仍指向原 ISP。随后恢复默认设置并再次应用，三个现有订阅均保持 `READY`。
- 验收期间第一条上游 ISP 曾在双站并发检测时短暂超时；另外两条 ISP 与 VPS 直出保持健康，未被该线路牵连。探测器现会在并发失败后对两个站点各顺序重试一次，顺序重试仍失败才标记异常；双站 IP 必须一致和禁止隐式直连的规则不变。更新后的现场复查显示三条 ISP、VPS 直出、所有订阅和 Controller、Caddy、Gateway、守卫定时器健康。

## Clash 延迟诊断与 TCP 优化

- 用户截图中的节点单测约 274 ms，但同时开启了只适用于至少两个节点的“链式代理”，左侧组合结果达到 1004 ms；首页仍显示中国电信 IP，说明 Windows 系统代理/TUN 尚未接管该流量。
- 生产 VPS 诊断时负载约 0.00、可用内存约 519 MB、磁盘使用 34%，Controller、Caddy、Gateway 和守卫均正常，因此不是 CPU、内存或磁盘瓶颈。
- 东京 VPS 到普通国际 Anycast 目标约 0.5–2.1 ms、无丢包；到一个中国电信测试地址约 244 ms，并出现 30% ICMP 丢包。该结果与客户端约 274 ms 同量级，主要瓶颈位于中国电信与 Vultr 东京之间的跨境路由。
- Gateway 已持久启用 BBR、FQ、双向 TCP Fast Open、路径 MTU 探测和空闲后拥塞窗口保持。Mihomo 订阅已加入 `tcp-concurrent`、Keepalive、TFO 与 Chrome TLS 指纹，并经生产订阅请求验证。
- 优化后原有 ISP、VPS 直出、订阅和默认拒绝策略保持；这些参数改善丢包时的连接和吞吐，不承诺改变由物理距离及运营商路由决定的基础 RTT。

## LightNode VPS 迁移（2026-10-04）

- 从旧 Vultr 东京节点 `45.32.20.164` 在线备份 SQLite、全部 secrets、网关事务状态、Caddy/Controller 配置和线上版本 `fb7c22ed3c3d66b0d3eab2bfea14f205ed47822d`。三个归档均在传输前后核对 SHA-256，SQLite `integrity_check` 返回 `ok`；制作归档期间只暂停 Controller 和守卫定时器，数据转发服务保持运行，完成后自动恢复旧服务。
- 备份恢复到 LightNode 东京 Debian 12 节点 `38.60.212.135`，保留管理员、设备、三条固定 ISP、四条出口线路、四个订阅组、订阅令牌、审计记录和网关管理密钥。Gateway 记录及 Ed25519 主机密钥已更新；VPS 直出身份从旧地址显式迁移到新地址，固定 ISP 身份未改变。
- Caddy 2.11.7 已为新公网 IPv4 签发短期可信证书，443 与 8443 健康检查通过。外部连续 10 次 HTTPS 请求全部成功；连接复用后的完整健康请求约 81–89 ms。该数字只证明电脑到新控制入口的路径，不能替代手机网络或游戏服务器 RTT。
- 使用真实 Windows sing-box 客户端依次穿透四个 VLESS + WebSocket + TLS 订阅组，实际出口分别为 `43.246.197.96`、`103.11.120.244`、`43.246.197.154` 和 `38.60.212.135`。前三个固定 ISP 出口保持，第四个 VPS 直出正确变化。
- 同一订阅地址分别返回 Shadowrocket Base64、Clash/Mihomo YAML 和浏览器说明页；官方 Mihomo v1.19.32 按发布 SHA-256 校验后成功加载 YAML。网关默认出口拒绝、防火墙、Controller、Caddy、Gateway 和守卫定时器均为 active。
- root 密码登录已关闭，下载的恢复密钥在硬化后重新登录成功。旧 VPS 暂时保留作为回退点，待新订阅在实际手机和 Clash Verge 中确认后再单独下线。

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
- 固定出口名称支持登录管理员直接编辑；空名称、超长名称和重复名称被拒绝，固定 IP 与线路绑定保持不变，修改前后写入审计历史。

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

订阅组成员已扩展为 1–20 台。创建和编辑表单支持自由输入设备名称、已有设备名称联想、自动创建设备、逐项添加及竖三点菜单删除；组名称也可直接编辑。服务端继续检查名称、设备唯一归属、成员数量和 CSRF，数据库约束同步扩展到 20 个位置。生产 schema 10 已迁移，原 `PHONE-GROUP-01` 和两台设备保持不变。真实 Chrome 已完成删除一行、重新添加、保存和数据保留验证；1440px 与 390px 页面均无横向溢出。

## Phase 7 加密入口与订阅

实现单节点 Base64 订阅、秘密引用、令牌轮换与旧链接撤销；配置事务通过真实加密客户端验证出口。当前手机节点使用 VLESS + WebSocket + TLS 的 HTTPS 443 通道。Gateway 独立探针每 15 秒复查，已验证的 443 入口授权持久保存。TCP 已通过生产测试，UDP 游戏仍需按应用实测。

登录后可同时显示订阅二维码和复制链接，两种方式包含同一条私密订阅地址。生产二维码截图已用独立 ZXing 解码器回读，结果与当前订阅地址完全一致；私密令牌未写入仓库或日志。

## Phase 8 网络监控

两个独立出口身份站已改为并行请求；后台任务最迟拾取间隔由 2 秒缩短至 0.5 秒。生产环境三次服务器检测约 0.55 秒，三次出口检测约 0.54–0.55 秒。页面显示的出口耗时是代理连接、TLS 和站点响应的完整耗时，不等同于纯网络延迟。Gateway 到 ISP 入口的十次 TCP 测试约 1–2 ms，抖动低于 1 ms，未出现连接失败。

新增 Gateway 健康任务、线路质量任务、资源与入口连接统计、五分钟 TCP 延迟/抖动/ICMP 采样、质量参考分和过期状态。质量页明确显示“服务器 → ISP 代理入口”，不把手机 RTT 或网站完整响应时间混入线路指标。Windows 103 passed / 10 Linux-only skipped；Debian 113 passed；生产 schema 8、健康和质量任务均成功，真实样本为 TCP 延迟约 1.16 ms、0/10 TCP 连接失败。

## Phase 9 运营页面

新增告警去重与恢复时间、ISP 到期提醒、网关/ISP/出口异常告警、审计历史分页和真实概览计数。生产 schema 9；Chrome 390px 页面验证 Network、Alerts、History 均无横向溢出，Controller、Gateway、入口守卫和监控任务均 active。

## Phase 10 真实手机验收

两台真实 iPhone 已成功导入订阅并取得固定出口；随后也复现了旧高端口节点同时超时。现场抓包显示手机侧 SYN 到达服务器，服务器持续回复 SYN-ACK，但客户端没有完成 ACK，证实高端口回程在接入路径中被丢弃。Wi-Fi/蜂窝切换、IPv6/DNS 和 UDP 游戏仍需按具体使用环境继续观察。

## Shadowrocket 间歇超时修复

生产日志确认 VPS 资源和 TCP 建连正常：两条 ISP 各 100 次 TCP 连接均成功，中位数 1.13 ms 与 1.38 ms。过去 24 小时中 `ISP-01` 的上游 SOCKS 出现 15 次连接超时和 9 次 EOF，而第二条 ISP 没有同类错误。旧守卫在任一出口一次探测失败时清空全部手机端口租约，因此第一条 ISP 的抖动会连带造成第二个 Shadowrocket 节点超时。

守卫现已改为逐出口并行检查和独立入口授权：每次检测内部重试两次；已成功验证的线路在普通检测超时后保持开放；出口 IP 不匹配或到期日过期仍立即关闭。443 入口授权不依赖 70 秒续租，即使守卫进程暂时没有运行也不会自行失效。状态变化以无凭据 JSONL 保留最近 200 条。

## 低负载 CPU 显示修复

旧版使用 0.2 秒 `/proc/stat` 差值；单 vCPU、100 Hz 计数下只有约 20 个刻度，低负载结果会量化为 0%、5% 等跳变。生产服务器五次旧采样为 0%、0%、5%、5%、0%，同时五次一秒样本为约 1%–2%，内存为约 43%，服务负载正常。

Gateway API 7 改用相邻健康检查之间的累计 CPU 差值，首次采样使用一秒窗口；过短的重复检查沿用上一段有效平均值。界面将精确零值显示为 `<1%` 并说明采样含义。Windows 111 passed / 15 Linux-only skipped；Linux helper 测试覆盖跨检查平均、短间隔复用及首次采样。

## HTTPS 443 手机通道修复

订阅节点由公网高端口 Shadowsocks TCP 改为 VLESS + WebSocket + TLS，经现有 Caddy 公网 HTTPS 443 入口转发到 loopback 监听器。Caddy 路径只允许映射到保留的 13001–14000 本地端口，nftables 再按已验证出口授权对应端口；旧高端口入口继续保留用于兼容和事务验证。

Windows Python 3.14 为 111 passed / 15 Linux-only skipped；Debian Python 3.11 为 127 passed。sing-box 1.14.0 候选配置检查、Caddy 配置检查和生产重载均通过。两条生产订阅在独立网络上各完成 10 次固定出口 HTTPS 请求，服务重启后又各完成 10 次，共 40/40 成功；每次结果均等于对应锁定出口。Controller、Caddy、Gateway 和守卫计时器重启后均为 active，443 本地授权仍存在且没有自动超时字段。

## SOCKS5 连接编辑与出口隔离修复

固定出口支持编辑完整连接信息，并能解析 `socks5://用户名:密码@地址:端口`。新凭据会先从 Gateway 完成真实认证和双站出口检测，成功后才以事务替换旧秘密；认证失败、出口 IP 不符或并发配置时保留旧连接。页面和审计记录均不回显凭据。

出口配置失败的状态更新已收窄到目标线路。第三条线路失败不会再把同一 Gateway 的其他线路或订阅改成待处理；已应用线路不会仅因临时检测失败或五分钟内的结果稍旧而被关闭。生产环境三条出口线路均为 HEALTHY。

## 卡片删除与依赖保护

固定出口和订阅组卡片增加右下角六点菜单及浏览器二次确认。仍被出口线路引用的固定出口会拒绝删除。删除已部署的订阅组时，系统在同一个 Gateway 配置事务中先移除客户端，远程验证并确认后再删除数据库记录和秘密；远程失败则回滚并保留原订阅。删除未启用的订阅组不会删除设备库记录。

Windows 为 122 passed / 16 skipped，Debian 为 138 passed。生产浏览器验证了两个六点菜单、确认提示和取消后数据不变。现场已有三条订阅，均为 READY，并分别完成 10 次固定出口 HTTPS 请求，共 30/30 成功。

