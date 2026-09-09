# 架构与实施决策

## 部署边界

Controller 使用 Debian 12、Python 3.11+、FastAPI、Jinja2、SQLite、Caddy 和 systemd。
Controller 只管理资源；用户业务流量走 Gateway → SOCKS5 ISP，不通过 Controller。
Gateway 使用 Debian 12、sing-box、systemd 和 nftables，通过受校验的 SSH 连接管理。
首次部署允许控制台与未来 Gateway 共用一台 VPS，减少资源需求；仍按独立服务和配置目录管理。当前 Controller、Gateway 与 ISP 检测均已上线。
没有域名时可使用公网 IPv4 的 Let's Encrypt 短期证书，由 Caddy 自动续期。主机已有防火墙时保留管理规则，仅补充网站端口。

## 模块边界

- `controller/api`：HTTP 路由、身份验证和表单校验。
- `controller/services`：数据库迁移、登录会话和后续任务协调。
- `controller/models`：阶段性数据库模式。
- `gateways/`、`isp/`、`devices/`、`groups/`、`subscriptions/`：按实施顺序加入领域功能。
- `deploy/`：Controller 与后续 Gateway 的部署资源。
- `database/`、`secrets/`、`backups/`：本机运行数据，Git 忽略。

## Controller 基线

SQLite 开启外键、WAL 和 busy timeout；迁移在事务内按 user_version 顺序应用。
单个应用 worker；未来监控与 SSH 任务不在 HTTP 请求中无限等待，需持久任务和单实例锁。
管理员密码使用 Argon2id 哈希。会话使用随机令牌，数据库只存 SHA-256 摘要，支持到期和退出撤销。
浏览器表单检查同源与 CSRF。登录限制按来源 IP 与全局窗口存入数据库，进程重启不清空。
生产只通过 Caddy HTTPS 访问；应用仅监听 loopback，代理头仅信任 loopback。
健康检查只说明 Controller 进程和数据库可用，不能代表任何 Gateway 或 ISP Healthy。

## 后续必须保持的业务约束

首次探测成功才写入 expected_exit_ip。之后探测只更新 current_exit_ip，漂移即 CRITICAL。
网关部署、探测、配置应用必须区分失败与未知，禁止虚构指标或直接标记 Healthy。
配置以 Gateway 为单位串行变更：生成 → sing-box check → 备份 → 应用 → 端到端出口校验 → 成功；失败回滚并验证恢复。
路由不可有 ISP 失败后直连出口的降级路径。更换 ISP 是显式的人工确认事务。
Controller 数据表只存秘密文件引用；Gateway 的运行配置与回滚快照需要保存对应凭据，分别限制为 root/代理服务只读和 root 私有。不可在日志、错误详情、订阅中泄露 ISP 凭据。
Gateway SSH 首次登记需核验 host key，关闭密码认证前验证管理密钥及 sudo，避免锁出。

## 待真实环境验证的决策

Gateway 客户端入口协议在 Phase 2/4 根据 sing-box 与 Shadowrocket 支持确定并实机验证。
共享订阅可供两台手机使用，但设备绑定只是管理记录，不能仅凭共享链接强制识别两台物理设备。
HTTP 探测失败率不可冒充网络层丢包；Phase 8 需明确测量协议、采样数和窗口。
禁止将 mock 测试通过视为两台 iPhone 固定出口链路已验收。

## Phase 3 ISP 检测

isp_exits、isp_jobs、isp_checks 保存资源、持久队列与检测证据。秘密文件通过引用访问，expected_exit_ip 由数据库 trigger 冻结。单 worker 每分钟调度已首次检测过的 ISP，通过 Gateway 上的固定探针执行 SOCKS5 认证和双源 HTTPS 出口确认。

## Phase 4 出口配置事务

exit_groups 绑定 Gateway 与 ISP，exit_jobs 按 Gateway 串行处理。只接收经过验证的结构化拓扑，生成固定模板，禁止任意配置或命令输入。先验证 sing-box 与 nftables 配置，持久保存旧配置和防火墙，再停止核心、替换并启动，通过该核心的本地认证入口核对两个 HTTPS 出口。Controller 收到完整匹配结果才提交事务。

未提交事务由 Gateway 的 120 秒定时器自动恢复；重启后在防火墙和核心启动前恢复。失败回滚保留原 ISP 身份，回滚可用性单独验证。配置状态不确定时控制台显示 UNKNOWN/CONFIG_FAILED，不继续标为正常。

Phase 4 入口仅监听 loopback，尚无手机公网入口。核心只能连接获准 ISP 的精确 IPv4/TCP 端口，拒绝其他 IPv4/IPv6 出站。开启手机入口前仍须完成周期线路验证、异常线路阻断和订阅管理。
