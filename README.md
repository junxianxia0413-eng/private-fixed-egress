# Private Fixed-Egress Network Manager

管理 Gateway、静态 SOCKS5 ISP、设备和固定出口的单管理员控制台。

## 开发顺序

按 MVP 实施方案 v1.0 顺序推进：

0. 项目骨架
1. Controller：登录、SQLite、响应式控制台、HTTPS 部署
2. Gateway 自动部署：Debian 12、sing-box、systemd、nftables、幂等执行
3. SOCKS ISP 管理与 Exit Identity Guard
4. Exit Group：配置校验、备份、应用、出口验证和回滚
5. Device 管理
6. Subscription Group 与两个设备绑定
7. Shadowrocket 订阅与令牌轮换
8. Health Monitor
9. History 与 Alerts
10. 真实 VPS、静态 ISP、两台 iPhone 完整验收

## 不可破坏的约束

- 不自动更换 ISP；变更出口身份必须人工确认。
- 没有真实探测证据，不能标记 Healthy。
- 密码、SSH 私钥、订阅令牌、运行数据库不得提交 Git。
- 不自动购买资源、删除 ISP/Gateway 或重装服务器。
- 每个完成的模块独立验证并提交；未完成的能力明确标注。

## 本地运行

需要 Python 3.11+：

```sh
python -m venv .venv
# Linux: source .venv/bin/activate
# Windows PowerShell: .venv/Scripts/Activate.ps1
python -m pip install -r requirements.txt
python -m scripts.setup
python -m uvicorn controller.main:app --host 127.0.0.1 --port 8000
```

首次设置会在本机交互式创建管理员，无默认密码；密码至少 14 个字符。
打开 http://127.0.0.1:8000，登录后显示 Private Network / System Online。
这代表 Controller 与数据库在线，不代表 Gateway 或 ISP 已接入。
生产环境必须设置 `APP_ENV=production` 和 `PUBLIC_URL=https://实际域名`，由 Caddy 提供 HTTPS。

重置管理员：`python -m scripts.setup --reset-admin`，会撤销全部旧会话。
在线备份：`python -m scripts.backup`；使用 SQLite backup API，校验完整性并清除备份中的会话。
备份含密码哈希和后续业务数据，应使用受限权限并保存在 Git 外。

测试：`python -m pip install -r requirements-dev.txt`，然后 `python -m pytest`。
工程说明见 ARCHITECTURE.md、MVP.md、AI-OPERATIONS.md、TECH-STACK.md。

Debian 12 部署步骤见 [deploy/README.md](deploy/README.md)。
测试证据与未完成验收见 [VALIDATION.md](VALIDATION.md)。
开发任务见 [GitHub Issues](https://github.com/junxianxia0413-eng/private-fixed-egress/issues)。
当前连接没有 Milestone 创建能力，暂用 Phase 0–10 共 11 个 Issue 跟踪。

当前状态：Phase 0 已完成；Phase 1 Controller 登录、持久化与响应式首页已实现。
Gateway、ISP、设备、订阅和监控尚未实现；导航明确标为待接入。
尚未完成生产 HTTPS 和真实手机链路验收。
