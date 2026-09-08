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

## 本地运行（Phase 0）

需要 Python 3.11+：

```sh
python -m venv .venv
# Linux: source .venv/bin/activate
# Windows PowerShell: .venv/Scripts/Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn controller.main:app --host 127.0.0.1 --port 8000
```

打开 http://127.0.0.1:8000，显示 Private Network / System Online。
本阶段只供本机验证，不能暴露公网；Phase 1 加入登录和 HTTPS 部署。

测试：`python -m pip install -r requirements-dev.txt`，然后 `python -m pytest`。
工程说明见 ARCHITECTURE.md、MVP.md、AI-OPERATIONS.md、TECH-STACK.md。

当前状态：Phase 0 项目骨架，尚未完成 MVP 验收。
