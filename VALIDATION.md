# 阶段验收记录

验证日期：2026-09-08 UTC（用户当地 2026-09-07）。

## 已验证

| 范围 | 证据/结果 |
| --- | --- |
| Phase 0 | 本地 Python 3.14 virtualenv；FastAPI + SQLite 启动与健康检查通过 |
| 自动测试 | `python -m pytest -q`：18 passed |
| 代码检查 | Ruff lint、format、Git diff whitespace 检查通过 |
| 依赖 | 锁定运行/开发依赖；`pip check` 通过 |
| 持久化 | 应用重建后会话仍有效；退出、到期、重设管理员使旧会话失效 |
| 防护 | CSRF、同源、错误密码限速、全局限速、请求体大小限制、受信主机 |
| 数据恢复 | WAL 模式在线备份，完整性校验，恢复后旧会话不可用、管理员可重新登录 |
| 故障状态 | 数据库异常返回 503，不输出敏感路径或假 Online |
| 真实进程 | 本机 Uvicorn 监听 127.0.0.1:8000；真实 Chrome 登录/退出成功 |
| 页面布局 | Chrome 1440×1100 与 390×844；截图人工检查，无横向溢出、无浏览器脚本错误 |
| 部署脚本 | Git Bash 语法检查通过；Debian/systemd/Caddy 现场执行待完成 |

浏览器验证发现并修复 `Referrer-Policy: no-referrer` 导致 POST 的 Origin 为 null 的登录问题。
现采用 same-origin；同源 POST 可用，跨站请求仍被拒绝，测试覆盖该响应头。

依赖测试工具目前有 2 条弃用警告（Starlette TestClient 的 httpx / AnyIO 兼容层），测试没有失败。
GitHub CI 配置覆盖 Linux Python 3.11 和 3.14，实际运行状态以仓库 Actions 为准。

## 未验证或未实现

- 未在真实 Debian 12 Controller VPS 上安装；公共 DNS、ACME 证书与 HTTPS 尚未验收。
- 未接入或部署 Gateway，未输入/测试任何实际 SOCKS5 ISP。
- Exit Group、设备管理、订阅、出口身份守卫、周期监控、完整 History/Alerts 尚待后续阶段。
- 未使用真实 iPhone/Shadowrocket，MVP.md 的现场 Test 01–10 全部待执行。
- 未测试真实 Safari；390px Chrome 视口验证不是 iPhone 实机验收。

Phase 0 完成。Phase 1 软件已实现，生产部署验收待资源。整个 MVP 尚未完成。

