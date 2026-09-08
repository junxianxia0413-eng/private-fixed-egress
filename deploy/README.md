# 部署阶段门槛

Phase 0 只运行在本机 loopback；Phase 1 增加 Controller 的 Debian 12 安装脚本、systemd 与 Caddy。

部署前准备：

1. 一台已有 Debian 12 Controller VPS，建议 1 CPU / 1 GB / 20 GB。
2. 域名或子域名的 A/AAAA 记录指向该 VPS；不配置指向其他主机的 AAAA。
3. SSH 地址、端口、用户、可信 host key 指纹，以及本地 SSH 私钥路径。
4. 入站 TCP 80/443 用于 HTTPS；SSH 仅向管理来源开放。

不需要提前购买更多节点。Gateway、SOCKS ISP 和两台 iPhone 分别用于后续阶段验收。
不要将任何凭据填入 GitHub Issue 或 README。
