# Controller 部署与恢复

当前提供 Debian 12 首次安装脚本、非 root systemd 服务和 Caddy HTTPS。
脚本必须在目标 VPS 本机运行；已在真实 Debian 12 VPS 完成公网 IPv4 HTTPS、浏览器登录、服务重启恢复及备份验收，证据见 VALIDATION.md。

部署前准备：

1. 一台已有 Debian 12 Controller VPS，建议 1 CPU / 1 GB / 20 GB。
2. 可用公网 IPv4，或域名的 A/AAAA 记录指向该 VPS；使用 IPv4 模式不需要域名。
3. SSH 地址、端口、用户、可信 host key 指纹，以及本地 SSH 私钥路径。
4. 入站 TCP 80/443 用于 HTTPS；SSH 仅向管理来源开放。

不需要提前购买更多节点。Gateway、SOCKS ISP 和两台 iPhone 分别用于后续阶段验收。
不要将任何凭据填入 GitHub Issue 或 README。

## 首次安装

在一台专用、没有既有 Caddy 站点的 Debian 12 VPS 上：

```sh
sudo apt-get update
sudo apt-get install -y git
git clone https://github.com/junxianxia0413-eng/private-fixed-egress.git
cd private-fixed-egress
sudo bash deploy/install_controller.sh network.example.com
```

把示例域名换成已指向 VPS 的真实域名。脚本会交互式要求管理员名称和密码。
也可以把参数直接替换成你控制的公网 IPv4。IPv4 模式安装 Caddy 官方稳定版（至少 2.11），显式使用 Let's Encrypt 的 shortlived IP 证书，Caddy 自动续期。
不需要购买域名或向手机导入自签名根证书；证书签发需要公网 80/443 可达。
IP 模式当前只支持公网 IPv4，私有/保留 IP 和 IPv6 会明确拒绝。

自动部署可设置 `PFEM_ADMIN_PASSWORD_FILE` 指向服务器上权限受限的密码文件，用户名由 `PFEM_ADMIN_USERNAME` 指定（默认 admin）。
安装器会临时复制为 pfem 用户的 0600 文件，初始化后删除临时副本。密码不会放进进程参数或日志；操作者负责删除源密码文件。
重复安装相同提交保留管理员和数据库。若检测到其他版本或已有非本项目 Caddy 配置，会停止并要求先审查升级/站点合并。
脚本不修改 SSH 或主机防火墙，避免意外切断管理连接；云防火墙需允许 80/443 和受限来源的 SSH。
不要开放 8000；应用只监听 127.0.0.1。

若 VPS 已启用 UFW 且仅放行 SSH，在核实规则后添加 `ufw allow 80/tcp` 和 `ufw allow 443/tcp`，保留已有 SSH 规则。
不要关闭整个防火墙或清空规则。云平台防火墙若启用也需放行这两个端口。
证书签发阶段可能暂时出现 TLS 握手错误，安装器会在有界时间内重试；持续超时应先排查防火墙。

脚本验证顺序：依赖完整性 → 管理员/数据库 → systemd → loopback 健康检查 → Caddy 校验 → 公共 HTTPS。
失败时不会把部署标为成功。Caddy reload 失败会恢复配置。
DNS/证书失败时 Controller 可能已启动但 HTTPS 未通过；修正 DNS/防火墙后重复相同版本安装或验证公共健康地址。

## 文件与服务

| 路径/服务 | 用途 |
| --- | --- |
| `/opt/private-fixed-egress` | root 管理的代码和虚拟环境 |
| `/etc/private-fixed-egress/controller.env` | 生产环境配置，root:pfem 0640 |
| `/var/lib/private-fixed-egress/controller.db` | 数据库，pfem 0600 |
| `/var/lib/private-fixed-egress/secrets` | 后续 SSH/ISP 秘密文件，0700 |
| `/var/lib/private-fixed-egress/backups` | 本地备份，0700 |
| `private-fixed-egress.service` | 单 worker 应用，限制写目录与权限 |
| `caddy.service` | HTTPS、证书续期与反向代理 |

检查：`systemctl status private-fixed-egress caddy`。
诊断：`journalctl -u private-fixed-egress -u caddy --since '10 minutes ago'`。
应用禁用 HTTP access log，避免后续订阅令牌进入请求日志；不要自行开启含完整 URL 的代理日志。

## 备份与恢复

在 Controller 上执行（路径必须指向 Git 外）：

```sh
cd /opt/private-fixed-egress
sudo -u pfem env DATABASE_PATH=/var/lib/private-fixed-egress/controller.db \
  .venv/bin/python -m scripts.backup \
  --output /var/lib/private-fixed-egress/backups/controller-before-upgrade.db
```

备份使用 SQLite 在线 backup API，完整性校验后清空备份会话，避免恢复旧登录。
备份不可覆盖同名文件。应另行安排加密异地副本；当前未提供自动备份定时任务。

恢复时先停止应用，保留当前 `.db`、`-wal`、`-shm` 为一组故障副本，再把已验证备份复制到数据库路径；使用匹配该数据库版本的代码，修复属主 pfem 和 0600 权限，再启动服务并重新登录。
不要只复制正在写入的 SQLite 主文件，不要把旧 WAL/SHM 配到新恢复的主文件旁。

## 升级流程

首次安装脚本会拒绝覆盖不同提交。升级前必须完成：

1. 记录当前提交，备份数据库和 `/etc/private-fixed-egress`；保存当前代码目录。
2. 在独立目录安装新版本依赖并执行测试，确认数据库迁移兼容策略。
3. 停止应用，再切换代码；执行迁移，启动并验证 HTTPS 与登录。
4. 若失败，停止新应用，恢复匹配版本的代码与数据库快照，再启动验证。

不要仅回退 Python 文件而保留不兼容的新数据库。自动代码升级和生产数据库回滚是后续运维增强项。

## 参考

- [Caddy 官方安装说明](https://caddyserver.com/docs/install)
- [Let's Encrypt 公网 IP 证书正式可用](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability.html)
- [Caddy ACME issuer 与 profile](https://caddyserver.com/docs/caddyfile/directives/tls#acme)
- [Caddyfile 入门与自动 HTTPS](https://caddyserver.com/docs/quick-starts/caddyfile)
- [systemd 服务隔离配置](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
