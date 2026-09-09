# Gateway 自动部署

控制台 `/gateways` 登记 Debian 12 公网 IPv4、SSH 端口、位置、初始 root 密码或 Ed25519 私钥，以及已核实的 Ed25519 主机公钥。保存后点击部署；后台队列持久化任务和失败阶段。每台服务器只允许一个活动任务，Controller 只运行一个进程；进程锁防止重复 worker。重启中断的任务标记失败，用户可检测后重试。

安装 sing-box 1.14.0（官方发行包及固定 SHA-256）、独立 systemd 服务、proxyadmin 密钥账户。首次需要 Debian 12、至少 384 MiB 内存及 512 MiB 空闲磁盘、root 权限、SSH 可达以及 Debian/GitHub HTTPS 出站。更新软件包索引并安装所需包；不执行发行版升级、不重装主机。

重复部署先检查受管服务；已有用户、配置与密钥复用。首次遇到同名非受管组件则停止。管理账户仅能通过 sudo 调用 root 拥有的固定 helper；不能提交任意命令、配置路径或脚本。

初始代理仅监听 `127.0.0.1:10810`，所有 CONNECT 请求拒绝。独立 nftables `inet pfem_guard` 表额外阻断代理服务用户的非 loopback 出站；保留主机已有 UFW、Docker、SSH 和控制台规则。未绑定 ISP 前没有公网代理入口，也没有直接出口回退。后续 Exit Group 阶段才实现经验证的 ISP 出站许可。

首次登录凭据只存在 0600 的秘密文件内，数据库存随机引用。每台 Gateway 生成管理密钥与 root 恢复密钥；先分别建立新连接验证，再关闭 SSH 密码登录。配置变更带 90 秒远程回滚计时器；重新连接成功后才确认。成功后清除 Controller 中的首次登录凭据。恢复密钥可在管理员页面以带 CSRF 的下载操作取得；下载记录进入审计。

`HEALTHY` 代表 SSH、systemd、配置、SOCKS 握手、拒绝直出探测和资源采样通过，**不代表 ISP 出口可用**。页面超过 5 分钟无新检测显示未知；本阶段手动点击检测，定时监测在 Phase 8 实现。失败不变更 ISP、不清空现有配置、不触发购买或重装。

## 备份与恢复

Gateway 密钥位于 `Settings.secret_directory`（生产为 `/var/lib/private-fixed-egress/secrets`），应与数据库一起备份。`scripts.backup` 仅生成 SQLite 备份，不能单独恢复 Gateway 控制权限。完整快照应暂停 Controller、确认无待处理部署任务，将 SQLite 备份、整个 secrets 目录及 Controller 环境配置一并存入 0700 私人目录，再启动 Controller；不得提交 Git。

`deploy/upgrade_controller.sh` 在安装依赖后短暂停服，制作上述完整快照、应用数据库迁移并切换版本；健康检查失败恢复旧代码和数据库。原有生产安装器不会覆盖一个不同版本。升级操作需使用已审核的新旧完整 Git SHA，详细入口见 deploy/README.md。

## 当前限制

首次支持 root 及未加密 Ed25519 私钥/密码；不支持 SSH 跳板、RSA 私钥、IPv6 Gateway。初始锁定 Debian 12 与 sing-box 1.14.0；更换核心版本需单独验证与发布。未提供 Gateway 删除、重装和 ISP 自动切换功能。
