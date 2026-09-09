# Static SOCKS5 ISP 与出口身份守卫

`/isps` 登记名称、代理地址/端口、用户名/密码及检测网关。国家、城市、服务商、到期日可选；未知值保留为空，不推断或虚构。可选填写商家确认的固定出口 IP，否则以首次成功检测的真实 IP 建立身份。

保存后进入持久化检测队列，完成第一次检测后每 60 秒重新排队复查。每个 ISP 最多一个活动任务；与 Gateway 管理共用单个有界 worker。检测间隔以完成时间为基准，其他长任务可能延后执行；超过 5 分钟无新结果显示 UNKNOWN。

检测在所选 Gateway 的 proxyadmin 账户执行，使用固定的 `/usr/local/sbin/pfem-isp-probe`，凭据通过加密 SSH 的标准输入传递，不进入命令行、数据库、日志或 HTTP 响应。代理地址解析成公网 IPv4 后固定连接目标，拒绝内网与 link-local 地址。

验证步骤：SOCKS5 用户名密码方法协商 → RFC 1929 认证 → 域名 CONNECT → 系统 CA 校验的 HTTPS → api.ipify.org 与 icanhazip.com 两处 IPv4 结果一致。延迟是两次完整 HTTPS 出口检测的平均耗时，不是 ICMP RTT。任何认证、TLS、网络、返回数据异常均不能标记 Healthy。

数据库的 `expected_exit_ip` 首次确定后不可覆盖（SQL trigger 保护，包含禁止清空）；当前 IP 不一致时显示 CRITICAL / EXIT IP CHANGED，审计与检测历史同时保留原 IP 和实际 IP。到期 ISP 也不能显示 Healthy。此阶段检测不修改业务路由；业务入口仍关闭，路由与回滚由 Phase 4 接入。

系统不自动购买、续费、更换或删除 ISP。后续若需要新的固定出口身份，应新增 ISP 并通过明确确认的组绑定操作切换，不能直接重写旧身份。
